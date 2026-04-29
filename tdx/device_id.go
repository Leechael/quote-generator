package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"
)

func extractDeviceIdentity(quote []byte) ([]byte, [sha256.Size]byte, error) {
	ppid, err := extractPPIDFromTDXQuote(quote)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return ppid, sha256.Sum256(ppid), nil
}

func extractPPIDFromTDXQuote(quote []byte) ([]byte, error) {
	certChain, err := extractPCKCertChainFromQuote(quote)
	if err != nil {
		return nil, err
	}
	certDER, err := firstCertificateDER(certChain)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse PCK certificate: %w", err)
	}

	intelExtOID := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	ppidOID := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 1}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(intelExtOID) {
			continue
		}
		ppid, err := findASN1OIDValue(ext.Value, ppidOID)
		if err != nil {
			return nil, err
		}
		if len(ppid) == 0 {
			return nil, fmt.Errorf("empty PPID in PCK certificate")
		}
		return ppid, nil
	}
	return nil, fmt.Errorf("Intel PCK extension not found")
}

func extractPCKCertChainFromQuote(quote []byte) ([]byte, error) {
	if len(quote) < 48 {
		return nil, fmt.Errorf("quote too short for header")
	}

	version := binary.LittleEndian.Uint16(quote[0:2])
	var authLenOffset int
	switch version {
	case 4:
		authLenOffset = 48 + 584
	case 5:
		if len(quote) < 54 {
			return nil, fmt.Errorf("quote too short for v5 body header")
		}
		bodySize := int(binary.LittleEndian.Uint32(quote[50:54]))
		authLenOffset = 54 + bodySize
	default:
		return nil, fmt.Errorf("unsupported TDX quote version for PCK extraction: %d", version)
	}

	if len(quote) < authLenOffset+4 {
		return nil, fmt.Errorf("quote too short for auth data length")
	}
	authLen := int(binary.LittleEndian.Uint32(quote[authLenOffset : authLenOffset+4]))
	authStart := authLenOffset + 4
	if len(quote) < authStart+authLen {
		return nil, fmt.Errorf("quote auth data truncated")
	}
	return extractPCKCertChainFromAuthV4(quote[authStart : authStart+authLen])
}

func extractPCKCertChainFromAuthV4(auth []byte) ([]byte, error) {
	const (
		signatureSize          = 64
		attestationKeySize     = 64
		enclaveReportSize      = 384
		qeReportSignatureSize  = 64
		outerCertDataHeaderLen = 6
	)

	outerOffset := signatureSize + attestationKeySize
	if len(auth) < outerOffset+outerCertDataHeaderLen {
		return nil, fmt.Errorf("auth data too short for certification data")
	}
	outerBodyLen := int(binary.LittleEndian.Uint32(auth[outerOffset+2 : outerOffset+6]))
	outerBodyStart := outerOffset + outerCertDataHeaderLen
	if len(auth) < outerBodyStart+outerBodyLen {
		return nil, fmt.Errorf("outer certification data truncated")
	}
	qeData := auth[outerBodyStart : outerBodyStart+outerBodyLen]

	qeAuthLenOffset := enclaveReportSize + qeReportSignatureSize
	if len(qeData) < qeAuthLenOffset+2 {
		return nil, fmt.Errorf("QE report certification data too short")
	}
	qeAuthLen := int(binary.LittleEndian.Uint16(qeData[qeAuthLenOffset : qeAuthLenOffset+2]))
	innerOffset := qeAuthLenOffset + 2 + qeAuthLen
	if len(qeData) < innerOffset+outerCertDataHeaderLen {
		return nil, fmt.Errorf("QE report certification data missing nested certificate data")
	}

	certType := binary.LittleEndian.Uint16(qeData[innerOffset : innerOffset+2])
	certBodyLen := int(binary.LittleEndian.Uint32(qeData[innerOffset+2 : innerOffset+6]))
	certBodyStart := innerOffset + outerCertDataHeaderLen
	if len(qeData) < certBodyStart+certBodyLen {
		return nil, fmt.Errorf("nested certificate data truncated")
	}
	if certType != 4 && certType != 5 {
		return nil, fmt.Errorf("unsupported PCK certificate data type: %d", certType)
	}
	return qeData[certBodyStart : certBodyStart+certBodyLen], nil
}

func firstCertificateDER(certChain []byte) ([]byte, error) {
	if block, _ := pem.Decode(certChain); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("first PEM block is %s, not CERTIFICATE", block.Type)
		}
		return block.Bytes, nil
	}
	if cert, err := x509.ParseCertificate(certChain); err == nil {
		return cert.Raw, nil
	}
	return nil, fmt.Errorf("decode PCK certificate chain as PEM or DER")
}

func findASN1OIDValue(der []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, fmt.Errorf("parse Intel PCK extension: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after Intel PCK extension")
	}
	value, ok, err := findASN1OIDValueInSequence(seq.Bytes, oid)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("PPID OID not found in Intel PCK extension")
	}
	return value, nil
}

func findASN1OIDValueInSequence(contents []byte, oid asn1.ObjectIdentifier) ([]byte, bool, error) {
	rest := contents
	for len(rest) > 0 {
		var entry asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &entry)
		if err != nil {
			return nil, false, fmt.Errorf("parse Intel PCK extension entry: %w", err)
		}
		if entry.Tag != asn1.TagSequence || !entry.IsCompound {
			continue
		}

		entryRest := entry.Bytes
		var entryOID asn1.ObjectIdentifier
		entryRest, err = asn1.Unmarshal(entryRest, &entryOID)
		if err != nil {
			return nil, false, fmt.Errorf("parse Intel PCK extension entry OID: %w", err)
		}
		var entryValue asn1.RawValue
		if _, err := asn1.Unmarshal(entryRest, &entryValue); err != nil {
			return nil, false, fmt.Errorf("parse Intel PCK extension entry value: %w", err)
		}
		if entryOID.Equal(oid) {
			return bytes.Clone(entryValue.Bytes), true, nil
		}
		if entryValue.Tag == asn1.TagSequence && entryValue.IsCompound {
			value, ok, err := findASN1OIDValueInSequence(entryValue.Bytes, oid)
			if err != nil || ok {
				return value, ok, err
			}
		}
	}
	return nil, false, nil
}

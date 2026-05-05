package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	tdxGuestDevice = "/dev/tdx_guest"

	reportDataSize = 64
	tdxReportSize  = 1024
	quoteMinSize   = 1020
	quoteMaxSize   = 64 * 1024

	afVsock       = 40
	vmaddrCIDHost = 2

	qgsMsgGetQuoteReq  = 0
	qgsMsgGetQuoteResp = 1
	qgsMsgVerMajor     = 1
	qgsMsgVerMinor     = 0
	qgsMsgLenPrefix    = 4
)

type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Zero      [4]byte
}

type tdxReportReq struct {
	ReportData [reportDataSize]byte
	TdReport   [tdxReportSize]byte
}

func main() {
	var outFile string
	var reportDataHex string
	var qgsPort uint
	var useDeviceIDReportData bool
	var printPPID bool
	var printDeviceID bool

	flag.StringVar(&outFile, "o", "quote.bin", "output quote file")
	flag.StringVar(&reportDataHex, "d", "", "64-byte report data as hex; default is all zeros")
	flag.UintVar(&qgsPort, "qgs-port", 0, "QGS vsock port")
	flag.BoolVar(&useDeviceIDReportData, "device-id-report-data", false, "set report data to sha256(PPID) || 32 zero bytes")
	flag.BoolVar(&printPPID, "print-ppid", false, "print PPID parsed from the quote's PCK certificate")
	flag.BoolVar(&printDeviceID, "print-device-id", false, "print sha256(PPID)")
	flag.Parse()

	if useDeviceIDReportData && reportDataHex != "" {
		fatal(fmt.Errorf("-device-id-report-data cannot be used with -d"))
	}
	if qgsPort == 0 {
		fatal(fmt.Errorf("-qgs-port is required"))
	}

	reportData, err := parseReportData(reportDataHex)
	if err != nil {
		fatal(err)
	}

	if useDeviceIDReportData || printPPID || printDeviceID {
		probeQuote, err := timedGetQuote("quote_probe", uint32(qgsPort), reportData)
		if err != nil {
			fatal(fmt.Errorf("generate probe quote: %w", err))
		}
		ppid, deviceID, err := extractDeviceIdentity(probeQuote)
		if err != nil {
			fatal(err)
		}
		if printPPID {
			fmt.Printf("ppid=%s\n", hex.EncodeToString(ppid))
		}
		if printDeviceID {
			fmt.Printf("device_id=%s\n", hex.EncodeToString(deviceID[:]))
		}
		if useDeviceIDReportData {
			reportData = [reportDataSize]byte{}
			copy(reportData[:32], deviceID[:])
		}
	}

	quote, err := timedGetQuote("quote", uint32(qgsPort), reportData)
	if err != nil {
		fatal(err)
	}

	if err := os.WriteFile(outFile, quote, 0644); err != nil {
		fatal(fmt.Errorf("write %s: %w", outFile, err))
	}
	fmt.Printf("wrote %s (%d bytes)\n", outFile, len(quote))
	summary("quote_result=ok quote_len=%d", len(quote))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	summary("quote_result=fail")
	os.Exit(1)
}

func summary(format string, args ...any) {
	fmt.Printf("SUMMARY "+format+"\n", args...)
}

func timedGetQuote(label string, port uint32, reportData [reportDataSize]byte) ([]byte, error) {
	start := time.Now()
	quote, err := getQuote(port, reportData)
	elapsed := time.Since(start)
	summary("%s_ms=%d", label, elapsed.Milliseconds())
	if err == nil {
		summary("%s_len=%d", label, len(quote))
	}
	return quote, err
}

func parseReportData(s string) ([reportDataSize]byte, error) {
	var out [reportDataSize]byte
	if s == "" {
		return out, nil
	}
	data, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return out, fmt.Errorf("decode report data: %w", err)
	}
	if len(data) != reportDataSize {
		return out, fmt.Errorf("report data must be exactly %d bytes, got %d", reportDataSize, len(data))
	}
	copy(out[:], data)
	return out, nil
}

func getQuote(port uint32, reportData [reportDataSize]byte) ([]byte, error) {
	if port == 0 {
		return nil, fmt.Errorf("QGS port is required")
	}

	report, err := getTDReport(reportData)
	if err != nil {
		return nil, err
	}

	resp, err := qgsRequest(port, buildQGSRequest(report))
	if err != nil {
		return nil, err
	}
	return parseQGSResponse(resp)
}

func getTDReport(reportData [reportDataSize]byte) ([]byte, error) {
	fd, err := syscall.Open(tdxGuestDevice, syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tdxGuestDevice, err)
	}
	defer syscall.Close(fd)

	req := tdxReportReq{ReportData: reportData}
	ioctlCmd := uint32(0xC0000000 | (unsafe.Sizeof(req) << 16) | ('T' << 8) | 1)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ioctlCmd), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return nil, fmt.Errorf("TDX_CMD_GET_REPORT ioctl: %v", errno)
	}
	return req.TdReport[:], nil
}

func qgsRequest(port uint32, request []byte) ([]byte, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("create vsock socket: %w", err)
	}
	defer syscall.Close(fd)

	addr := sockaddrVM{Family: afVsock, Port: port, CID: vmaddrCIDHost}
	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	if errno != 0 {
		return nil, fmt.Errorf("connect QGS vsock cid=%d port=%d: %v", vmaddrCIDHost, port, errno)
	}

	lenHeader := make([]byte, qgsMsgLenPrefix)
	binary.BigEndian.PutUint32(lenHeader, uint32(len(request)))
	if _, err := writeAll(fd, lenHeader); err != nil {
		return nil, fmt.Errorf("send QGS length: %w", err)
	}
	if _, err := writeAll(fd, request); err != nil {
		return nil, fmt.Errorf("send QGS request: %w", err)
	}

	if _, err := readAll(fd, lenHeader); err != nil {
		return nil, fmt.Errorf("read QGS response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenHeader)
	if respLen == 0 || respLen > quoteMaxSize {
		return nil, fmt.Errorf("invalid QGS response length: %d", respLen)
	}

	response := make([]byte, respLen)
	if _, err := readAll(fd, response); err != nil {
		return nil, fmt.Errorf("read QGS response: %w", err)
	}
	return response, nil
}

func buildQGSRequest(report []byte) []byte {
	msgSize := uint32(16 + 4 + 4 + len(report))
	msg := make([]byte, 0, msgSize)
	msg = binary.LittleEndian.AppendUint16(msg, qgsMsgVerMajor)
	msg = binary.LittleEndian.AppendUint16(msg, qgsMsgVerMinor)
	msg = binary.LittleEndian.AppendUint32(msg, qgsMsgGetQuoteReq)
	msg = binary.LittleEndian.AppendUint32(msg, msgSize)
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	msg = binary.LittleEndian.AppendUint32(msg, uint32(len(report)))
	msg = binary.LittleEndian.AppendUint32(msg, 0)
	msg = append(msg, report...)
	return msg
}

func parseQGSResponse(data []byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("QGS response too short: %d", len(data))
	}
	if got := binary.LittleEndian.Uint32(data[4:8]); got != qgsMsgGetQuoteResp {
		return nil, fmt.Errorf("unexpected QGS message type: %d", got)
	}
	if code := binary.LittleEndian.Uint32(data[12:16]); code != 0 {
		return nil, fmt.Errorf("QGS error code: 0x%x", code)
	}

	selectedIDSize := int(binary.LittleEndian.Uint32(data[16:20]))
	quoteSize := int(binary.LittleEndian.Uint32(data[20:24]))
	quoteOffset := 24 + selectedIDSize
	if quoteSize <= 0 || quoteOffset+quoteSize > len(data) {
		return nil, fmt.Errorf("invalid QGS quote bounds")
	}
	return validateQuote(data[quoteOffset : quoteOffset+quoteSize])
}

func validateQuote(quote []byte) ([]byte, error) {
	if len(quote) < quoteMinSize {
		return nil, fmt.Errorf("quote too short: %d bytes", len(quote))
	}
	if len(quote) > quoteMaxSize {
		return nil, fmt.Errorf("quote too large: %d bytes", len(quote))
	}
	return quote, nil
}

func writeAll(fd int, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := syscall.Write(fd, buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func readAll(fd int, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := syscall.Read(fd, buf[total:])
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("unexpected EOF")
		}
		total += n
	}
	return total, nil
}

# TDX Quote Generator

A small standalone Go application that generates a raw Intel TDX attestation
quote from inside a TDX guest VM.

It has no external Go dependencies and does not link `libtdx_attest.so`.
It talks to host QGS over vsock and can derive the [dstack](https://github.com/dstack-TEE/dstack/) device id from the
quote's PCK certificate.

## How it works

The tool opens `/dev/tdx_guest`, calls `TDX_CMD_GET_REPORT` to produce a
TDREPORT, sends that TDREPORT to host QGS over vsock, and writes the returned
TD quote.

## Prerequisites

- Must run inside a TDX guest VM (not on the host)
- `/dev/tdx_guest` device available
- QEMU must provide `quote-generation-socket` to host QGS/qgsd
- Pass the QGS vsock port with `-qgs-port`

## Build

Inside the TDX guest (or cross-compile on the host):
```bash
cd quote-generator/tdx
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tdx-quote-generator-linux .
```

This produces a fully static binary with no external dependencies.

## Usage

```bash
# Generate a quote with default (all-zero) report data
./tdx-quote-generator-linux -qgs-port 4050

# Specify output file
./tdx-quote-generator-linux -qgs-port 4050 -o myquote.bin

# Provide custom 64-byte report data (hex)
./tdx-quote-generator-linux -qgs-port 4050 -d 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

# Print PPID and [dstack](https://github.com/dstack-TEE/dstack/) device id from a probe quote
./tdx-quote-generator-linux -qgs-port 4050 -print-ppid -print-device-id -o quote.bin

# Use [dstack](https://github.com/dstack-TEE/dstack/) device id as report data
./tdx-quote-generator-linux -qgs-port 4050 -device-id-report-data -print-device-id -o quote-device-id.bin

# Show help
./tdx-quote-generator-linux -h
```

## [dstack](https://github.com/dstack-TEE/dstack/) device id

The device id mode uses:

```text
device_id = sha256(PPID)
report_data = device_id || 32 zero bytes
```

`PPID` is parsed from the Intel PCK certificate embedded in a probe quote. The
tool then generates the final quote with `-device-id-report-data`.

## Output

The tool writes the raw binary quote to the selected output file. The quote can
be verified or parsed with DCAP/QVL tooling outside this binary.

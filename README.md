# Quote Generator

Minimal standalone tools for generating Intel SGX and TDX attestation quotes.
Useful for testing remote attestation workflows and verifying quote parsers.

> [!WARNING]
> These tools are for **learning and quick smoke testing only**. They are
> deliberately minimal and lack the safeguards expected in production:
>
> - **No enclave identity management** — the SGX enclave is signed with a
>   throwaway debug key; production requires a trusted signing key and MRSIGNER
>   policy enforcement.
> - **No input validation or rate limiting** — the TDX tool accepts arbitrary
>   report data without sanitization; production services should validate bounds
>   and throttle quote requests.
> - **No audit logging or monitoring** — neither tool emits structured logs or
>   metrics; production deployments need observability for security events.
> - **Debug mode** — the SGX enclave is built with `SGX_DEBUG=1`, which disables
>   memory encryption protections required by many threat models.
> - **PPID privacy** — the TDX device-id mode extracts and hashes the platform
>   PPID; real deployments must handle this identifier as sensitive material.
>
> Before using either tool in a production attestation flow, review your threat
> model, key-management strategy, and compliance requirements.

- [`tdx/`](tdx/README.md) — Go TDX quote generator
- [`sgx/`](sgx/README.md) — Intel SGX SDK/DCAP quote generator

## TDX

See [`tdx/README.md`](tdx/README.md) for full details.

The TDX generator is implemented in Go and builds to a static Linux amd64
binary:

```bash
cd tdx
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tdx-quote-generator-linux .
```

It must run inside a TDX guest with `/dev/tdx_guest`. The QGS vsock port must
be passed with `-qgs-port`.
The binary emits `SUMMARY quote_ms=...`, `SUMMARY quote_len=...`, and
`SUMMARY quote_result=...` lines for benchmark harnesses.

Examples:

```bash
./tdx-quote-generator-linux -qgs-port 4050 -o quote-default.bin
./tdx-quote-generator-linux -qgs-port 4050 -d <64-byte-hex> -o quote-custom.bin
./tdx-quote-generator-linux -qgs-port 4050 -o quote.bin
./tdx-quote-generator-linux -qgs-port 4050 -device-id-report-data -print-device-id -o quote-device-id.bin
```

`-device-id-report-data` generates a probe quote, extracts PPID from the PCK
certificate, computes `device_id = sha256(PPID)`, and generates the final quote
with `report_data = device_id || 32 zero bytes`.

The `device_id` follows the
[dstack](https://github.com/dstack-TEE/dstack/) standard.

## SGX

See [`sgx/README.md`](sgx/README.md) for full details.

The SGX generator is a C implementation using Intel SGX SDK and DCAP
libraries. It is not a pure Go implementation.

Build requirements:

```text
Intel SGX SDK
Intel SGX PSW/DCAP quote provider libraries
sgx_edger8r and sgx_sign from the SGX SDK
```

Build:

```bash
cd sgx
source /usr/lib/sgx-sdk/environment
make
```

Runtime requirements:

```text
/dev/sgx_enclave
/dev/sgx_provision
SGX PSW/DCAP services and quote provider configured
```

The SGX generator can be built on a separate machine if it has a compatible
Linux environment, SGX SDK, and DCAP development libraries. In practice, building
on the target SGX machine is the simplest and least fragile path because the app
links against SGX/DCAP runtime libraries and produces a signed enclave that must
match the target runtime environment. If built elsewhere, deploy both the host
binary and the signed enclave, and ensure the target has compatible SGX PSW/DCAP
runtime libraries and device access.

Examples:

```bash
./quote-generator -o quote-default.bin
./quote-generator -d <64-byte-hex> -o quote-custom.bin
```

## License

MIT

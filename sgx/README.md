# SGX Quote Generator

A minimal standalone C application that generates an Intel SGX DCAP attestation quote using the SGX SDK and DCAP libraries.

## How it works

1. Loads a minimal SGX enclave.
2. Calls `sgx_qe_get_target_info` to get the Quoting Enclave's target info.
3. Generates an enclave REPORT targeting the QE.
4. Calls `sgx_qe_get_quote_size` and `sgx_qe_get_quote` to produce the DCAP quote.
5. Writes the quote to a binary file.

## Prerequisites

- Intel SGX capable CPU with FLC (Flexible Launch Control)
- SGX PSW and SDK installed (`sgx-sdk`, `libsgx-dcap-ql-dev`)
- Access to `/dev/sgx_enclave` and `/dev/sgx_provision`
- User must be in the `sgx_prv` group (or run as root)

## Build

```bash
source /usr/lib/sgx-sdk/environment
make
```

## Usage

```bash
# Generate a quote with default (all-zero) report data
./sgx-quote-generator

# Specify output file
./sgx-quote-generator -o myquote.bin

# Provide custom 64-byte report data (hex)
./sgx-quote-generator -d 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f

# Show help
./sgx-quote-generator -h
```

## Output

The tool prints:
- Enclave ID
- QE target info status
- MRENCLAVE and MRSIGNER of the generated report
- Quote size
- Output file path

The quote file is a raw binary SGX DCAP quote (v3, ECDSA-P256), which can be parsed with tools like `gramine-sgx-quote-view` or the [`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) Rust crate.

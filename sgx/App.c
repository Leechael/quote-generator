#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sgx_urts.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_report.h>
#include "Enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o FILE    Output quote to FILE (default: quote.bin)\n");
    fprintf(stderr, "  -d HEX     64-byte report data in hex (default: zeros)\n");
    fprintf(stderr, "  -h         Show this help\n");
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len > 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        hex_len -= 2;
    }
    if (hex_len != out_len * 2)
        return -1;

    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char *argv[])
{
    const char *outfile = "quote.bin";
    sgx_report_data_t report_data = {0};
    int opt;

    while ((opt = getopt(argc, argv, "o:d:h")) != -1) {
        switch (opt) {
        case 'o':
            outfile = optarg;
            break;
        case 'd':
            if (hex_to_bytes(optarg, report_data.d, sizeof(report_data.d)) != 0) {
                fprintf(stderr, "Error: report data must be %zu hex bytes\n", sizeof(report_data.d));
                return 1;
            }
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* 1. Load enclave */
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "Error: failed to create enclave: 0x%x\n", ret);
        return 1;
    }
    printf("Enclave loaded (eid=%lu)\n", eid);

    /* 2. Get QE target info */
    sgx_target_info_t qe_target_info = {0};
    quote3_error_t qe_ret = sgx_qe_get_target_info(&qe_target_info);
    if (qe_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "Error: sgx_qe_get_target_info failed: 0x%x\n", qe_ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Got QE target info\n");

    /* 3. Generate report inside enclave */
    sgx_report_t report = {0};
    ret = ecall_get_report(eid, &ret, &qe_target_info, &report_data, &report);
    if (ret != SGX_SUCCESS) {
        fprintf(stderr, "Error: ecall_get_report failed: 0x%x\n", ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Generated enclave report\n");
    print_hex("  MRENCLAVE", report.body.mr_enclave.m, sizeof(report.body.mr_enclave.m));
    print_hex("  MRSIGNER",  report.body.mr_signer.m,  sizeof(report.body.mr_signer.m));

    /* 4. Get quote size */
    uint32_t quote_size = 0;
    qe_ret = sgx_qe_get_quote_size(&quote_size);
    if (qe_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "Error: sgx_qe_get_quote_size failed: 0x%x\n", qe_ret);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Quote size: %u bytes\n", quote_size);

    /* 5. Get quote */
    uint8_t *quote = calloc(1, quote_size);
    if (!quote) {
        fprintf(stderr, "Error: out of memory\n");
        sgx_destroy_enclave(eid);
        return 1;
    }
    qe_ret = sgx_qe_get_quote(&report, quote_size, quote);
    if (qe_ret != SGX_QL_SUCCESS) {
        fprintf(stderr, "Error: sgx_qe_get_quote failed: 0x%x\n", qe_ret);
        free(quote);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Generated quote\n");

    /* 6. Save to file */
    FILE *fp = fopen(outfile, "wb");
    if (!fp) {
        fprintf(stderr, "Error: failed to open %s for writing\n", outfile);
        free(quote);
        sgx_destroy_enclave(eid);
        return 1;
    }
    size_t written = fwrite(quote, 1, quote_size, fp);
    fclose(fp);
    if (written != quote_size) {
        fprintf(stderr, "Error: failed to write quote\n");
        free(quote);
        sgx_destroy_enclave(eid);
        return 1;
    }
    printf("Quote saved to %s (%zu bytes)\n", outfile, written);

    free(quote);
    sgx_destroy_enclave(eid);
    return 0;
}

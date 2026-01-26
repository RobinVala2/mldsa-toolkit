#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with the ML-DSA private key in PEM format\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

uint64_t get_time_before() {
    uint64_t time_before = 0;
#if defined( __s390x__ )
    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    time_before = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_before) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_before) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_before_high = 0, time_before_low = 0;
    asm volatile (
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t" : "=r" (time_before_high),
        "=r" (time_before_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_before = (uint64_t)time_before_high<<32 | time_before_low;
#else
#error Unsupported architecture
#endif
    return time_before;
}

uint64_t get_time_after() {
    uint64_t time_after = 0;
#if defined( __s390x__ )
    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    time_after = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_after) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_after) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_after_high = 0, time_after_low = 0;
    asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (time_after_high),
        "=r" (time_after_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_after = (uint64_t)time_after_high<<32 | time_after_low;
#else
#error Unsupported architecture
#endif
    return time_after;
}

int main(int argc, char *argv[]) {
    int result = 1;
    int r_ret;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;

    size_t msg_len = 0;
    size_t sig_len = 0;
    size_t sig_cap = 0;

    int mldsa_level = 44; /* default: ML-DSA-44 */

    FILE *fp = NULL;

    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *sig = NULL;

    int opt;
    uint64_t time_before, time_after, time_diff;

    OSSL_PROVIDER *prov_default = NULL;

    int deterministic = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };

    while ((opt=getopt(argc, argv, "i:o:t:k:n:s:h")) != -1) {
        switch (opt) {
            case 'i': in_file_name = optarg; break;
            case 'o': out_file_name = optarg; break;
            case 't': time_file_name = optarg; break;
            case 'k': key_file_name = optarg; break;
            case 'n': sscanf(optarg, "%zu", &msg_len); break;
            case 's': mldsa_level = atoi(optarg); break;
            case 'h': help(argv[0]); return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                return 1;
        }
    }

    if (!in_file_name || !out_file_name || !time_file_name || !key_file_name || !msg_len) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        return 1;
    }

    if (mldsa_level != 44 && mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr,
                "Invalid ML-DSA parameter set: %d (use 44, 65, or 87)\n",
                mldsa_level);
        return 1;
    }    

    /* Open files */
    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s: %s", in_file_name, strerror(errno));
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1){
        fprintf(stderr, "can't open output file %s: %s", out_file_name, strerror(errno));
        goto err;
    }

    time_fd = open(time_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (time_fd == -1){
        fprintf(stderr, "can't open timing file %s: %s\n", time_file_name, strerror(errno));
        goto err;
    }

    prov_default = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_default) {
        fprintf(stderr, "Failed to load default provider\n");
        goto err;
    }

    /* Allocate message buffer */
    fprintf(stderr, "malloc(msg) - size %zu\n", msg_len);
    msg = malloc(msg_len);
    if (!msg)
        goto err;

    /* Load key (PEM format) */
    fp = fopen(key_file_name, "r");
    if (!fp) {
        fprintf(stderr, "can't open key file %s\n", key_file_name);
        goto err;
    }

    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL)
        goto err;

    if (fclose(fp) != 0)
        goto err;
    fp = NULL;

    /* Signature algorithm */

    char alg_name[16];

    snprintf(alg_name, sizeof(alg_name), "ML-DSA-%d", mldsa_level);
    sig_alg = EVP_SIGNATURE_fetch(NULL, alg_name, NULL);
    if (!sig_alg) {
        fprintf(stderr, "EVP_SIGNATURE_fetch(%s) failed\n", alg_name);
        goto err;
    }

    sig_cap = EVP_PKEY_get_size(pkey);
    if (sig_cap == 0) {
        fprintf(stderr, "EVP_PKEY_get_size() failed or returned 0\n");
        goto err;
    }

    if (!EVP_PKEY_is_a(pkey, alg_name)) {
        fprintf(stderr,
                "Private key does not match selected algorithm (%s)\n",
                alg_name);
        goto err;
    }

    fprintf(stderr, "malloc(sig) - size %zu\n", sig_cap);
    sig = malloc(sig_cap);
    if (!sig)
        goto err;

    /* Create ctx */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx)
        goto err;

    fprintf(stderr, "EVP_PKEY_sign_message_init(deterministic=1)\n");
    if (EVP_PKEY_sign_message_init(ctx, sig_alg, params) <= 0)
        goto err;

    fprintf(stderr, "Using %s\n", alg_name);
    fprintf(stderr, "Signing messages...\n");

    while((r_ret = read(in_fd, msg, msg_len)) > 0) {
        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected");
            goto err;
        }

        sig_len = sig_cap;

        time_before = get_time_before();
        r_ret = EVP_PKEY_sign(ctx, sig, &sig_len, msg, msg_len);
        time_after = get_time_after();

        if (r_ret <=0) {
            fprintf(stderr, "Signing failure\n");
        }

        /* signature size check */
        if (sig_len > sig_cap) {
            fprintf(stderr, "Signature length overflow: %zu > %zu\n", sig_len, sig_cap);
            goto err;
        }

        time_diff = time_after - time_before;

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(out_fd, sig, sig_len) != (ssize_t)sig_len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

err:
    fprintf(stderr, "failed!\n");
    ERR_print_errors_fp(stderr);
    result = 1;

out:
    if (msg) free(msg);
    if (sig) free(sig);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (sig_alg) EVP_SIGNATURE_free(sig_alg);
    if (pkey) EVP_PKEY_free(pkey);
    if (in_fd >=0) close(in_fd);
    if (out_fd >=0) close(out_fd);
    if (time_fd >=0) close(time_fd);
    if (fp) fclose(fp);
    if (prov_default) OSSL_PROVIDER_unload(prov_default);

    return result;
}
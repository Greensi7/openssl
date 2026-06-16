#include <openssl/ech.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdint.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    OSSL_ECHSTORE *es;
    BIO *in;
    uint8_t *fixed_buf;
    size_t content_len;

    /*
     * ech_decode_and_flatten has a strict size check:
     * OSSL_ECH_MIN_ECHCONFIG_LEN = 32
     * OSSL_ECH_MAX_ECHCONFIG_LEN = 1500
     */
    if (len < 32 || len >= 1500)
        return 0;

    /* Create an ECH Store */
    es = OSSL_ECHSTORE_new(NULL, NULL);
    if (es == NULL)
        return 0;

    fixed_buf = OPENSSL_memdup(buf, len);
    if (fixed_buf == NULL) {
        OSSL_ECHSTORE_free(es);
        return 0;
    }

    /* Fix up the magic bytes so it always passes the binary format check */
    content_len = len - 2;
    fixed_buf[0] = (content_len >> 8) & 0xff; /* Length High */
    fixed_buf[1] = content_len & 0xff; /* Length Low */
    fixed_buf[2] = 0xfe; /* Version High (0xfe0d) */
    fixed_buf[3] = 0x0d; /* Version Low */


    in = BIO_new_mem_buf(fixed_buf, (int)len);
    if (in == NULL) {
        OPENSSL_free(fixed_buf);
        OSSL_ECHSTORE_free(es);
        return 0;
    }

    /* Target */
    OSSL_ECHSTORE_read_echconfiglist(es, in);

    /* Cleanup */
    BIO_free(in);
    OPENSSL_free(fixed_buf);
    OSSL_ECHSTORE_free(es);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}

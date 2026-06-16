#include <openssl/ech.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include "fuzzer.h"

static SSL_CTX *ctx = NULL;
static SSL *s = NULL;

int FuzzerInitialize(int *argc, char ***argv)
{
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return 0;
        
    s = SSL_new(ctx);
    if (s == NULL) {
        SSL_CTX_free(ctx);
        ctx = NULL;
        return 0;
    }
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    uint8_t *fixed_buf;
    size_t content_len;

    // Instead of creating new SSL every time 
    SSL_clear(s);

    /*
     * ech_decode_and_flatten has a strict size check:
     * OSSL_ECH_MIN_ECHCONFIG_LEN = 32
     * OSSL_ECH_MAX_ECHCONFIG_LEN = 1500
     */
    if (len < 32 || len >= 1500) // preferebly should be set in the fuzzer
        return 0;

    fixed_buf = OPENSSL_memdup(buf, len);
    if (fixed_buf == NULL)
        return 0;

    // Fix up the magic bytes so it always passes the binary format check
    // For hex (? second fuzze?)
    content_len = len - 2;
    fixed_buf[0] = (content_len >> 8) & 0xff; /* Length High */
    fixed_buf[1] = content_len & 0xff; /* Length Low */
    fixed_buf[2] = 0xfe; /* Version High (0xfe0d) */
    fixed_buf[3] = 0x0d; /* Version Low */

    /* Fuzz the Client-Side ECH configuration list API */
    SSL_set1_ech_config_list(s, fixed_buf, len);

    /* Cleanup */
    OPENSSL_free(fixed_buf);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
    SSL_CTX_free(ctx);
    SSL_free(s);
}

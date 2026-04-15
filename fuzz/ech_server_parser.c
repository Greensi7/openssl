#include <openssl/ech.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdlib.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (len == 0 || len > INT_MAX) {
        return 0;
    }

    OSSL_ECHSTORE *es = OSSL_ECHSTORE_new(NULL, NULL);
    if (es == NULL) {
        return 0;
    }

    BIO *in = BIO_new(BIO_s_mem());
    if (in == NULL) {
        OSSL_ECHSTORE_free(es);
        return 0;
    }
    BIO_write(in, buf, (int)len);

    //*Target
    OSSL_ECHSTORE_read_pem(es, in, 0);

    BIO_free(in);
    OSSL_ECHSTORE_free(es);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}

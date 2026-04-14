/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ech.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
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
    OSSL_ECHSTORE *es;
    BIO *in;

    if (len == 0 || len > INT_MAX)
        return 0;

    /* Create an ECH Store */
    es = OSSL_ECHSTORE_new(NULL, NULL);
    if (es == NULL)
        return 0;

    /* Load the fuzzer's binary data into a BIO memory buffer */
    in = BIO_new(BIO_s_mem());
    if (in == NULL) {
        OSSL_ECHSTORE_free(es);
        return 0;
    }
    BIO_write(in, buf, (int)len);

    /* The target function! Parses the untrusted binary ECHConfigList */
    OSSL_ECHSTORE_read_echconfiglist(es, in);

    /* Cleanup */
    BIO_free(in);
    OSSL_ECHSTORE_free(es);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

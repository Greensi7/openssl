/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ech.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    SSL_CTX *ctx;
    SSL *s;

    if (len == 0 || len > INT_MAX)
        return 0;

    /* Setup a minimal SSL_CTX and SSL object */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return 0;

    s = SSL_new(ctx);
    if (s == NULL) {
        SSL_CTX_free(ctx);
        return 0;
    }

    /* Fuzz the Client-Side ECH configuration list API */
    SSL_set1_ech_config_list(s, buf, len);

    /* Cleanup */
    SSL_free(s);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

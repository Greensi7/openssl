/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/http.h>
#include <openssl/crypto.h>
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
    char *url;
    char *host = NULL, *port = NULL, *path = NULL, *user = NULL, *query = NULL, *frag = NULL;
    int ssl = 0;
    int port_num = 0;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    url = OPENSSL_malloc(len + 1);
    if (url == NULL)
        return 0;

    memcpy(url, buf, len);
    url[len] = '\0';

    OSSL_HTTP_parse_url(url, &ssl, &user, &host, &port, &port_num, &path, &query, &frag);

    OPENSSL_free(user);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(frag);
    OPENSSL_free(url);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

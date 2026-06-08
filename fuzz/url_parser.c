/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Fuzzer for OSSL_parse_url() - the generic URL parser.
 *
 * The existing http_parser fuzzer only exercises OSSL_HTTP_parse_url(),
 * which wraps OSSL_parse_url() with HTTP/HTTPS scheme restrictions.
 * This fuzzer targets the underlying generic parser directly, exercising
 * additional code paths for arbitrary schemes, IPv6 bracket handling,
 * sscanf()-based port parsing, userinfo extraction, query strings, and
 * fragment parsing.
 *
 * OSSL_parse_url() is internet-facing: it processes URLs received over
 * the network in OCSP, CMP, CT, and other protocols.
 */

#include <openssl/http.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <limits.h>
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
    char *scheme = NULL, *user = NULL, *host = NULL;
    char *port = NULL, *path = NULL, *query = NULL, *frag = NULL;
    int port_num = 0;

    if (len == 0 || len > INT_MAX)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    url = OPENSSL_malloc(len + 1);
    if (url == NULL)
        return 0;

    memcpy(url, buf, len);
    url[len] = '\0';

    /* Exercise the full generic URL parser with all output parameters */
    OSSL_parse_url(url, &scheme, &user, &host, &port, &port_num,
                   &path, &query, &frag);

    OPENSSL_free(scheme);
    OPENSSL_free(user);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(frag);

    /* Also exercise with various NULL output parameters to cover branches */
    OSSL_parse_url(url, NULL, NULL, &host, &port, &port_num,
                   &path, NULL, NULL);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);

    OSSL_parse_url(url, &scheme, &user, NULL, NULL, NULL,
                   NULL, &query, &frag);
    OPENSSL_free(scheme);
    OPENSSL_free(user);
    OPENSSL_free(query);
    OPENSSL_free(frag);

    OPENSSL_free(url);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}

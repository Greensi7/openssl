/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "fuzzer.h"

static void fuzz_parse_hostserv(const char *hostserv,
                                enum BIO_hostserv_priorities prio)
{
    char *host = NULL;
    char *service = NULL;

    BIO_parse_hostserv(hostserv, &host, &service, prio);
    OPENSSL_free(host);
    OPENSSL_free(service);

    host = NULL;
    service = NULL;
    BIO_parse_hostserv(hostserv, &host, NULL, prio);
    OPENSSL_free(host);

    BIO_parse_hostserv(hostserv, NULL, &service, prio);
    OPENSSL_free(service);

    BIO_parse_hostserv(hostserv, NULL, NULL, prio);
}

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    char *hostserv;

    if (len == 0 || len > INT_MAX)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    hostserv = OPENSSL_malloc(len + 1);
    if (hostserv == NULL)
        return 0;

    memcpy(hostserv, buf, len);
    hostserv[len] = '\0';

    fuzz_parse_hostserv(hostserv, BIO_PARSE_PRIO_HOST);
    fuzz_parse_hostserv(hostserv, BIO_PARSE_PRIO_SERV);

    OPENSSL_free(hostserv);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}

/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/property.h"
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
    char *querystr;
    OSSL_PROPERTY_LIST *plist;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    querystr = OPENSSL_malloc(len + 1);
    if (querystr == NULL)
        return 0;

    memcpy(querystr, buf, len);
    querystr[len] = '\0';

    /* Target 1: Parse it as a Query String (e.g. "?fips!=yes") */
    plist = ossl_parse_query(NULL, querystr, 1);
    if (plist != NULL)
        ossl_property_free(plist);

    /* Target 2: Parse it as a Property Definition (e.g. "fips=yes") */
    plist = ossl_parse_property(NULL, querystr);
    if (plist != NULL)
        ossl_property_free(plist);

    OPENSSL_free(querystr);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

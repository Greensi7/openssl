/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/hpke.h>
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
    char *suitestr;
    OSSL_HPKE_SUITE suite;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    suitestr = OPENSSL_malloc(len + 1);
    if (suitestr == NULL)
        return 0;

    memcpy(suitestr, buf, len);
    suitestr[len] = '\0';

    /* The target function! */
    OSSL_HPKE_str2suite(suitestr, &suite);

    OPENSSL_free(suitestr);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

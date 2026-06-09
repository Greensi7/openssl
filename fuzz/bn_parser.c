/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
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
    char *str;
    BIGNUM *bn = NULL;
    char *out;

    if (len == 0 || len > 8192)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    str = OPENSSL_malloc(len + 1);
    if (str == NULL)
        return 0;

    memcpy(str, buf, len);
    str[len] = '\0';

    /* Fuzz BN_hex2bn */
    bn = NULL;
    if (BN_hex2bn(&bn, str) > 0 && bn != NULL) {
        /* Round-trip: convert back and free */
        out = BN_bn2hex(bn);
        OPENSSL_free(out);
    }
    BN_free(bn);

    /* Fuzz BN_dec2bn */
    bn = NULL;
    if (BN_dec2bn(&bn, str) > 0 && bn != NULL) {
        out = BN_bn2dec(bn);
        OPENSSL_free(out);
    }
    BN_free(bn);

    /* Fuzz BN_asc2bn (auto-detects hex with 0x prefix vs decimal) */
    bn = NULL;
    if (BN_asc2bn(&bn, str) && bn != NULL) {
        out = BN_bn2hex(bn);
        OPENSSL_free(out);
    }
    BN_free(bn);

    OPENSSL_free(str);
    ERR_clear_error();

    return 0;
}

void FuzzerCleanup(void)
{
}

/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/asn1.h>
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
    char *timestr;
    ASN1_TIME *t;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    timestr = OPENSSL_malloc(len + 1);
    if (timestr == NULL)
        return 0;

    memcpy(timestr, buf, len);
    timestr[len] = '\0';

    t = ASN1_TIME_new();
    if (t != NULL) {
        /* Fuzz the generic time string parser */
        ASN1_TIME_set_string(t, timestr);
        
        /* Fuzz the strict RFC5280 X.509 time string parser */
        ASN1_TIME_set_string_X509(t, timestr);
        
        ASN1_TIME_free(t);
    }

    OPENSSL_free(timestr);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

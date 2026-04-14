/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/objects.h>
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
    char *oid_str;
    ASN1_OBJECT *obj;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    oid_str = OPENSSL_malloc(len + 1);
    if (oid_str == NULL)
        return 0;

    memcpy(oid_str, buf, len);
    oid_str[len] = '\0';

    /* Fuzz both name lookups (0) and strict numerical OID parsing (1) */
    obj = OBJ_txt2obj(oid_str, 0);
    if (obj)
        ASN1_OBJECT_free(obj);
    
    obj = OBJ_txt2obj(oid_str, 1);
    if (obj)
        ASN1_OBJECT_free(obj);

    OPENSSL_free(oid_str);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

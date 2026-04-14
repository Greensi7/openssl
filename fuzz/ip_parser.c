/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/x509v3.h>
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
    char *ip_str;
    ASN1_OCTET_STRING *ip;

    if (len == 0)
        return 0;

    /* Create a proper null-terminated string from the fuzzer input */
    ip_str = OPENSSL_malloc(len + 1);
    if (ip_str == NULL)
        return 0;

    memcpy(ip_str, buf, len);
    ip_str[len] = '\0';

    /* Fuzz the IP parsing logic */
    ip = a2i_IPADDRESS(ip_str);
    if (ip)
        ASN1_OCTET_STRING_free(ip);

    /* Fuzz the IP Address + Subnet Mask parsing logic */
    ip = a2i_IPADDRESS_NC(ip_str);
    if (ip)
        ASN1_OCTET_STRING_free(ip);

    OPENSSL_free(ip_str);
    ERR_clear_error();
    
    return 0;
}

void FuzzerCleanup(void)
{
}

/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include "fuzzer.h"

#define MAX_INPUT_SIZE (256 * 1024)
#define MAX_LOADS 64

#define MODE_EXPECT_MASK 0x07
#define MODE_INPUT_SHIFT 3
#define MODE_INPUT_MASK 0x03

static const int expected_types[] = {
    0,
    OSSL_STORE_INFO_PARAMS,
    OSSL_STORE_INFO_PUBKEY,
    OSSL_STORE_INFO_PKEY,
    OSSL_STORE_INFO_CERT,
    OSSL_STORE_INFO_CRL,
    OSSL_STORE_INFO_SKEY,
    0,
};

int FuzzerInitialize(int *argc, char ***argv)
{
    FuzzerSetRand();
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    BIO *in = NULL;
    OSSL_STORE_CTX *store = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const OSSL_PARAM *attach_params = NULL;
    const char *input_type = NULL;
    int expected_type = 0;
    size_t i;

    if (len < 2)
        return 0;

    /*
     * The first input byte selects the STORE configuration:
     *
     *   mode bits 0..2: generic, params, pubkey, pkey, cert, crl, skey
     *   mode bits 3..4: auto, PEM, DER, auto
     */
    expected_type = expected_types[buf[0] & MODE_EXPECT_MASK];
    switch ((buf[0] >> MODE_INPUT_SHIFT) & MODE_INPUT_MASK) {
    case 1:
        input_type = "PEM";
        break;
    case 2:
        input_type = "DER";
        break;
    default:
        break;
    }
    buf++;
    len--;

    if (len > MAX_INPUT_SIZE || len > INT_MAX)
        return 0;

    if (input_type != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE,
            (char *)input_type, 0);
        attach_params = params;
    }

    in = BIO_new_mem_buf(buf, (int)len);
    if (in == NULL)
        goto end;

    store = OSSL_STORE_attach(in, "file", NULL, NULL, UI_null(), NULL,
        attach_params, NULL, NULL);
    if (store == NULL)
        goto end;

    if (expected_type != 0 && !OSSL_STORE_expect(store, expected_type))
        goto end;

    for (i = 0; i < MAX_LOADS && !OSSL_STORE_eof(store); i++) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(store);

        if (info == NULL) {
            if (OSSL_STORE_error(store))
                break;
            continue;
        }

        switch (OSSL_STORE_INFO_get_type(info)) {
        case OSSL_STORE_INFO_NAME:
            OPENSSL_free(OSSL_STORE_INFO_get1_NAME(info));
            OPENSSL_free(OSSL_STORE_INFO_get1_NAME_description(info));
            break;
        case OSSL_STORE_INFO_PARAMS:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PARAMS(info));
            break;
        case OSSL_STORE_INFO_PUBKEY:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PUBKEY(info));
            break;
        case OSSL_STORE_INFO_PKEY:
            EVP_PKEY_free(OSSL_STORE_INFO_get1_PKEY(info));
            break;
        case OSSL_STORE_INFO_CERT:
            X509_free(OSSL_STORE_INFO_get1_CERT(info));
            break;
        case OSSL_STORE_INFO_CRL:
            X509_CRL_free(OSSL_STORE_INFO_get1_CRL(info));
            break;
        case OSSL_STORE_INFO_SKEY:
            EVP_SKEY_free(OSSL_STORE_INFO_get1_SKEY(info));
            break;
        default:
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

end:
    OSSL_STORE_close(store);
    BIO_free(in);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
    FuzzerClearRand();
}

/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/ech.h>
#include <openssl/err.h>
#include "internal/ech_helpers.h"
#include "fuzzer.h"

#define MAX_FUZZ_ENCODING_LEN 4096
#define ECH_INFO_FIXED_PREFIX_LEN 8

static void fuzz_make_enc_info(const unsigned char *encoding,
                               size_t encoding_len, size_t info_len)
{
    unsigned char zero_len_info = 0;
    unsigned char *info = NULL;
    size_t out_len = info_len;

    if (info_len == 0) {
        ossl_ech_make_enc_info(encoding, encoding_len, &zero_len_info,
                               &out_len);
        return;
    }

    info = OPENSSL_malloc(info_len);
    if (info == NULL)
        return;

    ossl_ech_make_enc_info(encoding, encoding_len, info, &out_len);
    OPENSSL_free(info);
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
    static const unsigned char empty_encoding = 0;
    const unsigned char *encoding = len == 0 ? &empty_encoding : buf;
    size_t varied_info_len;

    if (len > MAX_FUZZ_ENCODING_LEN)
        return 0;

    if (len > 1)
        varied_info_len = (((size_t)buf[0] << 8) | buf[1])
                          % (MAX_FUZZ_ENCODING_LEN + ECH_INFO_FIXED_PREFIX_LEN);
    else
        varied_info_len = len;

    fuzz_make_enc_info(encoding, len, 0);
    fuzz_make_enc_info(encoding, len, varied_info_len);
    fuzz_make_enc_info(encoding, len, OSSL_ECH_MAX_INFO_LEN);
    fuzz_make_enc_info(encoding, len, len + ECH_INFO_FIXED_PREFIX_LEN);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You can obtain a copy in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test S/MIME PKCS#7 signature verification.
 */

#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
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
    BIO *in = NULL;
    BIO *indata = NULL;
    BIO *out = NULL;
    PKCS7 *p7 = NULL;

    if (len == 0 || len > INT_MAX)
        return 0;

    in = BIO_new_mem_buf(buf, (int)len);
    if (in == NULL)
        goto err;

    p7 = SMIME_read_PKCS7(in, &indata);
    if (p7 == NULL)
        goto err;

    out = BIO_new(BIO_s_null());
    if (out == NULL)
        goto err;

    PKCS7_verify(p7, NULL, NULL, indata, out, PKCS7_NOVERIFY);

err:
    BIO_free(out);
    PKCS7_free(p7);
    BIO_free(indata);
    BIO_free(in);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

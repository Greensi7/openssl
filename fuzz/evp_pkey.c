/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Test the public EVP_PKEY parsing entry points with fuzzed input.
 *
 * The first byte selects the parser and the remainder is the encoded key or
 * parameters.  Keeping the selector outside the encoded object lets the
 * fuzzer retain well-formed seeds while independently mutating the parser.
 */

#include <limits.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "fuzzer.h"

enum parse_mode {
    PARSE_DER_PRIVATE,
    PARSE_DER_PUBLIC,
    PARSE_PEM_PRIVATE,
    PARSE_PEM_PUBLIC,
    PARSE_PEM_PARAMETERS,
    PARSE_MODE_COUNT
};

static const char password[] = "password";

static int password_cb(char *out, int out_size, int rwflag, void *userdata)
{
    size_t password_len = strlen(password);

    if (out_size < 0 || password_len > (size_t)out_size)
        return 0;

    (void)rwflag;
    (void)userdata;
    memcpy(out, password, password_len);
    return (int)password_len;
}

int FuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *input;
    size_t input_len;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    unsigned int mode;

    if (len < 2 || len - 1 > INT_MAX)
        return 0;

    input = buf + 1;
    input_len = len - 1;
    mode = buf[0] % PARSE_MODE_COUNT;

    switch (mode) {
    case PARSE_DER_PRIVATE:
        pkey = d2i_AutoPrivateKey_ex(NULL, &input, (long)input_len,
                                    NULL, NULL);
        break;
    case PARSE_DER_PUBLIC:
        pkey = d2i_PUBKEY_ex(NULL, &input, (long)input_len, NULL, NULL);
        break;
    case PARSE_PEM_PRIVATE:
    case PARSE_PEM_PUBLIC:
    case PARSE_PEM_PARAMETERS:
        bio = BIO_new_mem_buf(input, (int)input_len);
        if (bio == NULL)
            break;

        if (mode == PARSE_PEM_PRIVATE)
            pkey = PEM_read_bio_PrivateKey_ex(bio, NULL, password_cb,
                                              NULL, NULL, NULL);
        else if (mode == PARSE_PEM_PUBLIC)
            pkey = PEM_read_bio_PUBKEY_ex(bio, NULL, NULL, NULL, NULL, NULL);
        else
            pkey = PEM_read_bio_Parameters_ex(bio, NULL, NULL, NULL);
        break;
    }

    EVP_PKEY_free(pkey);
    BIO_free(bio);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

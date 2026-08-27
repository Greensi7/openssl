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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "fuzzer.h"

#define MAX_INPUT_SIZE (64 * 1024)

int FuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
                            | OPENSSL_INIT_ADD_ALL_DIGESTS,
                        NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char *der = NULL, *tbs = NULL;
    unsigned int digest_len = 0;
    X509_REQ *req = NULL, *copy = NULL;
    X509_ATTRIBUTE *attr = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;

    if (len == 0 || len > MAX_INPUT_SIZE || len > LONG_MAX)
        return 0;

    req = d2i_X509_REQ(NULL, &p, (long)len);
    if (req == NULL)
        goto end;

    bio = BIO_new(BIO_s_null());
    if (bio != NULL)
        X509_REQ_print(bio, req);

    X509_REQ_digest(req, EVP_sha256(), digest, &digest_len);
    (void)X509_REQ_get_signature_nid(req);

    pkey = X509_REQ_get_pubkey(req);
    if (pkey != NULL)
        X509_REQ_verify(req, pkey);

    exts = X509_REQ_get_extensions(req);

    /* Exercise request setters using only values decoded from this input. */
    copy = X509_REQ_dup(req);
    if (copy != NULL) {
        X509_REQ_set_version(copy, X509_REQ_get_version(req));
        X509_REQ_set_subject_name(copy, X509_REQ_get_subject_name(req));
        if (pkey != NULL)
            X509_REQ_set_pubkey(copy, pkey);

        if (X509_REQ_get_attr_count(copy) > 0) {
            attr = X509_REQ_delete_attr(copy, 0);
            if (attr != NULL)
                X509_REQ_add1_attr(copy, attr);
        }
        if (exts != NULL)
            X509_REQ_add_extensions(copy, exts);

        i2d_re_X509_REQ_tbs(copy, &tbs);
    }

    i2d_X509_REQ(req, &der);

end:
    OPENSSL_free(der);
    OPENSSL_free(tbs);
    X509_ATTRIBUTE_free(attr);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    EVP_PKEY_free(pkey);
    X509_REQ_free(copy);
    X509_REQ_free(req);
    BIO_free(bio);
    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

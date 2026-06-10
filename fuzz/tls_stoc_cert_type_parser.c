/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_STOC_CERT_TYPE_INPUT_LEN 4096

static void fuzz_stoc_cert_type(const uint8_t *buf, size_t len,
                                int is_client_cert,
                                const unsigned char *cert_types,
                                size_t cert_types_len)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s = NULL;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    if (!SSL_set1_client_cert_type(ssl, cert_types, cert_types_len)
        || !SSL_set1_server_cert_type(ssl, cert_types, cert_types_len))
        goto end;

    SSL_set_connect_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (is_client_cert) {
        s->ext.client_cert_type_ctos = OSSL_CERT_TYPE_CTOS_GOOD;
        tls_parse_stoc_client_cert_type(s, &pkt, 0, NULL, 0);
    } else {
        s->ext.server_cert_type_ctos = OSSL_CERT_TYPE_CTOS_GOOD;
        tls_parse_stoc_server_cert_type(s, &pkt, 0, NULL, 0);
    }

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    static const unsigned char cert_types[] = {
        TLSEXT_cert_type_rpk,
        TLSEXT_cert_type_x509
    };
    static const unsigned char x509_only[] = {
        TLSEXT_cert_type_x509
    };
    static const unsigned char rpk_only[] = {
        TLSEXT_cert_type_rpk
    };
    static const unsigned char valid_x509[] = {
        TLSEXT_cert_type_x509
    };
    static const unsigned char valid_rpk[] = {
        TLSEXT_cert_type_rpk
    };

    if (len > MAX_FUZZ_STOC_CERT_TYPE_INPUT_LEN)
        return 0;

    fuzz_stoc_cert_type(buf, len, 1, cert_types, sizeof(cert_types));
    fuzz_stoc_cert_type(buf, len, 0, cert_types, sizeof(cert_types));
    fuzz_stoc_cert_type(valid_x509, sizeof(valid_x509), 1, x509_only,
                        sizeof(x509_only));
    fuzz_stoc_cert_type(valid_x509, sizeof(valid_x509), 0, x509_only,
                        sizeof(x509_only));
    fuzz_stoc_cert_type(valid_rpk, sizeof(valid_rpk), 1, rpk_only,
                        sizeof(rpk_only));
    fuzz_stoc_cert_type(valid_rpk, sizeof(valid_rpk), 0, rpk_only,
                        sizeof(rpk_only));

    return 0;
}

void FuzzerCleanup(void)
{
}

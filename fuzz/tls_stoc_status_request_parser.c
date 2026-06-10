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
#include <string.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_STOC_STATUS_REQUEST_INPUT_LEN 4096

static void fuzz_stoc_status_request(const uint8_t *buf, size_t len,
                                     int tls13, int requested,
                                     unsigned int context)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s = NULL;
    PACKET pkt;
    const SSL_METHOD *meth = tls13 ? tlsv1_3_client_method()
                                   : TLS_client_method();

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_connect_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (requested)
        s->ext.status_type = TLSEXT_STATUSTYPE_ocsp;

    tls_parse_stoc_status_request(s, &pkt, context, NULL, 0);

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
    static const unsigned char empty[] = { 0 };
    static const unsigned char status_only[] = { TLSEXT_STATUSTYPE_ocsp };
    unsigned char *ocsp_body = NULL;

    if (len > MAX_FUZZ_STOC_STATUS_REQUEST_INPUT_LEN)
        return 0;

    fuzz_stoc_status_request(buf, len, 0, 0, SSL_EXT_TLS1_2_SERVER_HELLO);
    fuzz_stoc_status_request(buf, len, 0, 1, SSL_EXT_TLS1_2_SERVER_HELLO);
    fuzz_stoc_status_request(empty, 0, 0, 1, SSL_EXT_TLS1_2_SERVER_HELLO);

    fuzz_stoc_status_request(buf, len, 1, 0, SSL_EXT_TLS1_3_CERTIFICATE);
    fuzz_stoc_status_request(buf, len, 1, 1, SSL_EXT_TLS1_3_CERTIFICATE);
    fuzz_stoc_status_request(buf, len, 1, 0,
                             SSL_EXT_TLS1_3_CERTIFICATE_REQUEST);
    fuzz_stoc_status_request(status_only, sizeof(status_only), 1, 1,
                             SSL_EXT_TLS1_3_CERTIFICATE);

    if (len > MAX_FUZZ_STOC_STATUS_REQUEST_INPUT_LEN - 4)
        return 0;

    ocsp_body = OPENSSL_malloc(len + 4);
    if (ocsp_body == NULL)
        return 0;

    ocsp_body[0] = TLSEXT_STATUSTYPE_ocsp;
    ocsp_body[1] = (unsigned char)(len >> 16);
    ocsp_body[2] = (unsigned char)(len >> 8);
    ocsp_body[3] = (unsigned char)len;
    if (len > 0)
        memcpy(ocsp_body + 4, buf, len);

    fuzz_stoc_status_request(ocsp_body, len + 4, 1, 1,
                             SSL_EXT_TLS1_3_CERTIFICATE);

    OPENSSL_free(ocsp_body);
    return 0;
}

void FuzzerCleanup(void)
{
}

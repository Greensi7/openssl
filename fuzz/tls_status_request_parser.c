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

#define MAX_FUZZ_STATUS_REQUEST_INPUT_LEN 4096

static int dummy_status_cb(SSL *ssl, void *arg)
{
    (void)ssl;
    (void)arg;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

static void fuzz_status_request(const uint8_t *buf, size_t len)
{
    SSL_CONNECTION *s = NULL;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    if (ssl == NULL)
        return;

    SSL_clear(ssl);
    SSL_set_accept_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    tls_parse_ctos_status_request(s, &pkt, 0, NULL, 0);

end:
    ERR_clear_error();
}

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx != NULL) {
        SSL_CTX_set_tlsext_status_cb(ctx, dummy_status_cb);
        ssl = SSL_new(ctx);
    }
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    unsigned char *ocsp_buf = NULL;

    if (len == 0 || len > MAX_FUZZ_STATUS_REQUEST_INPUT_LEN)
        return 0;

    fuzz_status_request(buf, len);

    if (len == MAX_FUZZ_STATUS_REQUEST_INPUT_LEN)
        return 0;

    ocsp_buf = OPENSSL_malloc(len + 1);
    if (ocsp_buf == NULL)
        return 0;

    ocsp_buf[0] = TLSEXT_STATUSTYPE_ocsp;
    memcpy(ocsp_buf + 1, buf, len);
    fuzz_status_request(ocsp_buf, len + 1);
    OPENSSL_free(ocsp_buf);

    return 0;
}

void FuzzerCleanup(void)
{
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

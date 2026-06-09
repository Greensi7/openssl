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
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_SESSION_TICKET_INPUT_LEN 4096

struct fuzz_ticket_cb_arg {
    int ret;
};

static int fuzz_session_ticket_cb(SSL *ssl, const unsigned char *data,
                                  int len, void *arg)
{
    struct fuzz_ticket_cb_arg *cbarg = arg;

    return cbarg != NULL ? cbarg->ret : 1;
}

static void fuzz_ctos_session_ticket(const uint8_t *buf, size_t len,
                                     int cb_ret)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s = NULL;
    PACKET pkt;
    struct fuzz_ticket_cb_arg cbarg = { cb_ret };

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_accept_state(ssl);
    if (cb_ret >= 0
        && !SSL_set_session_ticket_ext_cb(ssl, fuzz_session_ticket_cb,
                                          &cbarg))
        goto end;

    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    tls_parse_ctos_session_ticket(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

static void fuzz_stoc_session_ticket(const uint8_t *buf, size_t len,
                                     int cb_ret, int no_ticket)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s = NULL;
    PACKET pkt;
    struct fuzz_ticket_cb_arg cbarg = { cb_ret };

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_connect_state(ssl);
    if (cb_ret >= 0
        && !SSL_set_session_ticket_ext_cb(ssl, fuzz_session_ticket_cb,
                                          &cbarg))
        goto end;
    if (no_ticket)
        SSL_set_options(ssl, SSL_OP_NO_TICKET);

    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    tls_parse_stoc_session_ticket(s, &pkt, SSL_EXT_TLS1_2_SERVER_HELLO,
                                  NULL, 0);

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

    if (len > MAX_FUZZ_SESSION_TICKET_INPUT_LEN)
        return 0;

    fuzz_ctos_session_ticket(buf, len, -1);
    fuzz_ctos_session_ticket(buf, len, 0);
    fuzz_ctos_session_ticket(buf, len, 1);

    fuzz_stoc_session_ticket(buf, len, -1, 0);
    fuzz_stoc_session_ticket(buf, len, 0, 0);
    fuzz_stoc_session_ticket(buf, len, 1, 0);
    fuzz_stoc_session_ticket(buf, len, -1, 1);

    fuzz_stoc_session_ticket(empty, 0, -1, 0);
    fuzz_stoc_session_ticket(empty, 0, 1, 0);

    return 0;
}

void FuzzerCleanup(void)
{
}

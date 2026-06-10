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

#define MAX_FUZZ_STOC_SERVER_NAME_INPUT_LEN 4096

static int setup_session(SSL_CONNECTION *s, unsigned int options)
{
    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        return 0;

    if ((options & 4) != 0
        && !SSL_SESSION_set1_hostname(s->session, "previous.example"))
        return 0;

    return 1;
}

static void fuzz_stoc_server_name(const uint8_t *buf, size_t len,
                                  unsigned int options)
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

    SSL_set_connect_state(ssl);
    if ((options & 1) != 0
        && !SSL_set_tlsext_host_name(ssl, "server.example"))
        goto end;

    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (!setup_session(s, options))
        goto end;

    if ((options & 2) != 0)
        s->hit = 1;

    tls_parse_stoc_server_name(s, &pkt, SSL_EXT_TLS1_2_SERVER_HELLO,
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
    unsigned int options = len > 0 ? buf[0] : 0;
    const uint8_t *payload = len > 0 ? buf + 1 : empty;
    size_t payload_len = len > 0 ? len - 1 : 0;

    if (len > MAX_FUZZ_STOC_SERVER_NAME_INPUT_LEN)
        return 0;

    fuzz_stoc_server_name(payload, payload_len, options);
    fuzz_stoc_server_name(payload, payload_len, options | 1);
    fuzz_stoc_server_name(payload, payload_len, options | 3);
    fuzz_stoc_server_name(payload, payload_len, options | 5);

    fuzz_stoc_server_name(empty, 0, 0);
    fuzz_stoc_server_name(empty, 0, 1);
    fuzz_stoc_server_name(empty, 0, 3);
    fuzz_stoc_server_name(empty, 0, 5);

    return 0;
}

void FuzzerCleanup(void)
{
}

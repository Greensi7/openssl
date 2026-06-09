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

#define MAX_FUZZ_PSK_IDENTITY_INPUT_LEN 4096

static int setup_psk_sessions(SSL_CONNECTION *s, unsigned int options)
{
    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        return 0;

    if ((options & 1) == 0)
        return 1;

    s->psksession = SSL_SESSION_new();
    if (s->psksession == NULL)
        return 0;

    if ((options & 2) != 0)
        s->session->ext.max_early_data = 1;
    if ((options & 4) != 0)
        s->psksession->ext.max_early_data = 1;
    if ((options & 8) != 0)
        s->early_data_state = SSL_EARLY_DATA_WRITE_RETRY;
    if ((options & 16) != 0)
        s->early_data_state = SSL_EARLY_DATA_FINISHED_WRITING;

    return 1;
}

static void fuzz_stoc_psk_identity(const uint8_t *buf, size_t len,
                                   int tick_identity,
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
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (!setup_psk_sessions(s, options))
        goto end;

    s->ext.tick_identity = tick_identity;
    s->ext.early_data_ok = 1;

    tls_parse_stoc_psk(s, &pkt, SSL_EXT_TLS1_3_SERVER_HELLO, NULL, 0);

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
    static const unsigned char identity0[] = { 0, 0 };
    static const unsigned char identity1[] = { 0, 1 };
    unsigned int options = len > 0 ? buf[0] : 0;
    const uint8_t *payload = len > 0 ? buf + 1 : identity0;
    size_t payload_len = len > 0 ? len - 1 : 0;

    if (len > MAX_FUZZ_PSK_IDENTITY_INPUT_LEN)
        return 0;

    fuzz_stoc_psk_identity(payload, payload_len, 0, options);
    fuzz_stoc_psk_identity(payload, payload_len, 1, options);
    fuzz_stoc_psk_identity(payload, payload_len, 2, options);
    fuzz_stoc_psk_identity(payload, payload_len, 255, options);

    fuzz_stoc_psk_identity(identity0, sizeof(identity0), 1, 0);
    fuzz_stoc_psk_identity(identity0, sizeof(identity0), 2, 1);
    fuzz_stoc_psk_identity(identity1, sizeof(identity1), 2, 1);
    fuzz_stoc_psk_identity(identity1, sizeof(identity1), 2, 13);
    fuzz_stoc_psk_identity(identity1, sizeof(identity1), 2, 21);

    return 0;
}

void FuzzerCleanup(void)
{
}

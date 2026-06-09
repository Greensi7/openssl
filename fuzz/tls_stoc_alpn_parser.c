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
#include <string.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_STOC_ALPN_INPUT_LEN 4096

static void fuzz_stoc_alpn(const uint8_t *buf, size_t len,
                           const unsigned char *protos,
                           unsigned int protos_len,
                           const unsigned char *session_alpn,
                           size_t session_alpn_len)
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
    if (SSL_set_alpn_protos(ssl, protos, protos_len) != 0)
        goto end;

    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        goto end;

    s->s3.alpn_sent = 1;
    s->ext.early_data_ok = 1;

    if (session_alpn != NULL) {
        s->hit = 1;
        if (!SSL_SESSION_set1_alpn_selected(s->session, session_alpn,
                                            session_alpn_len))
            goto end;
    }

    tls_parse_stoc_alpn(s, &pkt, 0, NULL, 0);

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
    static const unsigned char default_protos[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'
    };
    static const unsigned char h2[] = { 'h', '2' };
    unsigned char *configured = NULL;
    unsigned char *wrapped = NULL;
    size_t wrapped_len;

    if (len > MAX_FUZZ_STOC_ALPN_INPUT_LEN)
        return 0;

    fuzz_stoc_alpn(buf, len, default_protos, sizeof(default_protos),
                   NULL, 0);
    fuzz_stoc_alpn(buf, len, default_protos, sizeof(default_protos),
                   h2, sizeof(h2));

    if (len == 0 || len > 255)
        return 0;

    configured = OPENSSL_malloc(len + 1);
    wrapped = OPENSSL_malloc(len + 3);
    if (configured == NULL || wrapped == NULL)
        goto end;

    configured[0] = (unsigned char)len;
    memcpy(configured + 1, buf, len);

    wrapped_len = len + 3;
    wrapped[0] = (unsigned char)((len + 1) >> 8);
    wrapped[1] = (unsigned char)(len + 1);
    wrapped[2] = (unsigned char)len;
    memcpy(wrapped + 3, buf, len);

    fuzz_stoc_alpn(wrapped, wrapped_len, configured,
                   (unsigned int)(len + 1), NULL, 0);
    fuzz_stoc_alpn(wrapped, wrapped_len, configured,
                   (unsigned int)(len + 1), buf, len);

end:
    OPENSSL_free(configured);
    OPENSSL_free(wrapped);
    return 0;
}

void FuzzerCleanup(void)
{
}

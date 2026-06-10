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

#define MAX_FUZZ_CTOS_PSK_INPUT_LEN 4096
#define FUZZ_PSK_BINDER_LEN 32

static const unsigned char tls13_aes128_gcm_sha256[] = { 0x13, 0x01 };

static int find_psk_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
    static const unsigned char psk[] = {
        0x70, 0x73, 0x6b, 0x20, 0x66, 0x75, 0x7a, 0x7a,
        0x65, 0x72, 0x20, 0x73, 0x65, 0x65, 0x64, 0x00
    };
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl,
                                               tls13_aes128_gcm_sha256);
    SSL_SESSION *session = NULL;

    (void)identity;
    (void)identity_len;
    *sess = NULL;

    if (cipher == NULL)
        return 1;

    session = SSL_SESSION_new();
    if (session == NULL)
        return 0;

    if (!SSL_SESSION_set1_master_key(session, psk, sizeof(psk))
        || !SSL_SESSION_set_cipher(session, cipher)
        || !SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION)) {
        SSL_SESSION_free(session);
        return 1;
    }

    *sess = session;
    return 1;
}

static int set_server_cipher(SSL *ssl, SSL_CONNECTION *s)
{
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl,
                                               tls13_aes128_gcm_sha256);

    if (cipher == NULL)
        return 0;

    s->s3.tmp.new_cipher = cipher;
    return 1;
}

static void fuzz_ctos_psk(const uint8_t *buf, size_t len,
                          unsigned int options, int use_session_cb)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s = NULL;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_accept_state(ssl);
    if (use_session_cb)
        SSL_set_psk_find_session_callback(ssl, find_psk_session_cb);

    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (!set_server_cipher(ssl, s))
        goto end;

    if ((options & 1) != 0)
        s->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE;
    else
        s->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if ((options & 2) != 0)
        s->ext.psk_kex_mode |= TLSEXT_KEX_MODE_FLAG_KE;
    if ((options & 4) != 0)
        s->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_NONE;
    if ((options & 8) != 0)
        SSL_set_options(ssl, SSL_OP_NO_TICKET);
    if ((options & 16) != 0)
        SSL_set_max_early_data(ssl, 1);
    if ((options & 32) != 0)
        SSL_set_options(ssl, SSL_OP_NO_ANTI_REPLAY);

    s->version = TLS1_3_VERSION;
    tls_parse_ctos_psk(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

static void fuzz_wrapped_identity(const uint8_t *buf, size_t len,
                                  unsigned int options)
{
    unsigned char *wrapped = NULL;
    size_t identities_len = len + 6;
    size_t packet_len = 2 + identities_len + 2 + 1 + FUZZ_PSK_BINDER_LEN;
    size_t off = 0;
    size_t i;

    if (identities_len > 0xffff)
        return;

    wrapped = OPENSSL_zalloc(packet_len);
    if (wrapped == NULL)
        return;

    wrapped[off++] = (unsigned char)(identities_len >> 8);
    wrapped[off++] = (unsigned char)identities_len;
    wrapped[off++] = (unsigned char)(len >> 8);
    wrapped[off++] = (unsigned char)len;
    if (len > 0)
        memcpy(wrapped + off, buf, len);
    off += len;

    wrapped[off++] = (unsigned char)(options >> 24);
    wrapped[off++] = (unsigned char)(options >> 16);
    wrapped[off++] = (unsigned char)(options >> 8);
    wrapped[off++] = (unsigned char)options;

    wrapped[off++] = 0;
    wrapped[off++] = FUZZ_PSK_BINDER_LEN + 1;
    wrapped[off++] = FUZZ_PSK_BINDER_LEN;
    for (i = 0; i < FUZZ_PSK_BINDER_LEN; i++)
        wrapped[off + i] = len == 0 ? 0 : buf[i % len];

    fuzz_ctos_psk(wrapped, packet_len, options, 0);
    fuzz_ctos_psk(wrapped, packet_len, options, 1);
    OPENSSL_free(wrapped);
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
    static const unsigned char empty_identities[] = { 0, 0 };
    unsigned int options = len > 0 ? buf[0] : 0;
    const uint8_t *payload = len > 0 ? buf + 1 : buf;
    size_t payload_len = len > 0 ? len - 1 : 0;

    if (len > MAX_FUZZ_CTOS_PSK_INPUT_LEN)
        return 0;

    fuzz_ctos_psk(payload, payload_len, options, 0);
    fuzz_ctos_psk(payload, payload_len, options, 1);
    fuzz_ctos_psk(payload, payload_len, options | 4, 0);

    fuzz_wrapped_identity(payload, payload_len, options);
    fuzz_wrapped_identity(payload, payload_len, options | 8);
    fuzz_wrapped_identity(payload, payload_len, options | 16);

    fuzz_ctos_psk(empty_identities, sizeof(empty_identities), 0, 0);
    fuzz_ctos_psk(empty_identities, sizeof(empty_identities), 4, 1);

    return 0;
}

void FuzzerCleanup(void)
{
}

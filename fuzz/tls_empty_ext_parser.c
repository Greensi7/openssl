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

#define MAX_FUZZ_EMPTY_EXT_INPUT_LEN 4096

enum fuzz_server_empty_ext {
    FUZZ_CTOS_ETM,
    FUZZ_CTOS_EMS,
    FUZZ_CTOS_EARLY_DATA,
    FUZZ_CTOS_POST_HANDSHAKE_AUTH
};

enum fuzz_client_empty_ext {
    FUZZ_STOC_ETM,
    FUZZ_STOC_EMS,
    FUZZ_STOC_EARLY_DATA_EE,
    FUZZ_STOC_EARLY_DATA_NST
};

static int set_client_cipher(SSL *ssl, SSL_CONNECTION *s, int use_aead)
{
    static const unsigned char aes128_sha[] = { 0x00, 0x2f };
    static const unsigned char tls13_aes128_gcm_sha256[] = { 0x13, 0x01 };
    const SSL_CIPHER *cipher = NULL;

    cipher = SSL_CIPHER_find(ssl, use_aead
                                  ? tls13_aes128_gcm_sha256
                                  : aes128_sha);
    if (cipher == NULL)
        cipher = SSL_CIPHER_find(ssl, use_aead
                                      ? aes128_sha
                                      : tls13_aes128_gcm_sha256);
    if (cipher == NULL)
        return 0;

    s->s3.tmp.new_cipher = cipher;
    return 1;
}

static void fuzz_server_empty_ext(const uint8_t *buf, size_t len,
                                  enum fuzz_server_empty_ext ext,
                                  unsigned int options)
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
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if ((options & 1) != 0)
        SSL_set_options(ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);
    if ((options & 2) != 0)
        SSL_set_options(ssl, SSL_OP_NO_EXTENDED_MASTER_SECRET);
    if ((options & 4) != 0)
        s->hello_retry_request = SSL_HRR_PENDING;

    switch (ext) {
    case FUZZ_CTOS_ETM:
        tls_parse_ctos_etm(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);
        break;
    case FUZZ_CTOS_EMS:
        tls_parse_ctos_ems(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);
        break;
    case FUZZ_CTOS_EARLY_DATA:
        tls_parse_ctos_early_data(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);
        break;
    case FUZZ_CTOS_POST_HANDSHAKE_AUTH:
        tls_parse_ctos_post_handshake_auth(s, &pkt, SSL_EXT_CLIENT_HELLO,
                                           NULL, 0);
        break;
    }

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

static void fuzz_client_empty_ext(const uint8_t *buf, size_t len,
                                  enum fuzz_client_empty_ext ext,
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

    if ((options & 1) != 0)
        SSL_set_options(ssl, SSL_OP_NO_ENCRYPT_THEN_MAC);
    if ((options & 2) != 0)
        SSL_set_options(ssl, SSL_OP_NO_EXTENDED_MASTER_SECRET);

    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        goto end;

    if ((options & 4) != 0)
        s->hit = 1;
    if ((options & 8) != 0)
        s->ext.early_data_ok = 1;

    switch (ext) {
    case FUZZ_STOC_ETM:
        if (set_client_cipher(ssl, s, (options & 16) != 0))
            tls_parse_stoc_etm(s, &pkt, SSL_EXT_TLS1_2_SERVER_HELLO, NULL, 0);
        break;
    case FUZZ_STOC_EMS:
        tls_parse_stoc_ems(s, &pkt, SSL_EXT_TLS1_2_SERVER_HELLO, NULL, 0);
        break;
    case FUZZ_STOC_EARLY_DATA_EE:
        tls_parse_stoc_early_data(s, &pkt, SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                                  NULL, 0);
        break;
    case FUZZ_STOC_EARLY_DATA_NST:
        tls_parse_stoc_early_data(s, &pkt, SSL_EXT_TLS1_3_NEW_SESSION_TICKET,
                                  NULL, 0);
        break;
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
    static const unsigned char empty[] = { 0 };
    static const unsigned char zero_early_data[] = { 0, 0, 0, 0 };
    unsigned int options = len > 0 ? buf[0] : 0;
    const uint8_t *payload = len > 0 ? buf + 1 : empty;
    size_t payload_len = len > 0 ? len - 1 : 0;

    if (len > MAX_FUZZ_EMPTY_EXT_INPUT_LEN)
        return 0;

    fuzz_server_empty_ext(payload, payload_len, FUZZ_CTOS_ETM, options);
    fuzz_server_empty_ext(payload, payload_len, FUZZ_CTOS_EMS, options);
    fuzz_server_empty_ext(payload, payload_len, FUZZ_CTOS_EARLY_DATA, options);
    fuzz_server_empty_ext(payload, payload_len, FUZZ_CTOS_POST_HANDSHAKE_AUTH,
                          options);

    fuzz_client_empty_ext(payload, payload_len, FUZZ_STOC_ETM, options);
    fuzz_client_empty_ext(payload, payload_len, FUZZ_STOC_EMS, options);
    fuzz_client_empty_ext(payload, payload_len, FUZZ_STOC_EARLY_DATA_EE,
                          options);
    fuzz_client_empty_ext(payload, payload_len, FUZZ_STOC_EARLY_DATA_NST,
                          options);

    fuzz_server_empty_ext(empty, 0, FUZZ_CTOS_EMS, 0);
    fuzz_server_empty_ext(empty, 0, FUZZ_CTOS_EARLY_DATA, 0);
    fuzz_server_empty_ext(empty, 0, FUZZ_CTOS_POST_HANDSHAKE_AUTH, 0);
    fuzz_client_empty_ext(empty, 0, FUZZ_STOC_EARLY_DATA_EE, 12);
    fuzz_client_empty_ext(zero_early_data, sizeof(zero_early_data),
                          FUZZ_STOC_EARLY_DATA_NST, 0);

    return 0;
}

void FuzzerCleanup(void)
{
}

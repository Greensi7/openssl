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
#include "internal/tlsgroups.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_KEY_SHARE_INPUT_LEN 4096
#define FUZZ_CLIENT_GROUP OSSL_TLS_GROUP_ID_sect163k1
#define FUZZ_CLIENT_GROUP2 OSSL_TLS_GROUP_ID_sect163r1

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

static void fuzz_key_share(const uint8_t *buf, size_t len)
{
    static const unsigned char supported_groups[] = {
        0x00, 0x04,
        (FUZZ_CLIENT_GROUP >> 8) & 0xff,
        FUZZ_CLIENT_GROUP & 0xff,
        (FUZZ_CLIENT_GROUP2 >> 8) & 0xff,
        FUZZ_CLIENT_GROUP2 & 0xff
    };
    SSL_CONNECTION *s = NULL;
    PACKET groups, key_share;

    if (!PACKET_buf_init(&key_share, buf, len))
        return;

    if (ssl == NULL)
        return;

    SSL_clear(ssl);
    SSL_set_accept_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        goto end;

    if (!PACKET_buf_init(&groups, supported_groups, sizeof(supported_groups)))
        goto end;
    if (tls_parse_ctos_supported_groups(s, &groups, 0, NULL, 0) != 1)
        goto end;

    tls_parse_ctos_key_share(s, &key_share, 0, NULL, 0);

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
    ssl = SSL_new(ctx);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    unsigned char *wrapped = NULL;
    size_t wrapped_len;

    if (len == 0 || len > MAX_FUZZ_KEY_SHARE_INPUT_LEN)
        return 0;

    fuzz_key_share(buf, len);

    if (len > 0xffff)
        return 0;

    wrapped_len = len + 2;
    wrapped = OPENSSL_malloc(wrapped_len);
    if (wrapped == NULL)
        return 0;

    wrapped[0] = (unsigned char)(len >> 8);
    wrapped[1] = (unsigned char)len;
    memcpy(wrapped + 2, buf, len);
    fuzz_key_share(wrapped, wrapped_len);

    if (len <= 0xffff - 4) {
        unsigned char *tmp = NULL;

        wrapped_len = len + 6;
        tmp = OPENSSL_realloc(wrapped, wrapped_len);
        if (tmp == NULL)
            goto end;
        wrapped = tmp;

        wrapped[0] = (unsigned char)((len + 4) >> 8);
        wrapped[1] = (unsigned char)(len + 4);
        wrapped[2] = (FUZZ_CLIENT_GROUP >> 8) & 0xff;
        wrapped[3] = FUZZ_CLIENT_GROUP & 0xff;
        wrapped[4] = (unsigned char)(len >> 8);
        wrapped[5] = (unsigned char)len;
        memcpy(wrapped + 6, buf, len);
        fuzz_key_share(wrapped, wrapped_len);
    }

end:
    OPENSSL_free(wrapped);
    return 0;
}

void FuzzerCleanup(void)
{
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

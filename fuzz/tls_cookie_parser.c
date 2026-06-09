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

#define MAX_FUZZ_COOKIE_INPUT_LEN 4096

static void fuzz_cookie(const uint8_t *buf, size_t len)
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

    tls_parse_stoc_cookie(s, &pkt, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST,
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
    unsigned char *wrapped = NULL;

    if (len > MAX_FUZZ_COOKIE_INPUT_LEN)
        return 0;

    if (len > 0)
        fuzz_cookie(buf, len);

    wrapped = OPENSSL_malloc(len + 2);
    if (wrapped == NULL)
        return 0;

    wrapped[0] = (unsigned char)(len >> 8);
    wrapped[1] = (unsigned char)len;
    if (len > 0)
        memcpy(wrapped + 2, buf, len);
    fuzz_cookie(wrapped, len + 2);
    OPENSSL_free(wrapped);

    return 0;
}

void FuzzerCleanup(void)
{
}

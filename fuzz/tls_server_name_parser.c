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

#define MAX_FUZZ_SERVER_NAME_INPUT_LEN 4096

static void fuzz_server_name(const uint8_t *buf, size_t len)
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

    tls_parse_ctos_server_name(s, &pkt, 0, NULL, 0);

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
    size_t wrapped_len;
    size_t server_name_list_len;

    if (len == 0 || len > MAX_FUZZ_SERVER_NAME_INPUT_LEN)
        return 0;

    fuzz_server_name(buf, len);

    wrapped_len = len + 5;
    wrapped = OPENSSL_malloc(wrapped_len);
    if (wrapped == NULL)
        return 0;

    server_name_list_len = len + 3;
    wrapped[0] = (unsigned char)(server_name_list_len >> 8);
    wrapped[1] = (unsigned char)server_name_list_len;
    wrapped[2] = TLSEXT_NAMETYPE_host_name;
    wrapped[3] = (unsigned char)(len >> 8);
    wrapped[4] = (unsigned char)len;
    memcpy(wrapped + 5, buf, len);

    fuzz_server_name(wrapped, wrapped_len);
    OPENSSL_free(wrapped);

    return 0;
}

void FuzzerCleanup(void)
{
}

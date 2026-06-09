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

#define MAX_FUZZ_EC_POINT_FORMATS_INPUT_LEN 4096

static void fuzz_ec_point_formats(const uint8_t *buf, size_t len)
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

    tls_parse_ctos_ec_pt_formats(s, &pkt, 0, NULL, 0);

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

    if (len == 0 || len > MAX_FUZZ_EC_POINT_FORMATS_INPUT_LEN)
        return 0;

    fuzz_ec_point_formats(buf, len);

    if (len > 255)
        return 0;

    wrapped = OPENSSL_malloc(len + 1);
    if (wrapped == NULL)
        return 0;

    wrapped[0] = (unsigned char)len;
    memcpy(wrapped + 1, buf, len);

    fuzz_ec_point_formats(wrapped, len + 1);
    OPENSSL_free(wrapped);

    return 0;
}

void FuzzerCleanup(void)
{
}

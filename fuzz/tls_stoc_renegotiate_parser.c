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
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <string.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_STOC_RENEGOTIATE_INPUT_LEN 4096

static void fuzz_stoc_renegotiate(const uint8_t *buf, size_t len,
                                  const uint8_t *previous_client,
                                  size_t previous_client_len,
                                  const uint8_t *previous_server,
                                  size_t previous_server_len)
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

    if (previous_client != NULL && previous_server != NULL) {
        memcpy(s->s3.previous_client_finished, previous_client,
               previous_client_len);
        s->s3.previous_client_finished_len = previous_client_len;
        memcpy(s->s3.previous_server_finished, previous_server,
               previous_server_len);
        s->s3.previous_server_finished_len = previous_server_len;
    }

    tls_parse_stoc_renegotiate(s, &pkt, 0, NULL, 0);

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
    static const unsigned char empty_renegotiate[] = { 0 };
    unsigned char *wrapped = NULL;
    size_t previous_client_len, previous_server_len;

    if (len > MAX_FUZZ_STOC_RENEGOTIATE_INPUT_LEN)
        return 0;

    fuzz_stoc_renegotiate(buf, len, NULL, 0, NULL, 0);
    fuzz_stoc_renegotiate(empty_renegotiate, sizeof(empty_renegotiate),
                          NULL, 0, NULL, 0);

    if (len < 2 || len > EVP_MAX_MD_SIZE * 2 || len > 255)
        return 0;

    previous_client_len = len / 2;
    previous_server_len = len - previous_client_len;

    fuzz_stoc_renegotiate(buf, len, buf, previous_client_len,
                          buf + previous_client_len, previous_server_len);

    wrapped = OPENSSL_malloc(len + 1);
    if (wrapped == NULL)
        return 0;

    wrapped[0] = (unsigned char)len;
    memcpy(wrapped + 1, buf, len);

    fuzz_stoc_renegotiate(wrapped, len + 1, buf, previous_client_len,
                          buf + previous_client_len, previous_server_len);
    OPENSSL_free(wrapped);

    return 0;
}

void FuzzerCleanup(void)
{
}

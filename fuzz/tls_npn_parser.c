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

#define MAX_FUZZ_NPN_INPUT_LEN 4096

struct fuzz_npn_select_arg {
    int ret;
    int empty_selection;
};

static int fuzz_npn_select_cb(SSL *ssl, unsigned char **out,
                              unsigned char *outlen,
                              const unsigned char *in, unsigned int inlen,
                              void *arg)
{
    static const unsigned char fallback_proto[] = { 'h', '2' };
    struct fuzz_npn_select_arg *cbarg = arg;

    (void)ssl;

    if (cbarg != NULL && cbarg->ret != SSL_TLSEXT_ERR_OK)
        return cbarg->ret;

    if (cbarg != NULL && cbarg->empty_selection) {
        *out = (unsigned char *)in;
        *outlen = 0;
        return SSL_TLSEXT_ERR_OK;
    }

    if (inlen == 0) {
        *out = (unsigned char *)fallback_proto;
        *outlen = sizeof(fallback_proto);
        return SSL_TLSEXT_ERR_OK;
    }

    *out = (unsigned char *)in + 1;
    *outlen = in[0];
    return SSL_TLSEXT_ERR_OK;
}

static void fuzz_ctos_npn(const uint8_t *buf, size_t len,
                          int first_handshake)
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

    if (!first_handshake) {
        s->s3.tmp.finish_md_len = 1;
        s->s3.tmp.peer_finish_md_len = 1;
    }

    tls_parse_ctos_npn(s, &pkt, SSL_EXT_CLIENT_HELLO, NULL, 0);

end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

static void fuzz_stoc_npn(const uint8_t *buf, size_t len,
                          const struct fuzz_npn_select_arg *select_arg,
                          int first_handshake)
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

    if (select_arg != NULL)
        SSL_CTX_set_npn_select_cb(ctx, fuzz_npn_select_cb,
                                  (void *)select_arg);

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_connect_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    if (!first_handshake) {
        s->s3.tmp.finish_md_len = 1;
        s->s3.tmp.peer_finish_md_len = 1;
    }

    tls_parse_stoc_npn(s, &pkt, SSL_EXT_TLS1_2_SERVER_HELLO, NULL, 0);

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
    static const struct fuzz_npn_select_arg ok_select = {
        SSL_TLSEXT_ERR_OK, 0
    };
    static const struct fuzz_npn_select_arg empty_select = {
        SSL_TLSEXT_ERR_OK, 1
    };
    static const struct fuzz_npn_select_arg fatal_select = {
        SSL_TLSEXT_ERR_ALERT_FATAL, 0
    };
    unsigned char *wrapped = NULL;

    if (len > MAX_FUZZ_NPN_INPUT_LEN)
        return 0;

    fuzz_ctos_npn(buf, len, 1);
    fuzz_ctos_npn(buf, len, 0);

    fuzz_stoc_npn(buf, len, NULL, 1);
    fuzz_stoc_npn(buf, len, &ok_select, 1);
    fuzz_stoc_npn(buf, len, &empty_select, 1);
    fuzz_stoc_npn(buf, len, &fatal_select, 1);
    fuzz_stoc_npn(buf, len, NULL, 0);

    fuzz_stoc_npn(default_protos, sizeof(default_protos), &ok_select, 1);
    fuzz_stoc_npn(default_protos, sizeof(default_protos), &empty_select, 1);
    fuzz_stoc_npn(default_protos, sizeof(default_protos), &fatal_select, 1);

    if (len == 0 || len > 255)
        return 0;

    wrapped = OPENSSL_malloc(len + 1);
    if (wrapped == NULL)
        return 0;

    wrapped[0] = (unsigned char)len;
    memcpy(wrapped + 1, buf, len);

    fuzz_stoc_npn(wrapped, len + 1, &ok_select, 1);
    fuzz_stoc_npn(wrapped, len + 1, &empty_select, 1);
    fuzz_stoc_npn(wrapped, len + 1, &fatal_select, 1);

    OPENSSL_free(wrapped);
    return 0;
}

void FuzzerCleanup(void)
{
}

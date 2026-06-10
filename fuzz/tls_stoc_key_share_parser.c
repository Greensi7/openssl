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

#define MAX_FUZZ_STOC_KEY_SHARE_INPUT_LEN 4096
#define FUZZ_SENT_GROUP OSSL_TLS_GROUP_ID_secp256r1
#define FUZZ_HRR_GROUP OSSL_TLS_GROUP_ID_x25519

static int setup_client_key_share(SSL_CONNECTION *s)
{
    EVP_PKEY *pkey = ssl_generate_pkey_group(s, FUZZ_SENT_GROUP);

    if (pkey == NULL)
        return 0;

    s->s3.tmp.pkey = pkey;
    s->s3.group_id = FUZZ_SENT_GROUP;
    s->s3.tmp.ks_pkey[0] = pkey;
    s->s3.tmp.ks_group_id[0] = FUZZ_SENT_GROUP;
    s->s3.tmp.num_ks_pkey = 1;
    return 1;
}

static void fuzz_stoc_key_share(const uint8_t *buf, size_t len,
                                unsigned int context)
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

    if (s->session == NULL)
        s->session = SSL_SESSION_new();
    if (s->session == NULL)
        goto end;

    if (!setup_client_key_share(s))
        goto end;

    tls_parse_stoc_key_share(s, &pkt, context, NULL, 0);

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
    static const unsigned char hrr_group[] = {
        (FUZZ_HRR_GROUP >> 8) & 0xff,
        FUZZ_HRR_GROUP & 0xff
    };
    static const unsigned char sent_group[] = {
        (FUZZ_SENT_GROUP >> 8) & 0xff,
        FUZZ_SENT_GROUP & 0xff
    };
    static const unsigned char grease_group[] = { 0x0a, 0x0a };
    unsigned char *server_share = NULL;
    size_t server_share_len;

    if (len > MAX_FUZZ_STOC_KEY_SHARE_INPUT_LEN)
        return 0;

    fuzz_stoc_key_share(buf, len, SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
    fuzz_stoc_key_share(buf, len, SSL_EXT_TLS1_3_SERVER_HELLO);

    fuzz_stoc_key_share(hrr_group, sizeof(hrr_group),
                        SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
    fuzz_stoc_key_share(sent_group, sizeof(sent_group),
                        SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
    fuzz_stoc_key_share(grease_group, sizeof(grease_group),
                        SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);

    server_share_len = len + 4;
    server_share = OPENSSL_malloc(server_share_len);
    if (server_share == NULL)
        return 0;

    server_share[0] = (FUZZ_SENT_GROUP >> 8) & 0xff;
    server_share[1] = FUZZ_SENT_GROUP & 0xff;
    server_share[2] = (unsigned char)(len >> 8);
    server_share[3] = (unsigned char)len;
    memcpy(server_share + 4, buf, len);
    fuzz_stoc_key_share(server_share, server_share_len,
                        SSL_EXT_TLS1_3_SERVER_HELLO);

    OPENSSL_free(server_share);
    return 0;
}

void FuzzerCleanup(void)
{
}

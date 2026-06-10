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
#include <openssl/srtp.h>
#include "internal/packet.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "fuzzer.h"

#define MAX_FUZZ_STOC_USE_SRTP_INPUT_LEN 4096

static void fuzz_stoc_use_srtp(const uint8_t *buf, size_t len, int configured)
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

    if (configured
        && SSL_CTX_set_tlsext_use_srtp(ctx,
               "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:"
               "SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM") != 0)
        goto end;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto end;

    SSL_set_connect_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (s == NULL)
        goto end;

    tls_parse_stoc_use_srtp(s, &pkt, 0, NULL, 0);

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
    static const unsigned char aes128_sha1_80[] = {
        0, 2,
        (SRTP_AES128_CM_SHA1_80 >> 8) & 0xff,
        SRTP_AES128_CM_SHA1_80 & 0xff,
        0
    };
    static const unsigned char bad_mki[] = {
        0, 2,
        (SRTP_AES128_CM_SHA1_80 >> 8) & 0xff,
        SRTP_AES128_CM_SHA1_80 & 0xff,
        1
    };
    static const unsigned char unsupported_profile[] = {
        0, 2, 0xff, 0xff, 0
    };
    unsigned char selected[] = { 0, 2, 0, 0, 0 };

    if (len > MAX_FUZZ_STOC_USE_SRTP_INPUT_LEN)
        return 0;

    fuzz_stoc_use_srtp(buf, len, 0);
    fuzz_stoc_use_srtp(buf, len, 1);
    fuzz_stoc_use_srtp(aes128_sha1_80, sizeof(aes128_sha1_80), 0);
    fuzz_stoc_use_srtp(aes128_sha1_80, sizeof(aes128_sha1_80), 1);
    fuzz_stoc_use_srtp(bad_mki, sizeof(bad_mki), 1);
    fuzz_stoc_use_srtp(unsupported_profile, sizeof(unsupported_profile), 1);

    if (len >= 2) {
        selected[2] = buf[0];
        selected[3] = buf[1];
        if (len >= 3)
            selected[4] = buf[2];
        fuzz_stoc_use_srtp(selected, sizeof(selected), 1);
    }

    return 0;
}

void FuzzerCleanup(void)
{
}

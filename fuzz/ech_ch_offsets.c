/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/ech_helpers.h"
#include "fuzzer.h"

#define MAX_FUZZ_CH_EXTENSIONS 4096

static void fuzz_get_ch_offsets(const uint8_t *ch, size_t ch_len)
{
    size_t sessid_off = 0;
    size_t exts_off = 0;
    size_t exts_len = 0;
    size_t ech_off = 0;
    size_t ech_len = 0;
    size_t sni_off = 0;
    size_t sni_len = 0;
    uint16_t echtype = 0;
    int inner = 0;

    ossl_ech_helper_get_ch_offsets(ch, ch_len, &sessid_off, &exts_off,
                                   &exts_len, &ech_off, &echtype, &ech_len,
                                   &sni_off, &sni_len, &inner);
}

static void fuzz_ch_with_extensions(const uint8_t *exts, size_t exts_len)
{
    static const unsigned char suite[] = { 0x13, 0x01 };
    size_t ch_len = 2 + SSL3_RANDOM_SIZE + 1 + 2 + sizeof(suite) + 1 + 1
                    + 2 + exts_len;
    unsigned char *ch = OPENSSL_zalloc(ch_len);
    unsigned char *p = ch;

    if (ch == NULL)
        return;

    *p++ = (unsigned char)(TLS1_2_VERSION >> 8);
    *p++ = (unsigned char)TLS1_2_VERSION;
    p += SSL3_RANDOM_SIZE;
    *p++ = 0; /* session_id length */
    *p++ = 0;
    *p++ = (unsigned char)sizeof(suite);
    memcpy(p, suite, sizeof(suite));
    p += sizeof(suite);
    *p++ = 1; /* compression methods length */
    *p++ = 0;
    *p++ = (unsigned char)(exts_len >> 8);
    *p++ = (unsigned char)exts_len;
    memcpy(p, exts, exts_len);

    fuzz_get_ch_offsets(ch, ch_len);
    OPENSSL_free(ch);
}

static void fuzz_ch_with_wrapped_extension(const uint8_t *buf, size_t len,
                                           uint16_t ext_type)
{
    size_t exts_len = len + 4;
    unsigned char *exts = OPENSSL_malloc(exts_len);

    if (exts == NULL)
        return;

    exts[0] = (unsigned char)(ext_type >> 8);
    exts[1] = (unsigned char)ext_type;
    exts[2] = (unsigned char)(len >> 8);
    exts[3] = (unsigned char)len;
    memcpy(exts + 4, buf, len);

    fuzz_ch_with_extensions(exts, exts_len);
    OPENSSL_free(exts);
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
    if (len == 0 || len > MAX_FUZZ_CH_EXTENSIONS)
        return 0;

    fuzz_get_ch_offsets(buf, len);
    fuzz_ch_with_extensions(buf, len);
    fuzz_ch_with_wrapped_extension(buf, len, TLSEXT_TYPE_ech);
    fuzz_ch_with_wrapped_extension(buf, len, TLSEXT_TYPE_server_name);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

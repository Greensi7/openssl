/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/packet.h"
#include "internal/quic_wire.h"
#include "fuzzer.h"

#define MAX_FUZZ_TPARAM_INPUT_LEN 8192
#define MAX_FUZZ_TPARAMS 64

static void fuzz_decode_one_tparam(PACKET *pkt)
{
    PACKET pbytes = *pkt;
    PACKET pint = *pkt;
    PACKET pcid = *pkt;
    PACKET ppreferred = *pkt;
    uint64_t id = 0;
    uint64_t value = 0;
    size_t len = 0;
    const unsigned char *body = NULL;
    QUIC_CONN_ID cid = { 0 };
    QUIC_PREFERRED_ADDR preferred = { 0 };

    ossl_quic_wire_peek_transport_param(pkt, &id);
    ossl_quic_wire_decode_transport_param_int(&pint, &id, &value);
    ossl_quic_wire_decode_transport_param_cid(&pcid, &id, &cid);
    ossl_quic_wire_decode_transport_param_preferred_addr(&ppreferred,
                                                         &preferred);

    body = ossl_quic_wire_decode_transport_param_bytes(&pbytes, &id, &len);
    if (body == NULL)
        return;

    *pkt = pbytes;
}

static void fuzz_decode_tparam_sequence(const uint8_t *buf, size_t len)
{
    PACKET pkt;
    size_t i;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    for (i = 0; i < MAX_FUZZ_TPARAMS && PACKET_remaining(&pkt) > 0; ++i) {
        size_t before = PACKET_remaining(&pkt);

        fuzz_decode_one_tparam(&pkt);
        if (PACKET_remaining(&pkt) >= before)
            return;
    }
}

int FuzzerInitialize(int *argc, char ***argv)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    if (len == 0 || len > MAX_FUZZ_TPARAM_INPUT_LEN)
        return 0;

    fuzz_decode_tparam_sequence(buf, len);
    if (len > 1)
        fuzz_decode_tparam_sequence(buf + 1, len - 1);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

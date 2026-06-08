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
#include "internal/quic_wire_pkt.h"
#include "fuzzer.h"

#define MAX_FUZZ_QUIC_PACKET_INPUT_LEN 8192
#define MAX_FUZZ_QUIC_PACKETS 16

static void fuzz_pkt_helpers(const unsigned char *buf, size_t len,
                             size_t short_conn_id_len)
{
    QUIC_CONN_ID dst_conn_id = { 0 };
    QUIC_PN pn = 0;
    uint64_t largest_pn = len;
    size_t pn_len;

    ossl_quic_wire_get_pkt_hdr_dst_conn_id(buf, len, short_conn_id_len,
                                           &dst_conn_id);

    for (pn_len = 1; pn_len <= 4 && pn_len <= len; ++pn_len)
        ossl_quic_wire_decode_pkt_hdr_pn(buf, pn_len, largest_pn, &pn);

    ossl_quic_wire_determine_pn_len((QUIC_PN)len, largest_pn);
}

static void fuzz_decoded_hdr(const QUIC_PKT_HDR *hdr,
                             size_t short_conn_id_len)
{
    QUIC_PN pn = 0;
    uint32_t enc_level;

    ossl_quic_pkt_type_is_encrypted(hdr->type);
    ossl_quic_pkt_type_has_pn(hdr->type);
    ossl_quic_pkt_type_can_share_dgram(hdr->type);
    ossl_quic_pkt_type_must_be_last(hdr->type);
    ossl_quic_pkt_type_has_version(hdr->type);
    ossl_quic_pkt_type_has_scid(hdr->type);
    enc_level = ossl_quic_pkt_type_to_enc_level(hdr->type);
    ossl_quic_enc_level_to_pkt_type(enc_level);
    ossl_quic_wire_get_encoded_pkt_hdr_len(short_conn_id_len, hdr);

    if (!hdr->partial && hdr->pn_len >= 1 && hdr->pn_len <= sizeof(hdr->pn))
        ossl_quic_wire_decode_pkt_hdr_pn(hdr->pn, hdr->pn_len, 0, &pn);
}

static void fuzz_decode_sequence(const unsigned char *buf, size_t len,
                                 size_t short_conn_id_len,
                                 int partial, int nodata)
{
    PACKET pkt;
    size_t i;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    for (i = 0; i < MAX_FUZZ_QUIC_PACKETS && PACKET_remaining(&pkt) > 0; ++i) {
        QUIC_PKT_HDR hdr = { 0 };
        QUIC_PKT_HDR_PTRS ptrs = { 0 };
        uint64_t fail_cause = 0;
        size_t before = PACKET_remaining(&pkt);

        if (!ossl_quic_wire_decode_pkt_hdr(&pkt, short_conn_id_len, partial,
                                           nodata, &hdr, &ptrs, &fail_cause))
            return;

        fuzz_decoded_hdr(&hdr, short_conn_id_len);
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
    size_t short_conn_id_len;

    if (len == 0 || len > MAX_FUZZ_QUIC_PACKET_INPUT_LEN)
        return 0;

    short_conn_id_len = buf[0] % (QUIC_MAX_CONN_ID_LEN + 1);

    fuzz_pkt_helpers(buf, len, 0);
    fuzz_pkt_helpers(buf, len, short_conn_id_len);
    fuzz_pkt_helpers(buf, len, QUIC_MAX_CONN_ID_LEN);
    fuzz_pkt_helpers(buf, len, (size_t)-1);

    fuzz_decode_sequence(buf, len, short_conn_id_len, 0, 0);
    fuzz_decode_sequence(buf, len, short_conn_id_len, 1, 0);
    fuzz_decode_sequence(buf, len, short_conn_id_len, 0, 1);
    fuzz_decode_sequence(buf, len, (size_t)-1, 1, 1);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

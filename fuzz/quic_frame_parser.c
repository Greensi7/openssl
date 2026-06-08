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

#define MAX_FUZZ_QUIC_FRAME_INPUT_LEN 8192
#define MAX_FUZZ_QUIC_FRAMES 64
#define MAX_FUZZ_ACK_RANGES 16

static int fuzz_decode_ack(PACKET *pkt, uint32_t ack_delay_exp)
{
    OSSL_QUIC_ACK_RANGE ranges[MAX_FUZZ_ACK_RANGES];
    OSSL_QUIC_FRAME_ACK ack = { 0 };
    uint64_t total_ranges = 0;
    PACKET peek = *pkt;
    int ret;

    ack.ack_ranges = ranges;
    ack.num_ack_ranges = MAX_FUZZ_ACK_RANGES;

    ossl_quic_wire_peek_frame_ack_num_ranges(&peek, &total_ranges);
    ret = ossl_quic_wire_decode_frame_ack(pkt, ack_delay_exp, &ack,
                                          &total_ranges);
    if (ret && ack.num_ack_ranges > 0)
        ossl_quic_frame_ack_contains_pn(&ack, ack.ack_ranges[0].start);

    return ret;
}

static int fuzz_decode_one_frame(PACKET *pkt, uint32_t ack_delay_exp)
{
    uint64_t frame_type = 0;
    uint64_t tmp64 = 0;
    uint64_t tmp64_2 = 0;
    int was_minimal = 0;
    PACKET preview = *pkt;
    OSSL_QUIC_FRAME_RESET_STREAM reset_stream = { 0 };
    OSSL_QUIC_FRAME_STOP_SENDING stop_sending = { 0 };
    OSSL_QUIC_FRAME_CRYPTO crypto = { 0 };
    OSSL_QUIC_FRAME_STREAM stream = { 0 };
    OSSL_QUIC_FRAME_NEW_CONN_ID new_conn_id = { 0 };
    OSSL_QUIC_FRAME_CONN_CLOSE conn_close = { 0 };
    const unsigned char *token = NULL;
    size_t token_len = 0;

    if (!ossl_quic_wire_peek_frame_header(pkt, &frame_type, &was_minimal))
        return 0;

    ossl_quic_frame_type_to_string(frame_type);
    ossl_quic_frame_type_is_ack_eliciting(frame_type);

    switch (frame_type) {
    case OSSL_QUIC_FRAME_TYPE_PADDING:
        return ossl_quic_wire_decode_padding(pkt) > 0;
    case OSSL_QUIC_FRAME_TYPE_PING:
        return ossl_quic_wire_decode_frame_ping(pkt);
    case OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN:
    case OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN:
        return fuzz_decode_ack(pkt, ack_delay_exp);
    case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
        return ossl_quic_wire_decode_frame_reset_stream(pkt, &reset_stream);
    case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
        return ossl_quic_wire_decode_frame_stop_sending(pkt, &stop_sending);
    case OSSL_QUIC_FRAME_TYPE_CRYPTO:
        ossl_quic_wire_decode_frame_crypto(&preview, 1, &crypto);
        return ossl_quic_wire_decode_frame_crypto(pkt, 0, &crypto);
    case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
        return ossl_quic_wire_decode_frame_new_token(pkt, &token, &token_len);
    case OSSL_QUIC_FRAME_TYPE_STREAM:
    case OSSL_QUIC_FRAME_TYPE_STREAM_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_LEN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_LEN_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_FIN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN:
    case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN:
        ossl_quic_wire_decode_frame_stream(&preview, 1, &stream);
        return ossl_quic_wire_decode_frame_stream(pkt, 0, &stream);
    case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
        return ossl_quic_wire_decode_frame_max_data(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
        return ossl_quic_wire_decode_frame_max_stream_data(pkt, &tmp64,
                                                           &tmp64_2);
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
        return ossl_quic_wire_decode_frame_max_streams(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED:
        return ossl_quic_wire_decode_frame_data_blocked(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED:
        return ossl_quic_wire_decode_frame_stream_data_blocked(pkt, &tmp64,
                                                               &tmp64_2);
    case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
    case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI:
        return ossl_quic_wire_decode_frame_streams_blocked(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
        return ossl_quic_wire_decode_frame_new_conn_id(pkt, &new_conn_id);
    case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
        return ossl_quic_wire_decode_frame_retire_conn_id(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE:
        return ossl_quic_wire_decode_frame_path_challenge(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE:
        return ossl_quic_wire_decode_frame_path_response(pkt, &tmp64);
    case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT:
    case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP:
        return ossl_quic_wire_decode_frame_conn_close(pkt, &conn_close);
    case OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE:
        return ossl_quic_wire_decode_frame_handshake_done(pkt);
    default:
        return ossl_quic_wire_skip_frame_header(pkt, &frame_type);
    }
}

static void fuzz_decode_frame_sequence(const uint8_t *buf, size_t len,
                                       uint32_t ack_delay_exp)
{
    PACKET pkt;
    size_t i;

    if (!PACKET_buf_init(&pkt, buf, len))
        return;

    for (i = 0; i < MAX_FUZZ_QUIC_FRAMES && PACKET_remaining(&pkt) > 0; ++i) {
        size_t before = PACKET_remaining(&pkt);

        if (!fuzz_decode_one_frame(&pkt, ack_delay_exp)
            || PACKET_remaining(&pkt) >= before)
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
    if (len == 0 || len > MAX_FUZZ_QUIC_FRAME_INPUT_LEN)
        return 0;

    fuzz_decode_frame_sequence(buf, len, buf[len - 1] & 0x1f);
    if (len > 1)
        fuzz_decode_frame_sequence(buf + 1, len - 1, buf[0] & 0x1f);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

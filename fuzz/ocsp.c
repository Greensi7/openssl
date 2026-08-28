/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Fuzz the public OCSP request and response parsing entry points. */

#include <limits.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include "fuzzer.h"

#define MAX_INPUT_SIZE (256 * 1024)
#define MAX_RESPONSES 32

static void encode_response(OCSP_RESPONSE *response)
{
    unsigned char *der = NULL;

    if (response != NULL)
        i2d_OCSP_RESPONSE(response, &der);
    OPENSSL_free(der);
}

static void exercise_request(const unsigned char *buf, size_t len,
    unsigned int mode)
{
    const unsigned char *p = buf;
    OCSP_REQUEST *request = NULL;
    OCSP_BASICRESP *basic = NULL;
    OCSP_RESPONSE *response = NULL;
    ASN1_TIME *thisupd = NULL, *nextupd = NULL, *revtime = NULL;
    BIO *bio = NULL;
    unsigned char *der = NULL;
    int cert_status, count, i;

    request = d2i_OCSP_REQUEST(NULL, &p, (long)len);
    if (request == NULL)
        goto end;

    bio = BIO_new(BIO_s_null());
    if (bio != NULL)
        OCSP_REQUEST_print(bio, request, 0);

    i2d_OCSP_REQUEST(request, &der);
    (void)OCSP_REQUEST_get_ext_count(request);

    if (OCSP_request_is_signed(request))
        OCSP_request_verify(request, NULL, NULL, OCSP_NOVERIFY);

    switch ((mode >> 1) & 3) {
    case 0:
        cert_status = V_OCSP_CERTSTATUS_GOOD;
        break;
    case 1:
        cert_status = V_OCSP_CERTSTATUS_REVOKED;
        break;
    default:
        cert_status = V_OCSP_CERTSTATUS_UNKNOWN;
        break;
    }

    basic = OCSP_BASICRESP_new();
    thisupd = ASN1_TIME_set(NULL, 0);
    if ((mode & 8) != 0)
        nextupd = ASN1_TIME_set(NULL, 60);
    if (cert_status == V_OCSP_CERTSTATUS_REVOKED)
        revtime = ASN1_TIME_set(NULL, 0);

    count = OCSP_request_onereq_count(request);
    if (count > MAX_RESPONSES)
        count = MAX_RESPONSES;
    for (i = 0; i < count; i++) {
        OCSP_ONEREQ *one = OCSP_request_onereq_get0(request, i);
        OCSP_CERTID *id;

        if (one == NULL)
            continue;
        (void)OCSP_ONEREQ_get_ext_count(one);
        id = OCSP_onereq_get0_id(one);
        if (id == NULL)
            continue;
        OCSP_id_get0_info(NULL, NULL, NULL, NULL, id);
        if (basic != NULL && thisupd != NULL
            && (cert_status != V_OCSP_CERTSTATUS_REVOKED
                || revtime != NULL))
            OCSP_basic_add1_status(basic, id, cert_status,
                OCSP_REVOKED_STATUS_NOSTATUS, revtime, thisupd, nextupd);
    }

    if (basic != NULL) {
        (void)OCSP_BASICRESP_get_ext_count(basic);
        response = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
        encode_response(response);
    }

end:
    OPENSSL_free(der);
    BIO_free(bio);
    ASN1_TIME_free(revtime);
    ASN1_TIME_free(nextupd);
    ASN1_TIME_free(thisupd);
    OCSP_RESPONSE_free(response);
    OCSP_BASICRESP_free(basic);
    OCSP_REQUEST_free(request);
}

static void exercise_response(const unsigned char *buf, size_t len)
{
    const unsigned char *p = buf;
    OCSP_RESPONSE *response = NULL, *copy = NULL;
    OCSP_BASICRESP *basic = NULL;
    ASN1_OCTET_STRING *responder_key = NULL;
    X509_NAME *responder_name = NULL;
    BIO *bio = NULL;
    unsigned char *der = NULL;
    int response_status, count, i;

    response = d2i_OCSP_RESPONSE(NULL, &p, (long)len);
    if (response == NULL)
        goto end;

    bio = BIO_new(BIO_s_null());
    if (bio != NULL)
        OCSP_RESPONSE_print(bio, response, 0);

    i2d_OCSP_RESPONSE(response, &der);
    response_status = OCSP_response_status(response);
    basic = OCSP_response_get1_basic(response);
    if (basic == NULL)
        goto end;

    (void)OCSP_BASICRESP_get_ext_count(basic);
    (void)OCSP_resp_get0_signature(basic);
    (void)OCSP_resp_get0_tbs_sigalg(basic);
    (void)OCSP_resp_get0_respdata(basic);
    (void)OCSP_resp_get0_produced_at(basic);
    (void)OCSP_resp_get0_certs(basic);
    (void)OCSP_resp_get1_id(basic, &responder_key, &responder_name);

    count = OCSP_resp_count(basic);
    if (count > MAX_RESPONSES)
        count = MAX_RESPONSES;
    for (i = 0; i < count; i++) {
        OCSP_SINGLERESP *single = OCSP_resp_get0(basic, i);
        ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
        const OCSP_CERTID *id;
        int reason;

        if (single == NULL)
            continue;
        (void)OCSP_SINGLERESP_get_ext_count(single);
        (void)OCSP_single_get0_status(single, &reason, &revtime, &thisupd,
            &nextupd);
        if (thisupd != NULL)
            OCSP_check_validity(thisupd, nextupd, 300, -1);
        id = OCSP_SINGLERESP_get0_id(single);
        if (id != NULL)
            OCSP_resp_find(basic, (OCSP_CERTID *)id, -1);
    }

    OCSP_basic_verify(basic, NULL, NULL, OCSP_NOVERIFY);
    copy = OCSP_response_create(response_status, basic);
    encode_response(copy);

end:
    OPENSSL_free(der);
    BIO_free(bio);
    ASN1_OCTET_STRING_free(responder_key);
    X509_NAME_free(responder_name);
    OCSP_RESPONSE_free(copy);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(response);
}

int FuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
            | OPENSSL_INIT_ADD_ALL_DIGESTS,
        NULL);
    ERR_clear_error();
    CRYPTO_free_ex_index(0, -1);
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    unsigned int mode;

    if (len < 2 || len > MAX_INPUT_SIZE || len - 1 > LONG_MAX)
        return 0;

    mode = *buf++;
    len--;
    if ((mode & 1) == 0)
        exercise_request(buf, len, mode);
    else
        exercise_response(buf, len);

    ERR_clear_error();
    return 0;
}

void FuzzerCleanup(void)
{
}

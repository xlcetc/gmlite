/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <gmlite/ec.h>
#include <gmlite/sm2.h>
#include "sm2_lcl.h"
#include "../ec/ec_lcl.h"

const EC_GROUP *sm2_group = NULL;

const EC_GROUP* SM2_get_group()
{
    if (sm2_group == NULL)
        return NULL;

    return sm2_group;
}

int sm2_group_init()
{
    sm2_group = EC_GROUP_new_sm2();
    return GML_OK;
}

int SM2_CTX_init(SM2_CTX *sm2_ctx, uint8_t pubkey_x[32], uint8_t pubkey_y[32])
{
    int ret = GML_ERROR;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *point = NULL;
    if (sm2_ctx == NULL)
        return GML_ERROR;

    CRYPTO_crit_enter();

    sm2_ctx->pk_precomp = NULL;
    sm2_ctx->group = (EC_GROUP*)SM2_get_group();
    if (sm2_ctx->group == NULL) {
        CRYPTO_crit_leave();
        return GML_ERROR;
    }

    /* no precompute */
    if (pubkey_x == NULL || pubkey_y == NULL) {
        CRYPTO_crit_leave();
        return GML_OK;
    }

    bn_ctx = BN_CTX_new();
    x = BN_new();
    y = BN_new();
    point = EC_POINT_new(sm2_ctx->group);
    if (x == NULL || y == NULL || bn_ctx == NULL || point == NULL)
        goto end;

    BN_bin2bn(pubkey_x, 32, x);
    BN_bin2bn(pubkey_y, 32, y);
    if (EC_POINT_set_affine_coordinates_GFp(sm2_ctx->group, point, x, y, bn_ctx) == GML_ERROR) {
        goto end;
    }

    /* compute precompute table for point */
    if (EC_GROUP_point_precompute_mult(sm2_ctx->group, &sm2_ctx->pk_precomp, point, bn_ctx) == GML_ERROR) {
        goto end;
    }

    CRYPTO_memzero(sm2_ctx->sk_precomp, 64);

    ret = GML_OK;
end:
    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    CRYPTO_crit_leave();
    return ret;
}

void SM2_CTX_clear(SM2_CTX *sm2_ctx)
{
    if (sm2_ctx == NULL)
        return;

    CRYPTO_crit_enter();

    if (sm2_ctx->pk_precomp != NULL) {
        EC_sm2z256_pre_comp_free(sm2_ctx->pk_precomp);
        sm2_ctx->pk_precomp = NULL;
    }
    CRYPTO_memzero(sm2_ctx->sk_precomp, 64);

    CRYPTO_crit_leave();
}

void SM2_CTX_clear_free(SM2_CTX *sm2_ctx)
{
    SM2_CTX_clear(sm2_ctx);
    CRYPTO_free(sm2_ctx);
}

/* asn1 encode big integer, at most 35 bytes */
int sm2_bn_asn1_encode(uint8_t asn1[35], int *make, uint8_t bn[32])
{
    int ret = GML_ERROR;
    int zeros = 0;
    int len;

    if (asn1 == NULL || make == NULL || bn == NULL)
        goto end;

    while (*bn == 0) {
        zeros++;
        bn++;
    }

    len = 0x20 - zeros + (int)(bn[0] >= 0x80U); // bn is considered as negative if bn[0] >= 0x80
    if (len < 0)
        goto end;

    asn1[0] = 0x02U;
    asn1[1] = (uint8_t)len;
    asn1 += 2;
    if (bn[0] >= 0x80U) {
        *asn1 = 0x00U;
        asn1++;
        memcpy(asn1, bn, len - 1); // asn1 = 02 ?? bn
    }
    else {
        memcpy(asn1, bn, len); // asn1 = 02 ?? bn
    }
    *make = (len + 2);

    ret = GML_OK;
end:
    return ret;
}

/* asn1 decode big integer */
int sm2_bn_asn1_decode(uint8_t bn[32], int *take, uint8_t asn1[35])
{
    int ret = GML_ERROR;
    int asn1_len;
    int zeros;

    if (bn == NULL || take == NULL || asn1 == NULL)
        goto end;

    if (*asn1 != 0x02U) // asn1 = 02 ?? r
        goto end;
    asn1++;

    asn1_len = (int)(*asn1); // asn1 = ?? r
    if (asn1_len < 1 || asn1_len > 0x21)
        goto end;
    asn1++;

    if (asn1_len == 0x21U) {
        asn1++;
        memcpy(bn, asn1, 0x20);
    }
    else {
        zeros = 0x20U - asn1_len;
        memset(bn, 0, zeros);
        bn += zeros;
        memcpy(bn, asn1, asn1_len);
    }
    *take = (asn1_len + 2);

    ret = GML_OK;
end:
    return ret;
}

// /* asn1 encode byte array */
// int sm2_bytearray_asn1_encode(uint8_t **asn1, int *make, uint8_t *b, int blen)
// {
//     int ret = GML_ERROR;
//     uint8_t *enc = NULL;
//     uint32_t be_blen;
//     int asn1len;
//     int k;

//     if (asn1 == NULL || b == NULL || blen < 0)
//         goto end;

//     k = 0;
//     be_blen = to_be32(blen);
//     while (blen) {
//         blen //TODO
//     }

//     /* asn1 = 0x04 || blen || b */
//     if (blen > 127) {
//         *asn1 = 0x04U;
//         asn1++;
//         *asn1 = 0x80U;
//         if (be_blen & 0xff000000U) {
//             *asn1 |= 0x04U;
//             asn1++;
//             memcpy(asn1, (const uint8_t*)(&be_blen), 4);
//             asn1 += 4;
//         }
//         else if (be_blen & 0x00ff0000U) {
//             *asn1 |= 0x03U;
//             asn1++;
//             memcpy(asn1, 1+(const uint8_t*)(&be_blen), 3);
//             asn1 += 3;
//         }
//         else if (be_blen & 0x0000ff00U) {
//             *asn1 |= 0x02U;
//             asn1++;
//             memcpy(asn1, 2+(const uint8_t*)(&be_blen), 2);
//             asn1 += 2;
//         }
//         else if (be_blen & 0x000000ffU) {
//             *asn1 |= 0x01U;
//             asn1++;
//             memcpy(asn1, 3+(const uint8_t*)(&be_blen), 1);
//             asn1 += 1;
//         }
//         else {
//             asn1++;
//         }
//         memcpy(asn1, b, blen);
//     }
//     else {
//         asn1[0] = 0x04U;
//         asn1[1] = (uint8_t)blen;
//         memcpy(asn1 + 2, b, blen);
//     }

//     ret = GML_OK;
// end:
//     return ret;
// }

int sm2_sig_asn1_encode(uint8_t sig[128], int *siglen, uint8_t r[32], uint8_t s[32])
{
    int ret = GML_ERROR;
    int r_asn1_len, s_asn1_len;
    uint8_t *tmp;

    if (sig == NULL || siglen == NULL || r == NULL || s == NULL)
        goto end;

    tmp = sig;
    *sig = 0x30; // sig = 0x30...
    sig += 2;

    /* encode r */
    if (sm2_bn_asn1_encode(sig, &r_asn1_len, r) == GML_ERROR)
        goto end;
    sig += r_asn1_len;

    /* encode s */
    if (sm2_bn_asn1_encode(sig, &s_asn1_len, s) == GML_ERROR)
        goto end;

    *(tmp + 1) = (uint8_t)(r_asn1_len + s_asn1_len);
    *siglen = r_asn1_len + s_asn1_len + 2;
    ret = GML_OK;
end:
    return ret;
}

int sm2_sig_asn1_decode(uint8_t r[32], uint8_t s[32], uint8_t sig[128], int siglen)
{
    int ret = GML_ERROR;
    int r_asn1_len, s_asn1_len;
    int total_len;

    if (sig == NULL || r == NULL || s == NULL)
        goto end;

    if (*sig != 0x30U) // sig = 0x30 ?? 02 ?? r 02 ?? s
        goto end;
    sig++;

    total_len = (int)(*sig); // sig = ?? 02 ?? r 02 ?? s
    if (total_len > 0x46 || siglen != (total_len + 2))
        goto end;
    sig++;

    if (sm2_bn_asn1_decode(r, &r_asn1_len, sig) == GML_ERROR)
        goto end;
    sig += r_asn1_len;

    if (sm2_bn_asn1_decode(s, &s_asn1_len, sig) == GML_ERROR)
        goto end;

    ret = GML_OK;
end:
    return ret;
}
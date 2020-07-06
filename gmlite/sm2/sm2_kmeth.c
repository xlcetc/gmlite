/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <gmlite/crypto.h>
#include <gmlite/ec.h>
#include <gmlite/sm2.h>
#include "sm2_lcl.h"

/* generate key pair */
int SM2_keygen(uint8_t privkey[32], uint8_t pubkey_x[32], uint8_t pubkey_y[32])
{
    int ret = GML_ERROR;
    BIGNUM *k = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *order = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    group = SM2_get_group();
    if (group == NULL)
        goto end;

    if (privkey == NULL || pubkey_x == NULL || pubkey_y == NULL)
        goto end;

    k = BN_new();
    x = BN_new();
    y = BN_new();
    order = BN_new();
    ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    if (k == NULL || x == NULL || y == NULL || ctx == NULL || point == NULL)
        goto end;

    if (!EC_GROUP_get_order(group, order, ctx))
        goto end;

    BN_sub_word(order, 1);

    /* generate private key */
    do {
        if (!BN_rand_range(k, order)) 
            goto end;
    } while (BN_is_zero(k));

    /* compute public key : point = k * G */
    if (!EC_POINT_mul(group, point, k, NULL, NULL, ctx))
        goto end;

    if (EC_POINT_is_on_curve(group, point, ctx) <= 0)
        goto end;

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx))
        goto end;

    BN_bn2binpad(k, privkey, 32);
    BN_bn2binpad(x, pubkey_x, 32);
    BN_bn2binpad(y, pubkey_y, 32);

    ret = GML_OK;
end:
    BN_free(k);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ret;
}

/* compute public key from private key */
int SM2_compute_pubkey(uint8_t privkey[32], uint8_t pubkey_x[32], uint8_t pubkey_y[32])
{
    int ret = GML_ERROR;
    BIGNUM *k = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    group = SM2_get_group();
    if (privkey == NULL || pubkey_x == NULL || pubkey_y == NULL || group == NULL )
        goto end;

    k = BN_new();
    x = BN_new();
    y = BN_new();
    ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    if (k == NULL || x == NULL || y == NULL || ctx == NULL || point == NULL )
        goto end;

    /* private key */
    BN_bin2bn(privkey, 32, k);

    /* compute public key : point = k * G */
    if (EC_POINT_mul(group, point, k, NULL, NULL, ctx) == GML_ERROR)
        goto end;

    if (EC_POINT_is_on_curve(group, point, ctx) <= 0)
        goto end;

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx) == GML_ERROR)
        goto end;

    BN_bn2binpad(x, pubkey_x, 32);
    BN_bn2binpad(y, pubkey_y, 32);
    ret = GML_OK;
end:
    BN_free(k);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ret;
}

int SM2_keygen_bn(BIGNUM *privkey_bn, BIGNUM *pubkey_x_bn, BIGNUM *pubkey_y_bn)
{
    int ret = GML_ERROR;
    uint8_t privkey[32], pubkey_x[32], pubkey_y[32];

    if (privkey_bn == NULL || pubkey_x_bn == NULL || pubkey_y_bn == NULL)
        goto end;

    /* generate key pair */
    if (SM2_keygen(privkey, pubkey_x, pubkey_y) == GML_ERROR)
        goto end;

    /* convert to BIGNUM */
    BN_bin2bn(privkey, 32, privkey_bn);
    BN_bin2bn(pubkey_x, 32, pubkey_x_bn);
    BN_bin2bn(pubkey_y, 32, pubkey_y_bn);

    ret = GML_OK;
end:
    return ret;
}

/* compute public key from private key (BIGNUM) */
int SM2_compute_pubkey_bn(BIGNUM *privkey_bn, BIGNUM *pubkey_x_bn, BIGNUM *pubkey_y_bn)
{
    int ret = GML_ERROR;
    BN_CTX *ctx = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    group = SM2_get_group();
    if (group == NULL || privkey_bn == NULL || pubkey_x_bn == NULL || pubkey_y_bn == NULL)
        goto end;

    ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    if (point == NULL || ctx == NULL)
        goto end;

    /* compute public key : point = k * G */
    if (EC_POINT_mul(group, point, privkey_bn, NULL, NULL, ctx) == GML_ERROR) 
        goto end;

    if (EC_POINT_get_affine_coordinates_GFp(group, point, pubkey_x_bn, pubkey_y_bn, ctx) == GML_ERROR) 
        goto end;

    ret = GML_OK;
end:
    BN_CTX_free(ctx);
    EC_POINT_free(point);
    return ret;
}

int SM2_pubkey_precompute(SM2_CTX *ctx, uint8_t pubkey_x[32], uint8_t pubkey_y[32])
{
    int ret = GML_ERROR;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;

    x = BN_new();
    y = BN_new();
    if (ctx == NULL || ctx->group == NULL || x == NULL || y == NULL)
        goto end;
    group = ctx->group;
    bn_ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    if (point == NULL || ctx == NULL)
        goto end;

    BN_bin2bn(pubkey_x, 32, x);
    BN_bin2bn(pubkey_y, 32, y);
    if (EC_POINT_set_affine_coordinates_GFp(group, point, x, y, bn_ctx) == GML_ERROR)
        goto end;

    /* precompute table for point */
    if (EC_GROUP_point_precompute_mult(group, ctx->pk_precomp, point, bn_ctx) == GML_ERROR)
        goto end;

    ret = GML_OK;
end:
    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    return ret;
}
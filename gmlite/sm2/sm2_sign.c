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
#include <gmlite/bn.h>
#include <gmlite/ec.h>
#include <gmlite/sm2.h>
#include "sm2_lcl.h"

/* constant id */
// static const uint8_t entl_str[2] = {0x0, 0x80};
// static const uint8_t sm2_user_id[17] = "1234567812345678";
/* constant curve parameters */
static const uint8_t a_b_gx_gy[128] = 
{
    /* a */
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    /* b */
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B,
    0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    /* gx */
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46,
    0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
    /* gy */
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3,
    0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

int SM2_sign(uint8_t *sig, int *siglen, const uint8_t e[32], const uint8_t rand[32], const uint8_t privkey[32], SM2_SIG_MODE mode, SM2_CTX *sm2_ctx)
{
    int ret = GML_ERROR;
    uint8_t r[32], s[32];
    BIGNUM *x = NULL;
    BIGNUM *d = NULL;
    BIGNUM *k = NULL;
    BIGNUM *e_bn = NULL;
    BIGNUM *r_bn = NULL;
    BIGNUM *s_bn = NULL;
    const BIGNUM *order = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    uint8_t *sk_precomp = NULL;

    if (sm2_ctx == NULL)
        goto end;

    group = sm2_ctx->group;
    if (group == NULL)
        goto end;

    if (e == NULL || sig == NULL || siglen == NULL || privkey == NULL)
        goto end;

    x = BN_new();
    d = BN_new();
    k = BN_new();
    e_bn = BN_new();
    r_bn = BN_new();
    s_bn = BN_new();
    order = EC_GROUP_get0_order(group);
    bn_ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    if (x == NULL || d == NULL || k == NULL || e_bn == NULL || r_bn == NULL || s_bn == NULL || 
        order == NULL || bn_ctx == NULL || point == NULL)
        goto end;

    BN_bin2bn(e, 32, e_bn);
    do {
        /* random k */
        if (rand == NULL) {
            do {
                if (!BN_rand_range(k, order)) 
                    goto end;
            } while (BN_is_zero(k));
        }
        else
            BN_bin2bn(rand, 32, k);
        
        /* k * G */
        if (!EC_POINT_mul(group, point, k, NULL, NULL, bn_ctx)) 
            goto end;

        if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, NULL, bn_ctx)) 
            goto end;

        /* r = e + x */
        BN_mod_add(r_bn, e_bn, x, order, bn_ctx);

        /* r + k */
        BN_add(x, r_bn, k);

        if (BN_is_zero(r_bn) || BN_cmp(x, order) == 0)
            continue;

        /* TODO : what if BN_mod_inverse_Lehmer returns error */
        sk_precomp = sm2_ctx->sk_precomp;
        CRYPTO_crit_enter();
        if (CRYPTO_memcmp(sk_precomp, privkey, 32) != 0) {
            BN_bin2bn(privkey, 32, d);
            /* (1 + d)^-1 */
            BN_add_word(d, 1);
            if (!BN_mod_inverse_Lehmer(d, d, order, bn_ctx)) {
                CRYPTO_crit_leave();
                goto end;
            }
            memcpy(sk_precomp, privkey, 32);
            BN_bn2binpad(d, sk_precomp + 32, 32);
        }
        else {
            BN_bin2bn(sk_precomp + 32, 32, d);
        }
        CRYPTO_crit_leave();

        // BN_bin2bn(privkey, 32, d);
        // BN_add_word(d, 1);
        // if (!BN_mod_inverse_Lehmer(d, d, order, bn_ctx))
        //     goto end;

        /* s = d'(k + r) - r mod n */
        BN_mod_mul(s_bn, d, x, order, bn_ctx);
        BN_mod_sub(s_bn, s_bn, r_bn, order, bn_ctx);
    } while (BN_is_zero(s_bn));

    BN_bn2binpad(r_bn, r, 32);
    BN_bn2binpad(s_bn, s, 32);
    if (mode == SM2_SIG_RS_ORIG) {
        memcpy(sig, r, 32);
        memcpy(sig + 32, s, 32);
        *siglen = 64;
    }
    else if (mode == SM2_SIG_RS_ASN1) {
        if (sm2_sig_asn1_encode(sig, siglen, r, s) == GML_ERROR) {
            goto end;
        }
    }
    else
        goto end;

    ret = GML_OK;
end:
    BN_free(x);
    BN_free(d);
    BN_free(k);
    BN_free(e_bn);
    BN_free(r_bn);
    BN_free(s_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    return ret;
}

int SM2_verify(uint8_t *sig, int siglen, const uint8_t e[32], const uint8_t pubkey_x[32], const uint8_t pubkey_y[32], SM2_SIG_MODE mode, SM2_CTX *sm2_ctx)
{
    int ret = GML_ERROR;
    uint8_t r[32], s[32];
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *t = NULL;
    BIGNUM *e_bn = NULL;
    BIGNUM *r_bn = NULL;
    BIGNUM *s_bn = NULL;
    const BIGNUM *order = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *point = NULL;
    EC_POINT *tP = NULL;
    const EC_GROUP *group = NULL;

    if (sm2_ctx == NULL)
        goto end;

    group = sm2_ctx->group;
    if (group == NULL)
        goto end;

    if (sig == NULL || siglen <= 0 || e == NULL || pubkey_x == NULL || pubkey_y == NULL)
        goto end;

    x = BN_new();
    y = BN_new();
    t = BN_new();
    e_bn = BN_new();
    r_bn = BN_new();
    s_bn = BN_new();
    order = EC_GROUP_get0_order(group);
    bn_ctx = BN_CTX_new();
    point = EC_POINT_new(group);
    tP = EC_POINT_new(group);
    if (x == NULL || y == NULL || t == NULL || e_bn == NULL || r_bn == NULL ||
        s_bn == NULL || order == NULL || bn_ctx == NULL || point == NULL || tP == NULL)
        goto end;

    BN_bin2bn(pubkey_x, 32, x);
    BN_bin2bn(pubkey_y, 32, y);
    /* public key */
    if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, bn_ctx))
        goto end;

    if (mode == SM2_SIG_RS_ORIG && siglen == 64) {
        memcpy(r, sig, 32);
        memcpy(s, sig + 32, 32);
    }
    else if (mode == SM2_SIG_RS_ASN1) {
        if (sm2_sig_asn1_decode(r, s, sig, siglen) == GML_ERROR) {
            goto end;
        }
    }
    else
        goto end;

    BN_bin2bn(r, 32, r_bn);
    BN_bin2bn(s, 32, s_bn);
    /* t = r + s */
    BN_mod_add(t, r_bn, s_bn, order, bn_ctx);

    if (BN_is_zero(t))
        goto end;

    /* tP */
    if (EC_POINT_mul_with_precomp(group, tP, t, sm2_ctx->pk_precomp, bn_ctx) == GML_ERROR) {
        if (EC_POINT_mul(group, tP, NULL, point, t, bn_ctx) == GML_ERROR)
            goto end;
    }

    /* sG */
    if (!EC_POINT_mul(group, point, s_bn, NULL, NULL, bn_ctx))
        goto end;

    /* sG + tP */
    if (EC_POINT_add(group, point, point, tP, bn_ctx) == GML_ERROR)
        goto end;

    /* (x, y) = sG + tP */
    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, NULL, bn_ctx))
        goto end;

    BN_bin2bn(e, 32, e_bn);
    /* e + x */
    BN_mod_add(y, e_bn, x, order, bn_ctx);

    /* R = r ? */
    if (BN_cmp(y, r_bn) != 0) {
        goto end;
    }

    ret = GML_OK;
end:
    BN_free(x);
    BN_free(y);
    BN_free(t);
    BN_free(e_bn);
    BN_free(r_bn);
    BN_free(s_bn);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(point);
    EC_POINT_free(tP);
    return ret;
}

int SM2_sign_ex(uint8_t *sig, int *siglen,  
                const uint8_t *msg, int msglen, 
                const uint8_t *id, int idlen,
                const uint8_t rand[32], 
                const uint8_t pubkey_x[32], const uint8_t pubkey_y[32], const uint8_t privkey[32],
                SM2_SIG_MODE mode, SM2_CTX *sm2_ctx)
{
    int ret = GML_ERROR;
    uint8_t ZA[32];
    uint8_t e[32];
    uint8_t entl_str[2];
    SM3_CTX sm3_ctx;

    if (msg == NULL || msglen < 0 || id == NULL || idlen < 0 || idlen >= 65536 || sig == NULL || siglen == NULL || 
        pubkey_x == NULL || pubkey_y == NULL || privkey == NULL || sm2_ctx == NULL)
        goto end;

    entl_str[0] = (uint8_t)((idlen << 3) >> 8);
    entl_str[1] = (uint8_t)((idlen << 3) & 0xff);
    /* ZA = SM3 (ENTLA || IDA || a || b || Gx || Gy || Ax || Ay) */
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, entl_str, 2);
    SM3_update(&sm3_ctx, id, idlen);
    SM3_update(&sm3_ctx, a_b_gx_gy, 128);
    SM3_update(&sm3_ctx, pubkey_x, 32);
    SM3_update(&sm3_ctx, pubkey_y, 32);
    SM3_final(&sm3_ctx, ZA);

    /* e = SM3(ZA || m) */
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, ZA, 32);
    SM3_update(&sm3_ctx, msg, msglen);
    SM3_final(&sm3_ctx, e);

    if (SM2_sign(sig, siglen, e, rand, privkey, mode, sm2_ctx) == GML_ERROR)
        goto end;

    ret = GML_OK;
end:
    return ret;
}

int SM2_verify_ex(uint8_t *sig, int siglen, 
                  const uint8_t *msg, int msglen, 
                  const uint8_t *id, int idlen,
                  const uint8_t pubkey_x[32], const uint8_t pubkey_y[32],
                  SM2_SIG_MODE mode, SM2_CTX *sm2_ctx)
{
    int ret = GML_ERROR;
    uint8_t ZA[32];
    uint8_t e[32];
    uint8_t entl_str[2];
    SM3_CTX sm3_ctx;

    if (msg == NULL || msglen < 0 || id == NULL || idlen < 0 || idlen >= 65536 ||
        sig == NULL || siglen <= 0 || pubkey_x == NULL || pubkey_y == NULL || sm2_ctx == NULL) {
        goto end;
    }

    entl_str[0] = (uint8_t)((idlen << 3) >> 8);
    entl_str[1] = (uint8_t)((idlen << 3) & 0xff);
    /* ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Ax || Ay ) */
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, entl_str, 2);
    SM3_update(&sm3_ctx, id, idlen);
    SM3_update(&sm3_ctx, a_b_gx_gy, 128);
    SM3_update(&sm3_ctx, pubkey_x, 32);
    SM3_update(&sm3_ctx, pubkey_y, 32);
    SM3_final(&sm3_ctx, ZA);

    /* e = SM3(ZA || m) */
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, ZA, 32);
    SM3_update(&sm3_ctx, msg, msglen);
    SM3_final(&sm3_ctx, e);

    if (SM2_verify(sig, siglen, e, pubkey_x, pubkey_y, mode, sm2_ctx) == GML_ERROR)
        goto end;

    ret = GML_OK;
end:
    return ret;
}

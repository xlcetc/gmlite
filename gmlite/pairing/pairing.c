/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <gmlite/ec.h>
#include <gmlite/pairing.h>
#include "../ec/ec_lcl.h"
#include "pairing_lcl.h"

unsigned int _booth_recode_w5(unsigned int in)
{
    unsigned int s, d;

    s = ~((in >> 5) - 1);
    d = (1 << 6) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);

    return (d << 1) + (s & 1);
}

int compute_6tplus2_naf(int **naf, int *naf_len, fp_t t)
{
    int bits, i, j;
    int *tmp = NULL;
    int *ret = NULL;
    BIGNUM *z = NULL;

    z = BN_new();
    if (z == NULL)
        goto end;

    BN_set_words(z, t->d, N_LIMBS);
    BN_mul_word(z, 6);
    BN_add_word(z, 2);
    bits = BN_num_bits(z);
    if (bits <= 0)
        goto end;

    tmp = (int*)CRYPTO_zalloc((bits + 1) * sizeof(int));
    ret = (int*)CRYPTO_zalloc((bits + 1) * sizeof(int));
    if (tmp == NULL || ret == NULL)
        goto end;

    for (i = 0; i < bits; i++)
        tmp[i] = BN_is_bit_set(z, bits - i);

    i = bits;
    while (i > 0) {
        j = i;
        while (j > 0 && tmp[j] == 1)
            j--;

        if (j == 0) {
            if ((i - j) >= 3) {
                tmp[i] = -1;
                i--;
                while (i > j) {
                    tmp[i] = 0;
                    i--;
                }
                tmp[i] = 1;
            }
        }

        /* ***11*** --> **10-1*** */
        if ((i - j) >= 2) {
            tmp[i] = -1;
            i--;
            while (i > j) {
                tmp[i] = 0;
                i--;
            }
            tmp[i] = 1;
        }
        else
            i--;
    }

    if (tmp[0] == 1) {
        memcpy(ret, tmp, (bits + 1) * sizeof(int));
        *naf = ret;
        *naf_len = (bits + 1);
    }
    else {
        memcpy(ret, tmp + 1, bits * sizeof(int));
        *naf = ret;
        *naf_len = bits;
    }

    CRYPTO_free(tmp);
    BN_free(z);
    return GML_OK;
end:
    *naf = NULL;
    *naf_len = 0;
    CRYPTO_free(tmp);
    CRYPTO_free(ret);
    BN_free(z);
    return GML_ERROR;
}

const EC_GROUP* PAIRING_get_ec_group(const ATE_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->group;
}

int PAIRING_set_ec_group(ATE_CTX *ctx, const EC_GROUP *group)
{
    if (ctx == NULL || group == NULL)
        return GML_ERROR;

    ctx->group = group;
    return GML_OK;
}

/* get G1 generator */
const G1* PAIRING_get0_generator1(const ATE_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return &ctx->curve_gen;
}

int PAIRING_get_generator1(G1 *P, const ATE_CTX *ctx)
{
    if (ctx == NULL)
        return GML_ERROR;

    G1_copy(P, &ctx->curve_gen);
    return GML_OK;
}

/* get G2 generator */
const G2* PAIRING_get0_generator2(const ATE_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return &ctx->twist_gen;
}

int PAIRING_get_generator2(G2 *Q, const ATE_CTX *ctx)
{
    if (ctx == NULL)
        return GML_ERROR;

    G2_copy(Q, &ctx->twist_gen);
    return GML_OK;
}

const BIGNUM* PAIRING_get0_order(const ATE_CTX *ctx)
{
    if (ctx == NULL || ctx->order == NULL)
        return NULL;

    return ctx->order;
}

static int pairing_set_params(const char *T, const char *P, const char *N, const char *B, ATE_CTX *ctx)
{
    int ret = GML_ERROR;
    int bits;
    BIGNUM *p = NULL;
    BIGNUM *b = NULL;
    BIGNUM *rp = NULL;
    BIGNUM *exp = NULL;
    BN_CTX *bn_ctx = NULL;
    BN_MONT_CTX *mont_ctx = NULL;
    fp2_t xi, tmp;

    p = BN_new();
    b = BN_new();
    rp = BN_new();
    exp = BN_new();
    bn_ctx = BN_CTX_new();
    mont_ctx = BN_MONT_CTX_new();

    if (ctx == NULL || bn_ctx == NULL || mont_ctx == NULL || p == NULL || b == NULL ||
        exp == NULL || T == NULL || P == NULL || N == NULL)
        goto end;

    /* t */
    hex_to_u64((uint8_t*)T, 16, ctx->t->d);
    /* order */
    BN_hex2bn(&ctx->order, N);
    /* mont_ctx */
    BN_hex2bn(&p, P);
    BN_MONT_CTX_set(mont_ctx, p, bn_ctx);

    /* p */
    bn_copy_words(ctx->p->d, p, N_LIMBS);
    /* p_type */
    if (ctx->p->d[0] % 8 == 5)
        ctx->p_type = P_MOD_8_EQ_5;
    else if (ctx->p->d[0] % 4 == 3)
        ctx->p_type = P_MOD_4_EQ_3;
    else
        ctx->p_type = 0;

    /* rp */
    bits = (BN_num_bits(p) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;
    BN_zero(rp);
    if (!(BN_set_bit(rp, bits)))
        goto end;
    if (!BN_mod(rp, rp, p, bn_ctx))
        goto end;
    bn_copy_words(ctx->rp->d, rp, N_LIMBS);
    /* rrp = r^2 mod p */
    bn_copy_words(ctx->rrp->d, &mont_ctx->RR, 4);
    /* n0 */
    fp_setzero(ctx->n0);
    ctx->n0->d[0] = mont_ctx->n0[0];

    /* b */
    fp_set_hexstr(ctx->b, B, ctx);

    /* xi = -sqrt(-2) / 2 */
    fp2_setone(xi, ctx->rp);
    fp2_double(xi, xi, ctx->p);
    fp2_neg(xi, xi, ctx->p); // -2
    fp2_sqrt(xi, xi, ctx);   // sqrt(-2)
    fp2_neg(xi, xi, ctx->p); // -sqrt(-2)
    fp_div_by_2(xi->m_a, xi->m_a, ctx->p);
    fp_div_by_2(xi->m_b, xi->m_b, ctx->p);
    fp2_set(ctx->xi, xi);
    // fp2_print(xi, ctx);

    /* ypminus1 = xi^((p-1)/3) */
    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_div_word(exp, 3);
    fp2_pow(tmp, ctx->xi, exp, ctx);
    fp2_set(ctx->ypminus1, tmp);

    /* zpminus1 = xi^((p-1)/6) */
    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_div_word(exp, 6);
    fp2_pow(tmp, ctx->xi, exp, ctx);
    fp2_set(ctx->zpminus1, tmp);

    /* zpminus1inv = xi^((p-1)/6) */
    fp2_invert(tmp, tmp, ctx);
    fp2_set(ctx->zpminus1inv, tmp);

    /* xi^((p-1)/2) */
    BN_copy(exp, p);
    BN_sub_word(exp, 1);
    BN_div_word(exp, 2);
    fp2_pow(tmp, ctx->xi, exp, ctx);
    fp2_set(ctx->xipminus1over2, tmp);

    /* zeta = xi^((2p^2-2)/3) */
    BN_copy(exp, p);
    BN_mul(exp, exp, exp, bn_ctx);
    BN_mul_word(exp, 2);
    BN_sub_word(exp, 2);
    BN_div_word(exp, 3);
    fp2_pow(tmp, ctx->xi, exp, ctx);
    fp_set(ctx->zeta, tmp->m_b);

    ret = GML_OK;
end:
    BN_free(p);
    BN_free(b);
    BN_free(rp);
    BN_free(exp);
    BN_CTX_free(bn_ctx);
    BN_MONT_CTX_free(mont_ctx);
    return ret;
}

void PAIRING_free(ATE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    BN_free(ctx->order);
    CRYPTO_free(ctx->naf);
    CRYPTO_free(ctx);
}

ATE_CTX* PAIRING_init(const char *T, const char *P, const char *N, const char *B,
                const char *G1X, const char *G1Y,
                const char *G2XA, const char *G2XB, const char *G2YA, const char *G2YB)
{
    ATE_CTX* ate_ctx = NULL;

    ate_ctx = (ATE_CTX*)CRYPTO_zalloc(sizeof(ATE_CTX));

    if (ate_ctx == NULL || T == NULL || P == NULL || B == NULL || N == NULL ||
        G1X == NULL || G1Y == NULL || G2XA == NULL || G2XB == NULL || G2YA == NULL || G2YB == NULL)
        goto end;

    if (pairing_set_params(T, P, N, B, ate_ctx) == GML_ERROR)
        goto end;

    /* G1 generator */
    G1_init_set_str(&ate_ctx->curve_gen, G1X, G1Y, ate_ctx);
    /* G2 generator */
    G2_init_set_str(&ate_ctx->twist_gen, G2XA, G2XB, G2YA, G2YB, ate_ctx);

    /* NAF of 6t+2 */
    if (compute_6tplus2_naf(&ate_ctx->naf, &ate_ctx->naf_len, ate_ctx->t) == GML_ERROR)
        goto end;

    return ate_ctx;
end:
    PAIRING_free(ate_ctx);
    return NULL;
}

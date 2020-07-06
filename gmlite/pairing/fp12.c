/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <stdio.h>
#include <assert.h>
#include "pairing_lcl.h"

#define ALIGNPTR(p,N)   ((unsigned char *)p+N-(size_t)p%N)

/* assembly */
void GT_scatter_w4(GT *val, const GT *in_t, int idx);
void GT_gather_w4(GT *val, const GT *in_t, int idx);

static void setone_conditional(BN_ULONG dst[12*N_LIMBS], const BN_ULONG src[12*N_LIMBS], const fp_t rp)
{
    BN_ULONG zero = 0;
    BN_ULONG mask1;
    BN_ULONG mask2;

    for (int i = 0; i < 12*N_LIMBS; i++)
        zero |= src[i];
    zero = (zero == 0);
    mask2 = 0-zero;
    mask1 = ~mask2;

    dst[12*N_LIMBS - 4] = (src[12*N_LIMBS - 4] & mask1) ^ (rp->d[0] & mask2);
    dst[12*N_LIMBS - 3] = (src[12*N_LIMBS - 3] & mask1) ^ (rp->d[1] & mask2);
    dst[12*N_LIMBS - 2] = (src[12*N_LIMBS - 2] & mask1) ^ (rp->d[2] & mask2);
    dst[12*N_LIMBS - 1] = (src[12*N_LIMBS - 1] & mask1) ^ (rp->d[3] & mask2);

    // printf("%ld %ld %ld %ld %ld %ld %ld\n", move, src[12*N_LIMBS - 4], mask1, dst[12*N_LIMBS - 4], dst[12*N_LIMBS - 3], dst[12*N_LIMBS - 2], dst[12*N_LIMBS - 1]);
}

/* r = P^exp */
static int fp12_windowed_pow(GT *r, const BIGNUM *scalar, const GT *P, const ATE_CTX *ctx)
{
    size_t i;
    int j, ret = 0, num = 1;
    unsigned int idx;
    unsigned char p_str[33];
    const unsigned int window_size = 4;
    const unsigned int mask = (1 << window_size) - 1;
    unsigned int wvalue;
    GT *temp;           /* place for 5 temporary points */
    const BIGNUM *scalars = NULL;
    GT *table;
    // void *table_storage = NULL;
    unsigned char table_storage[(16 + 5) * sizeof(GT) + 64];
    BN_CTX *bn_ctx = BN_CTX_new();

    table = (void *)ALIGNPTR(table_storage, 64);
    temp = table + 16;

    for (i = 0; i < num; i++) {
        GT *row = table;

        /* This is an unusual input, we don't guarantee constant-timeness. */
        if ((BN_num_bits(scalar) > 256) || BN_is_negative(scalar)) {
            BIGNUM *mod;

            if ((mod = BN_CTX_get(bn_ctx)) == NULL)
                goto err;
            if (!BN_nnmod(mod, scalar, ctx->order, bn_ctx)) {
                goto err;
            }
            scalars = mod;
        } else
        scalars = scalar;

        for (j = 0; j < bn_get_top(scalars) * BN_BYTES; j += BN_BYTES) {
            BN_ULONG d = bn_get_words(scalars)[j / BN_BYTES];

            p_str[j + 0] = (unsigned char)d;
            p_str[j + 1] = (unsigned char)(d >> 8);
            p_str[j + 2] = (unsigned char)(d >> 16);
            p_str[j + 3] = (unsigned char)(d >>= 24);
            if (BN_BYTES == 8) {
                d >>= 8;
                p_str[j + 4] = (unsigned char)d;
                p_str[j + 5] = (unsigned char)(d >> 8);
                p_str[j + 6] = (unsigned char)(d >> 16);
                p_str[j + 7] = (unsigned char)(d >> 24);
            }
        }
        for (; j < 33; j++)
            p_str[j] = 0;

        fp12_set(&temp[0], P);

        /*
         * row[0] is implicitly 0, therefore it
         * is not stored. All other values are actually stored with an offset
         * of -1 in table.
         */
        GT_scatter_w4  (row, &temp[0], 1);
        fp12_square(&temp[1], &temp[0], ctx);              /*1+1=2  */
        GT_scatter_w4  (row, &temp[1], 2);
        fp12_mul   (&temp[2], &temp[1], &temp[0], ctx);    /*2+1=3  */
        GT_scatter_w4  (row, &temp[2], 3);
        fp12_square(&temp[1], &temp[1], ctx);              /*2*2=4  */
        GT_scatter_w4  (row, &temp[1], 4);
        fp12_square(&temp[2], &temp[2], ctx);              /*2*3=6  */
        GT_scatter_w4  (row, &temp[2], 6);
        fp12_mul   (&temp[3], &temp[1], &temp[0], ctx);    /*4+1=5  */
        GT_scatter_w4  (row, &temp[3], 5);
        fp12_mul   (&temp[4], &temp[2], &temp[0], ctx);    /*6+1=7  */
        GT_scatter_w4  (row, &temp[4], 7);
        fp12_square(&temp[1], &temp[1], ctx);              /*2*4=8  */
        GT_scatter_w4  (row, &temp[1], 8);
        fp12_square(&temp[2], &temp[2], ctx);              /*2*6=12 */
        GT_scatter_w4  (row, &temp[2], 12);
        fp12_square(&temp[3], &temp[3], ctx);              /*2*5=10 */
        GT_scatter_w4  (row, &temp[3], 10);
        fp12_square(&temp[4], &temp[4], ctx);              /*2*7=14 */
        GT_scatter_w4  (row, &temp[4], 14);
        fp12_mul   (&temp[2], &temp[2], &temp[0], ctx);    /*12+1=13*/
        GT_scatter_w4  (row, &temp[2], 13);
        fp12_mul   (&temp[3], &temp[3], &temp[0], ctx);    /*10+1=11*/
        GT_scatter_w4  (row, &temp[3], 11);
        fp12_mul   (&temp[4], &temp[4], &temp[0], ctx);    /*14+1=15*/
        GT_scatter_w4  (row, &temp[4], 15);
        fp12_mul   (&temp[2], &temp[1], &temp[0], ctx);    /*8+1=9  */
        GT_scatter_w4  (row, &temp[2], 9);
        fp12_square(&temp[1], &temp[1], ctx);              /*2*8=16 */
        GT_scatter_w4  (row, &temp[1], 16);
    }

    idx = 255;

    wvalue = p_str[(idx - 1) / 8];
    wvalue = (wvalue >> ((((idx - 1) % 8) / 4) * 4)) & mask;
    /*
     * We gather to temp[0], because we know it's position relative
     * to table
     */
    GT_gather_w4(&temp[0], table, wvalue);
    setone_conditional((BN_ULONG*)&temp[0], (BN_ULONG*)&temp[0], ctx->rp);
    memcpy(r, &temp[0], sizeof(temp[0]));

    while (idx >= 4) {
        for (i = (idx == 255 ? 1 : 0); i < 1; i++) {
            wvalue = p_str[(idx - 1) / 8];
            wvalue = (wvalue >> ((((idx - 1) % 8) / 4) * 4)) & mask;

            GT_gather_w4(&temp[0], table, wvalue);
            setone_conditional((BN_ULONG*)&temp[0], (BN_ULONG*)&temp[0], ctx->rp);
            fp12_mul(r, r, &temp[0], ctx);
        }

        idx -= window_size;
        fp12_square(r, r, ctx);
        fp12_square(r, r, ctx);
        fp12_square(r, r, ctx);
        fp12_square(r, r, ctx);
    }

    /* Final window */
    wvalue = p_str[0] & mask;
    GT_gather_w4(&temp[0], table, wvalue);
    setone_conditional((BN_ULONG*)&temp[0], (BN_ULONG*)&temp[0], ctx->rp);
    fp12_mul(r, r, &temp[0], ctx);

    ret = GML_OK;
err:
    BN_CTX_free(bn_ctx);
    return ret;
}

GT* GT_new()
{
    GT *ret = NULL;

    ret = (GT*)malloc(sizeof(GT));
    return ret;
}

void GT_free(GT *op)
{
    free(op);
}

int fp12_cmp(const fp12_t op1, const fp12_t op2)
{
    if(fp6_cmp(op1->m_a, op2->m_a) != 0 ||
       fp6_cmp(op1->m_b, op2->m_b) != 0)
    {
        return 2;
    }
    return 0;
}

// Set fp12_t rop to given value:
void fp12_set(fp12_t rop, const fp12_t op)
{
    fp6_set(rop->m_a, op->m_a);
    fp6_set(rop->m_b, op->m_b);
}

// Initialize an fp12, set to value given in two fp6s
void fp12_set_fp6(fp12_t rop, const fp6_t a, const fp6_t b)
{
    fp6_set(rop->m_a, a);
    fp6_set(rop->m_b, b);
}

// Set rop to one:
void fp12_setone(fp12_t rop, const fp_t rp)
{
    fp6_setzero(rop->m_a);
    fp6_setone(rop->m_b, rp);
}

// Set rop to zero:
void fp12_setzero(fp12_t rop)
{
    fp6_setzero(rop->m_a);
    fp6_setzero(rop->m_b);
}

int fp12_iszero(const fp12_t op)
{
    if (fp6_iszero(op->m_a) && fp6_iszero(op->m_b))
        return 1;

    return 0;
}

// Add two fp12, store result in rop:
void fp12_add(fp12_t rop, const fp12_t op1, const fp12_t op2, const fp_t p)
{
    fp6_add(rop->m_a, op1->m_a, op2->m_a, p);
    fp6_add(rop->m_b, op1->m_b, op2->m_b, p);
}

// Subtract op2 from op1, store result in rop:
void fp12_sub(fp12_t rop, const fp12_t op1, const fp12_t op2, const fp_t p)
{
    fp6_sub(rop->m_a, op1->m_a, op2->m_a, p);
    fp6_sub(rop->m_b, op1->m_b, op2->m_b, p);
}

// Multiply two fp12, store result in rop:
void fp12_mul(fp12_t rop, const fp12_t op1, const fp12_t op2, const ATE_CTX *ctx)
{
    fp6_t tmp1, tmp2, tmp3; // Needed to store intermediary results

    fp6_mul(tmp1, op1->m_a, op2->m_a, ctx);
    fp6_mul(tmp3, op1->m_b, op2->m_b, ctx);

    fp6_add(tmp2, op2->m_a, op2->m_b, ctx->p);
    fp6_add(rop->m_a, op1->m_a, op1->m_b, ctx->p);
    fp6_set(rop->m_b, tmp3);

    fp6_mul(rop->m_a, rop->m_a, tmp2, ctx);
    fp6_sub(rop->m_a, rop->m_a, tmp1, ctx->p);
    fp6_sub(rop->m_a, rop->m_a, rop->m_b, ctx->p);
    fp6_multau(tmp1, tmp1, ctx);
    //fp6_mul(tmp1, tmp1, tau);
    fp6_add(rop->m_b, rop->m_b, tmp1, ctx->p);
}

/* op2 is sparse
 * op2->m_a->m_a = op2->m_b->m_a = op2->m_b->m_b = 0
 */
void fp12_mul_sparse1(fp12_t rop, const fp12_t op1, const fp12_t op2, const ATE_CTX *ctx)
{
    fp6_t tmp1, tmp2, tmp3; // Needed to store intermediary results

    fp6_mul_sparse1(tmp1, op1->m_a, op2->m_a, ctx);
    fp6_mul_sparse3(tmp3, op1->m_b, op2->m_b, ctx);

    fp6_add(tmp2, op2->m_a, op2->m_b, ctx->p);
    fp6_add(rop->m_a, op1->m_a, op1->m_b, ctx->p);
    fp6_set(rop->m_b, tmp3);
    fp6_mul_sparse1(rop->m_a, rop->m_a, tmp2, ctx);
    fp6_sub(rop->m_a, rop->m_a, tmp1, ctx->p);
    fp6_sub(rop->m_a, rop->m_a, rop->m_b, ctx->p);

    fp6_multau(tmp1, tmp1, ctx);
    fp6_add(rop->m_b, rop->m_b, tmp1, ctx->p);
}

/* both op1 and op2 are sparse
 * op1->m_a->m_a = op1->m_b->m_a = op1->m_b->m_b = 0
 * op2->m_a->m_a = op2->m_b->m_a = op2->m_b->m_b = 0
 */
void fp12_mul_sparse2(fp12_t rop, const fp12_t op1, const fp12_t op2, const ATE_CTX *ctx)
{
    fp2_t tmp;
    fp6_t tmp1, tmp2, tmp3; // Needed for intermediary values
    
    fp6_mul_sparse2(tmp1, op1->m_a, op2->m_a, ctx);

    fp2_setzero(tmp2->m_a);
    fp2_setzero(tmp3->m_a);
    fp2_mul(tmp2->m_b, op1->m_a->m_b, op2->m_b->m_c, ctx);
    fp2_mul(tmp2->m_c, op1->m_a->m_c, op2->m_b->m_c, ctx);
    fp2_mul(tmp3->m_b, op2->m_a->m_b, op1->m_b->m_c, ctx);
    fp2_mul(tmp3->m_c, op2->m_a->m_c, op1->m_b->m_c, ctx);
    fp6_add(rop->m_a, tmp2, tmp3, ctx->p);

    fp2_mul(tmp, op1->m_b->m_c, op2->m_b->m_c, ctx);
    fp6_multau(rop->m_b, tmp1, ctx);
    fp2_add(rop->m_b->m_c, rop->m_b->m_c, tmp, ctx->p);
}

void fp12_mul_fp6(fp12_t rop, const fp12_t op1, const fp6_t op2, const ATE_CTX *ctx)
{
    fp6_mul(rop->m_a, op1->m_a, op2, ctx);
    fp6_mul(rop->m_b, op1->m_b, op2, ctx);
}

// Square an fp12, store result in rop:
void fp12_square(fp12_t rop, const fp12_t op, const ATE_CTX *ctx)
{
    fp6_t tmp1, tmp2, tmp3; // Needed to store intermediary results

    fp6_mul(tmp1, op->m_a, op->m_b, ctx);

    fp6_add(tmp2, op->m_a, op->m_b, ctx->p);
    fp6_multau(tmp3, op->m_a, ctx);
    //fp6_mul(tmp3, op->m_a, tau);
    fp6_add(rop->m_b, tmp3, op->m_b, ctx->p);
    fp6_mul(rop->m_b, rop->m_b, tmp2, ctx);

    fp6_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
    fp6_multau(tmp2, tmp1, ctx);
    //fp6_mul(tmp2, tmp1, tau);
    fp6_sub(rop->m_b, rop->m_b, tmp2, ctx->p);

    fp6_add(rop->m_a, tmp1, tmp1, ctx->p);
}

/* op is in cyclotomic subgroup */
void fp12_square_cyclotomic(fp12_t rop, const fp12_t op, const ATE_CTX *ctx)
{
    
}

void fp12_pow1(fp12_t rop, const fp12_t op, const BIGNUM *exp, const ATE_CTX *ctx)
{
    fp12_t dummy;
    int i;
    fp12_set(dummy, op);
    fp12_set(rop, op);
    for (i = BN_num_bits(exp) - 1; i > 0; i--) {
        fp12_square(rop, rop, ctx);
        if(BN_is_bit_set(exp, i - 1))
            fp12_mul(rop, rop, dummy, ctx);
    }
}

void fp12_pow(fp12_t rop, const fp12_t op, const BIGNUM *exp, const ATE_CTX *ctx)
{
    // fp12_t dummy;
    // int i;
    // fp12_set(dummy, op);
    // fp12_set(rop, op);
    // for(i = BN_num_bits(exp) - 1; i > 0; i--)
    // {
    //     fp12_square(rop, rop, ctx);
    //     if(BN_is_bit_set(exp, i - 1))
    //         fp12_mul(rop, rop, dummy, ctx);
    // }
    fp12_windowed_pow(rop, exp, op, ctx);
}

void fp12_invert(fp12_t rop, const fp12_t op, const ATE_CTX *ctx)
{
    fp6_t tmp1, tmp2; // Needed to store intermediary results

    fp6_square(tmp1, op->m_a, ctx);
    fp6_square(tmp2, op->m_b, ctx);
    fp6_multau(tmp1, tmp1, ctx);
    //fp6_mul(tmp1, tmp1, tau);
    fp6_sub(tmp1, tmp2, tmp1, ctx->p);
    fp6_invert(tmp1, tmp1, ctx);
    fp12_set(rop, op);
    fp6_neg(rop->m_a, rop->m_a, ctx->p);
    fp12_mul_fp6(rop, rop, tmp1, ctx);
}

void fp12_frobenius_p(fp12_t rop, const fp12_t op, const ATE_CTX *ctx)
{
    fp6_frobenius_p(rop->m_a, op->m_a, ctx);
    fp6_frobenius_p(rop->m_b, op->m_b, ctx);
    fp6_mul_fp2(rop->m_a, rop->m_a, ctx->zpminus1, ctx);
}

void fp12_frobenius_p2(fp12_t rop, const fp12_t op, const ATE_CTX *ctx)
{
    fp6_frobenius_p2(rop->m_a, op->m_a, ctx);
    fp6_frobenius_p2(rop->m_b, op->m_b, ctx);
    fp6_mul_fp(rop->m_a, rop->m_a, ctx->zeta, ctx);
    fp6_neg(rop->m_a, rop->m_a, ctx->p);
}

void GT_to_bin(uint8_t s[12*N_BYTES], GT *op, const ATE_CTX *ctx)
{
    fp2_t a1, b1, c1, a0, b0, c0;

    fp2_mulxi(a1, op->m_a->m_a, ctx->p);
    fp2_mulxi(b1, op->m_a->m_b, ctx->p);
    fp2_mulxi(c1, op->m_a->m_c, ctx->p);
    fp2_mulxi(a0, op->m_b->m_a, ctx->p);
    fp2_mulxi(b0, op->m_b->m_b, ctx->p);
    fp2_set(c0, op->m_b->m_c);

    fp2_to_bin(s, c1, ctx);
    fp2_to_bin(s + 2*N_BYTES,  a0, ctx);
    fp2_to_bin(s + 4*N_BYTES,  b0, ctx);
    fp2_to_bin(s + 6*N_BYTES,  a1, ctx);
    fp2_to_bin(s + 8*N_BYTES,  b1, ctx);
    fp2_to_bin(s + 10*N_BYTES, c0, ctx);
}

void fp12_print(const fp12_t op, const ATE_CTX *ctx)
{
    fp2_t a1, b1, c1, a0, b0, c0;

    fp2_mulxi(a1, op->m_a->m_a, ctx->p);
    fp2_mulxi(b1, op->m_a->m_b, ctx->p);
    fp2_mulxi(c1, op->m_a->m_c, ctx->p);
    fp2_mulxi(a0, op->m_b->m_a, ctx->p);
    fp2_mulxi(b0, op->m_b->m_b, ctx->p);
    fp2_set(c0, op->m_b->m_c);

    fp2_print(c1, ctx);
    fp2_print(a0, ctx);
    fp2_print(b0, ctx);
    fp2_print(a1, ctx);
    fp2_print(b1, ctx);
    fp2_print(c0, ctx);
}

/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include "pairing_lcl.h"

#define ALIGNPTR(p,N)   ((unsigned char *)p+N-(size_t)p%N)

/* assembly */
void G2_scatter_w5(G2 *val, const G2 *in_t, int idx);
void G2_gather_w5(G2 *val, const G2 *in_t, int idx);

static void copy_conditional(BN_ULONG dst[2*N_LIMBS],
                             const BN_ULONG src[2*N_LIMBS], BN_ULONG move)
{
    BN_ULONG mask1 = 0-move;
    BN_ULONG mask2 = ~mask1;

    dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
    dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
    dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
    dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
    dst[4] = (src[4] & mask1) ^ (dst[4] & mask2);
    dst[5] = (src[5] & mask1) ^ (dst[5] & mask2);
    dst[6] = (src[6] & mask1) ^ (dst[6] & mask2);
    dst[7] = (src[7] & mask1) ^ (dst[7] & mask2);
    if (N_LIMBS == 8) {
        dst[ 8] = (src[ 8] & mask1) ^ (dst[ 8] & mask2);
        dst[ 9] = (src[ 9] & mask1) ^ (dst[ 9] & mask2);
        dst[10] = (src[10] & mask1) ^ (dst[10] & mask2);
        dst[11] = (src[11] & mask1) ^ (dst[11] & mask2);
        dst[12] = (src[12] & mask1) ^ (dst[12] & mask2);
        dst[13] = (src[13] & mask1) ^ (dst[13] & mask2);
        dst[14] = (src[14] & mask1) ^ (dst[14] & mask2);
        dst[15] = (src[15] & mask1) ^ (dst[15] & mask2);
    }
}

/* r = scalar * point */
static int G2_windowed_mul(G2 *r, const BIGNUM *scalar, const G2 *Q, const ATE_CTX *ctx)
{
    size_t i;
    int j, ret = 0, num = 1;
    unsigned int idx;
    unsigned char p_str[33];
    const unsigned int window_size = 5;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    G2 *temp;           /* place for 5 temporary points */
    const BIGNUM *scalars = NULL;
    G2 *table;
   // void *table_storage = NULL;
    unsigned char table_storage[(16 + 5) * sizeof(G2) + 64];
    BN_CTX *bn_ctx = BN_CTX_new();

    table = (void *)ALIGNPTR(table_storage, 64);
    temp = table + 16;

    for (i = 0; i < num; i++) {
        G2 *row = table;

        /* This is an unusual input, we don't guarantee constant-timeness. */
        if ((BN_num_bits(scalar) > 256) || BN_is_negative(scalar)) {
            BIGNUM *mod;

            if ((mod = BN_CTX_get(bn_ctx)) == NULL)
                goto err;
            if (!BN_nnmod(mod, scalar, ctx->order, bn_ctx)) {
                // //ECerr(EC_F_ECP_SM2Z256_WINDOWED_MUL, ERR_R_BN_LIB);
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

        G2_copy(&temp[0], Q);

        /*
         * row[0] is implicitly (0,0,0) (the point at infinity), therefore it
         * is not stored. All other values are actually stored with an offset
         * of -1 in table.
         */
        G2_scatter_w5  (row, &temp[0], 1);
        G2_double(&temp[1], &temp[0], ctx);              /*1+1=2  */
        G2_scatter_w5  (row, &temp[1], 2);
        G2_add   (&temp[2], &temp[1], &temp[0], ctx);    /*2+1=3  */
        G2_scatter_w5  (row, &temp[2], 3);
        G2_double(&temp[1], &temp[1], ctx);              /*2*2=4  */
        G2_scatter_w5  (row, &temp[1], 4);
        G2_double(&temp[2], &temp[2], ctx);              /*2*3=6  */
        G2_scatter_w5  (row, &temp[2], 6);
        G2_add   (&temp[3], &temp[1], &temp[0], ctx);    /*4+1=5  */
        G2_scatter_w5  (row, &temp[3], 5);
        G2_add   (&temp[4], &temp[2], &temp[0], ctx);    /*6+1=7  */
        G2_scatter_w5  (row, &temp[4], 7);
        G2_double(&temp[1], &temp[1], ctx);              /*2*4=8  */
        G2_scatter_w5  (row, &temp[1], 8);
        G2_double(&temp[2], &temp[2], ctx);              /*2*6=12 */
        G2_scatter_w5  (row, &temp[2], 12);
        G2_double(&temp[3], &temp[3], ctx);              /*2*5=10 */
        G2_scatter_w5  (row, &temp[3], 10);
        G2_double(&temp[4], &temp[4], ctx);              /*2*7=14 */
        G2_scatter_w5  (row, &temp[4], 14);
        G2_add   (&temp[2], &temp[2], &temp[0], ctx);    /*12+1=13*/
        G2_scatter_w5  (row, &temp[2], 13);
        G2_add   (&temp[3], &temp[3], &temp[0], ctx);    /*10+1=11*/
        G2_scatter_w5  (row, &temp[3], 11);
        G2_add   (&temp[4], &temp[4], &temp[0], ctx);    /*14+1=15*/
        G2_scatter_w5  (row, &temp[4], 15);
        G2_add   (&temp[2], &temp[1], &temp[0], ctx);    /*8+1=9  */
        G2_scatter_w5  (row, &temp[2], 9);
        G2_double(&temp[1], &temp[1], ctx);              /*2*8=16 */
        G2_scatter_w5  (row, &temp[1], 16);
    }

    idx = 255;

    wvalue = p_str[(idx - 1) / 8];
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    /*
     * We gather to temp[0], because we know it's position relative
     * to table
     */
    G2_gather_w5(&temp[0], table, _booth_recode_w5(wvalue) >> 1);
    memcpy(r, &temp[0], sizeof(temp[0]));

    while (idx >= 5) {
        for (i = (idx == 255 ? 1 : 0); i < 1; i++) {
            unsigned int off = (idx - 1) / 8;

            wvalue = p_str[off] | p_str[off + 1] << 8;
            wvalue = (wvalue >> ((idx - 1) % 8)) & mask;

            wvalue = _booth_recode_w5(wvalue);

            G2_gather_w5(&temp[0], table, wvalue >> 1);

            fp2_neg(temp[1].m_y, temp[0].m_y, ctx->p);
            copy_conditional((BN_ULONG*)temp[0].m_y, (BN_ULONG*)temp[1].m_y, (wvalue & 1));

            G2_add(r, r, &temp[0], ctx);
        }

        idx -= window_size;
        
        G2_double(r, r, ctx);
        G2_double(r, r, ctx);
        G2_double(r, r, ctx);
        G2_double(r, r, ctx);
        G2_double(r, r, ctx);
    }

    /* Final window */
    wvalue = p_str[0];
    wvalue = (wvalue << 1) & mask;

    wvalue = _booth_recode_w5(wvalue);
    G2_gather_w5(&temp[0], table, wvalue >> 1);

    fp2_neg(temp[1].m_y, temp[0].m_y, ctx->p);
    copy_conditional((BN_ULONG*)temp[0].m_y, (BN_ULONG*)temp[1].m_y, (wvalue & 1));

    G2_add(r, r, &temp[0], ctx);

    ret = GML_OK;
err:
    BN_CTX_free(bn_ctx);
    return ret;
}

G2* G2_new()
{
    G2 *ret = NULL;

    ret = (G2*)malloc(sizeof(G2));
    return ret;
}

void G2_free(G2 *op)
{
    free(op);
}

void G2_set(G2 *rop, const G2 *op)
{
    fp2_set(rop->m_x, op->m_x);
    fp2_set(rop->m_y, op->m_y);
    fp2_set(rop->m_z, op->m_z);
}

int G2_copy(G2 *rop, const G2 *op)
{
    fp2_set(rop->m_x, op->m_x);
    fp2_set(rop->m_y, op->m_y);
    fp2_set(rop->m_z, op->m_z);
    return GML_OK;
}

int G2_set_generator(G2 *rop, const ATE_CTX *ctx)
{
    G2_copy(rop, &ctx->twist_gen);
    return GML_OK;
}

void G2_set_jacobian(G2 *rop, const fp2_t x, const fp2_t y, const fp2_t z)
{
    fp2_set(rop->m_x, x);
    fp2_set(rop->m_y, y);
    fp2_set(rop->m_z, z);
}

void G2_set_affine(G2 *rop, const fp2_t x, const fp2_t y, const ATE_CTX *ctx)
{
    fp2_set(rop->m_x, x);
    fp2_set(rop->m_y, y);
    fp2_setone(rop->m_z, ctx->rp);
}

void G2_init_set_str(G2 *rop, const char* xa, const char* xb, const char* ya, const char* yb, const ATE_CTX *ctx)
{
    fp2_t twistgen_x;
    fp2_t twistgen_y;
    fp2_set_hexstr(twistgen_x, xa, xb, ctx);
    fp2_set_hexstr(twistgen_y, ya, yb, ctx);
    G2_set_affine(rop, twistgen_x, twistgen_y, ctx);
}

int G2_cmp(const G2 *op1, const G2 *op2)
{
    return 0;
}

void G2_add_affine(G2 *rop, const G2 *op1, const G2 *op2, const ATE_CTX *ctx)
{
    fp2_t tfp21, tfp22, tfp23, tfp24, tfp25, tfp26, tfp27, tfp28, tfp29; // Temporary variables needed for intermediary results
    fp2_square(tfp21, op1->m_z, ctx);
    fp2_mul(tfp22, op1->m_z, tfp21, ctx);
    fp2_mul(tfp23, op2->m_x, tfp21, ctx);
    fp2_mul(tfp24, op2->m_y, tfp22, ctx);
    fp2_sub(tfp25, tfp23, op1->m_x, ctx->p);
    fp2_sub(tfp26, tfp24, op1->m_y, ctx->p);

    if (fp2_iszero(tfp25) && fp2_iszero(tfp26))
        G2_double(rop, op1, ctx);

    fp2_square(tfp27, tfp25, ctx);
    fp2_mul(tfp28, tfp27, tfp25, ctx);
    fp2_mul(tfp29, op1->m_x, tfp27, ctx);

    fp2_double(tfp21, tfp29, ctx->p);
    fp2_add(tfp21, tfp21, tfp28, ctx->p);
    fp2_square(rop->m_x, tfp26, ctx);
    fp2_sub(rop->m_x, rop->m_x, tfp21, ctx->p);
    fp2_sub(tfp21, tfp29, rop->m_x, ctx->p);
    fp2_mul(tfp22, tfp21, tfp26, ctx);
    fp2_mul(tfp23, op1->m_y, tfp28, ctx);
    fp2_sub(rop->m_y, tfp22, tfp23, ctx->p);
    fp2_mul(rop->m_z, op1->m_z, tfp25, ctx);
}

void G2_add(G2 *rop, const G2 *op1, const G2 *op2, const ATE_CTX *ctx)
{
    fp2_t u1, u2, s1, s2, h, r, t1, t2, t3, t4;
    if (fp2_iszero(op1->m_z)) {
        G2_copy(rop, op2);
        return;
    }
    if (fp2_iszero(op2->m_z)) {
        G2_copy(rop, op1);
        return;
    }
    fp2_square(t1, op1->m_z, ctx); /* z1^2 */
    fp2_square(t2, op2->m_z, ctx); /* z2^2 */
    fp2_mul(u1, op1->m_x, t2, ctx); /* x1 * z2^2 */
    fp2_mul(u2, op2->m_x, t1, ctx); /* x2 * z1^2 */
    fp2_mul(t1, op1->m_z, t1, ctx); /* z1^3 */
    fp2_mul(t2, op2->m_z, t2, ctx); /* z2^3 */
    fp2_mul(s1, op1->m_y, t2, ctx); /* y1 * z2^3 */
    fp2_mul(s2, op2->m_y, t1, ctx); /* y2 * z1^3 */
    if (fp2_cmp(u1, u2) == 0) {
        if (fp2_cmp(s1, s2) != 0) {
            fp2_setzero(rop->m_x);
            fp2_setone(rop->m_y, ctx->rp);
            fp2_setzero(rop->m_z);
            return;
        }
        else {
            G2_double(rop, op1, ctx);
            return;
        }
    }
    fp2_sub(h, u2, u1, ctx->p);
    fp2_sub(r, s2, s1, ctx->p);
    fp2_square(rop->m_x, r, ctx);
    fp2_square(t1, h, ctx); /* h^2 */
    fp2_mul(t2, t1, h, ctx); /* h^3 */
    fp2_sub(rop->m_x, rop->m_x, t2, ctx->p); /* r^2 - h^3 */
    fp2_mul(t3, u1, t1, ctx); /* u1 * h^2 */
    fp2_double(t4, t3, ctx->p); /* 2u1 * h^2 */
    fp2_sub(rop->m_x, rop->m_x, t4, ctx->p); /* x = r^2 - h^3 - 2u1 * h^2 */
    fp2_sub(t4, t3, rop->m_x, ctx->p); /* u1 * h^2 - x */
    fp2_mul(rop->m_y, r, t4, ctx); /* r * (u1 * h^2 - x) */
    fp2_mul(t2, s1, t2, ctx); /* s1 * h^3 */
    fp2_sub(rop->m_y, rop->m_y, t2, ctx->p); /* y = r * (u1 * h^2 - x) - s1 * h^3 */
    fp2_mul(t1, h, op1->m_z, ctx);
    fp2_mul(rop->m_z, t1, op2->m_z, ctx); /* z = h * z1 * z2 */
}

void G2_double(G2 *rop, const G2 *op, const ATE_CTX *ctx)
{
    fp2_t tfp21, tfp22, tfp23, tfp24; // Temporary variables needed for intermediary results
    fp2_square(tfp21, op->m_y, ctx);
    fp2_mul(tfp22, tfp21, op->m_x, ctx);
    fp2_double(tfp22, tfp22, ctx->p);
    fp2_double(tfp22, tfp22, ctx->p);
    fp2_square(tfp23, tfp21, ctx);
    fp2_double(tfp23, tfp23, ctx->p);
    fp2_double(tfp23, tfp23, ctx->p);
    fp2_double(tfp23, tfp23, ctx->p);
    fp2_square(tfp24, op->m_x, ctx);
    fp2_triple(tfp24, tfp24, ctx->p);
    fp2_square(rop->m_x, tfp24, ctx);
    fp2_double(tfp21, tfp22, ctx->p);
    fp2_sub(rop->m_x, rop->m_x, tfp21, ctx->p);
    fp2_sub(tfp21, tfp22, rop->m_x, ctx->p);
    fp2_mul(rop->m_z, op->m_y, op->m_z, ctx);
    fp2_double(rop->m_z, rop->m_z, ctx->p);
    fp2_mul(rop->m_y, tfp24, tfp21, ctx);
    fp2_sub(rop->m_y, rop->m_y, tfp23, ctx->p);
}

void G2_mul(G2 *rop, const G2 *op, const BIGNUM *scalar, const ATE_CTX *ctx)
{
    // TODO: Test...
    // int i;
    // G2 r;
    // G2_set(&r, op);
    
    // for(i = BN_num_bits(scalar) - 1; i > 0; i--)
    // {
    //     G2_double(&r, &r, ctx);
    //     if(BN_is_bit_set(scalar, i - 1)) 
    //         G2_add(&r, &r, op, ctx);
    // }
    // G2_set(rop, &r);
    G2_windowed_mul(rop, scalar, op, ctx);
}


/* FrobeniusOnTwist for Dtype
 * p mod 6 = 1, w^6 = xi
 * Frob(x', y') = phi Frob phi^-1(x', y')
 * = phi Frob (x' w^2, y' w^3)
 * = phi (x'^p w^2p, y'^p w^3p)
 * = (x'^p w^2(p - 1), y'^p w^3(p - 1))
 */
void G2_frobenius(G2 *rop, const G2 *op, const ATE_CTX *ctx)
{
    G2_set(rop, op);

    fp_neg(rop->m_x->m_a, rop->m_x->m_a, ctx->p);
    fp2_mul(rop->m_x, rop->m_x, ctx->ypminus1, ctx);

    fp_neg(rop->m_y->m_a, rop->m_y->m_a, ctx->p);
    fp2_mul(rop->m_y, rop->m_y, ctx->xipminus1over2, ctx);
}

void G2_makeaffine(G2 *op, const ATE_CTX *ctx)
{
    fp2_invert(op->m_z, op->m_z, ctx);
    fp2_mul(op->m_y, op->m_y, op->m_z, ctx);
    fp2_square(op->m_z, op->m_z, ctx);
    fp2_mul(op->m_x, op->m_x, op->m_z, ctx);
    fp2_mul(op->m_y, op->m_y, op->m_z, ctx);
    fp2_setone(op->m_z, ctx->rp);
}

/* assume op is in affine coordinate */
int G2_is_on_curve(const G2 *op, const ATE_CTX *ctx)
{
    fp2_t b;
    fp2_t tx, ty;
    G2 tmp;
    G2_set(&tmp, op);
    G2_makeaffine(&tmp, ctx);
    fp2_setzero(b);
    fp_set(b->m_a, ctx->b); /* b*sqrt(-2) */

    fp2_square(ty, tmp.m_y, ctx); /* y^2 */
    fp2_square(tx, tmp.m_x, ctx);
    fp2_mul(tx, tx, tmp.m_x, ctx); /* x^3 */
    fp2_add(tx, tx, b, ctx->p); /* x^3 + b*sqrt(-2) */
    
    return fp2_cmp(tx, ty) == 0;
}

// print G2:
void G2_print(const G2 *op, const ATE_CTX *ctx)
{
    fp2_print(op->m_x, ctx);
    fp2_print(op->m_y, ctx);
    fp2_print(op->m_z, ctx);
}

int G2_to_bin(uint8_t s[4*N_BYTES], const G2 *Q, const ATE_CTX *ctx)
{
    G2 tmp;
    G2_copy(&tmp, Q);
    G2_makeaffine(&tmp, ctx);
    fp2_to_bin(s, tmp.m_x, ctx);
    fp2_to_bin(s + 2*N_BYTES, tmp.m_y, ctx);
    return GML_OK;
}

int G2_from_bin(G2 *Q, const uint8_t s[4*N_BYTES], const ATE_CTX *ctx)
{
    fp2_from_bin(Q->m_x, s, ctx);
    fp2_from_bin(Q->m_y, s + 2*N_BYTES, ctx);
    fp2_setone(Q->m_z, ctx->rp);
    return GML_OK;
}

int G2_point_compress(uint8_t s[4*N_BYTES + 1], const G2 *Q, const ATE_CTX *ctx)
{
    s[0] = 0x04;
    s++;
    G2_to_bin(s, Q, ctx);
    return GML_OK;
}

int G2_point_uncompress(G2 *Q, const uint8_t s[4*N_BYTES + 1], const ATE_CTX *ctx)
{
    if (s[0] != 0x04)
        return GML_ERROR;

    s++;
    G2_from_bin(Q, s, ctx);
    return GML_OK;
}
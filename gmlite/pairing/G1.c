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
#include <stdlib.h>
#include "pairing_lcl.h"

#define ALIGNPTR(p,N)   ((unsigned char *)p+N-(size_t)p%N)

/* assembly */
void G1_scatter_w5(G1 *val, const G1 *in_t, int idx);
void G1_gather_w5(G1 *val, const G1 *in_t, int idx);

static void copy_conditional(BN_ULONG dst[N_LIMBS],
                             const BN_ULONG src[N_LIMBS], BN_ULONG move)
{
    BN_ULONG mask1 = 0-move;
    BN_ULONG mask2 = ~mask1;

    dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
    dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
    dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
    dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
    if (N_LIMBS == 8) {
        dst[4] = (src[4] & mask1) ^ (dst[4] & mask2);
        dst[5] = (src[5] & mask1) ^ (dst[5] & mask2);
        dst[6] = (src[6] & mask1) ^ (dst[6] & mask2);
        dst[7] = (src[7] & mask1) ^ (dst[7] & mask2);
    }
}

/* r = scalar * point */
static int G1_windowed_mul(G1 *r, const BIGNUM *scalar, const G1 *P, const ATE_CTX *ctx)
{
    size_t i;
    int j, ret = 0, num = 1;
    unsigned int idx;
    unsigned char p_str[33];
    const unsigned int window_size = 5;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    G1 *temp;           /* place for 5 temporary points */
    const BIGNUM *scalars = NULL;
    G1 *table;
    unsigned char table_storage[(16 + 5) * sizeof(G1) + 64];
    BN_CTX *bn_ctx = BN_CTX_new();

    table = (void *)ALIGNPTR(table_storage, 64);
    temp = table + 16;

    for (i = 0; i < num; i++) {
        G1 *row = table;

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

        G1_copy(&temp[0], P);

        /*
         * row[0] is implicitly (0,0,0) (the point at infinity), therefore it
         * is not stored. All other values are actually stored with an offset
         * of -1 in table.
         */
        G1_scatter_w5  (row, &temp[0], 1);
        G1_double(&temp[1], &temp[0], ctx);              /*1+1=2  */
        G1_scatter_w5  (row, &temp[1], 2);
        G1_add   (&temp[2], &temp[1], &temp[0], ctx);    /*2+1=3  */
        G1_scatter_w5  (row, &temp[2], 3);
        G1_double(&temp[1], &temp[1], ctx);              /*2*2=4  */
        G1_scatter_w5  (row, &temp[1], 4);
        G1_double(&temp[2], &temp[2], ctx);              /*2*3=6  */
        G1_scatter_w5  (row, &temp[2], 6);
        G1_add   (&temp[3], &temp[1], &temp[0], ctx);    /*4+1=5  */
        G1_scatter_w5  (row, &temp[3], 5);
        G1_add   (&temp[4], &temp[2], &temp[0], ctx);    /*6+1=7  */
        G1_scatter_w5  (row, &temp[4], 7);
        G1_double(&temp[1], &temp[1], ctx);              /*2*4=8  */
        G1_scatter_w5  (row, &temp[1], 8);
        G1_double(&temp[2], &temp[2], ctx);              /*2*6=12 */
        G1_scatter_w5  (row, &temp[2], 12);
        G1_double(&temp[3], &temp[3], ctx);              /*2*5=10 */
        G1_scatter_w5  (row, &temp[3], 10);
        G1_double(&temp[4], &temp[4], ctx);              /*2*7=14 */
        G1_scatter_w5  (row, &temp[4], 14);
        G1_add   (&temp[2], &temp[2], &temp[0], ctx);    /*12+1=13*/
        G1_scatter_w5  (row, &temp[2], 13);
        G1_add   (&temp[3], &temp[3], &temp[0], ctx);    /*10+1=11*/
        G1_scatter_w5  (row, &temp[3], 11);
        G1_add   (&temp[4], &temp[4], &temp[0], ctx);    /*14+1=15*/
        G1_scatter_w5  (row, &temp[4], 15);
        G1_add   (&temp[2], &temp[1], &temp[0], ctx);    /*8+1=9  */
        G1_scatter_w5  (row, &temp[2], 9);
        G1_double(&temp[1], &temp[1], ctx);              /*2*8=16 */
        G1_scatter_w5  (row, &temp[1], 16);
    }

    idx = 255;

    wvalue = p_str[(idx - 1) / 8];
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    /*
     * We gather to temp[0], because we know it's position relative
     * to table
     */
    G1_gather_w5(&temp[0], table, _booth_recode_w5(wvalue) >> 1);
    memcpy(r, &temp[0], sizeof(temp[0]));

    while (idx >= 5) {
        for (i = (idx == 255 ? 1 : 0); i < 1; i++) {
            unsigned int off = (idx - 1) / 8;

            wvalue = p_str[off] | p_str[off + 1] << 8;
            wvalue = (wvalue >> ((idx - 1) % 8)) & mask;

            wvalue = _booth_recode_w5(wvalue);

            G1_gather_w5(&temp[0], table, wvalue >> 1);

            fp_neg(temp[1].m_y, temp[0].m_y, ctx->p);
            copy_conditional(temp[0].m_y->d, temp[1].m_y->d, (wvalue & 1));

            G1_add(r, r, &temp[0], ctx);
        }

        idx -= window_size;
        
        G1_double(r, r, ctx);
        G1_double(r, r, ctx);
        G1_double(r, r, ctx);
        G1_double(r, r, ctx);
        G1_double(r, r, ctx);
    }

    /* Final window */
    wvalue = p_str[0];
    wvalue = (wvalue << 1) & mask;

    wvalue = _booth_recode_w5(wvalue);
    G1_gather_w5(&temp[0], table, wvalue >> 1);

    fp_neg(temp[1].m_y, temp[0].m_y, ctx->p);
    copy_conditional(temp[0].m_y->d, temp[1].m_y->d, (wvalue & 1));

    G1_add(r, r, &temp[0], ctx);

    ret = GML_OK;
err:
    BN_CTX_free(bn_ctx);
    return ret;
}

G1* G1_new()
{
    G1 *ret = NULL;

    ret = (G1*)malloc(sizeof(G1));
    return ret;
}

void G1_free(G1 *op)
{
    free(op);
}

// Initialize a :
void G1_init(G1 *rop, const ATE_CTX *ctx)
{
    fp_setzero(rop->m_x);
    fp_setone(rop->m_y, ctx->rp);
    fp_setzero(rop->m_z);
}

int G1_copy(G1 *rop, const G1 *op)
{
    fp_set(rop->m_x, op->m_x);
    fp_set(rop->m_y, op->m_y);
    fp_set(rop->m_z, op->m_z);
    return GML_OK;
}

int G1_set_generator(G1 *rop, const ATE_CTX *ctx)
{
    G1_copy(rop, &ctx->curve_gen);
    return GML_OK;
}

void G1_init_set_str(G1 *rop, const char* x, const char* y, const ATE_CTX *ctx)
{
    fp_set_hexstr(rop->m_x, x, ctx);
    fp_set_hexstr(rop->m_y, y, ctx);
    fp_setone(rop->m_z, ctx->rp);
}

void G1_init_set(G1 *rop, const G1 *op)
{
    fp_set(rop->m_x, op->m_x);
    fp_set(rop->m_y, op->m_y);
    fp_set(rop->m_z, op->m_z);
}

// // Set the coordinates of bytearray:
// void G1_set_bytearray(G1 *rop, const unsigned char* x, const unsigned char* y)
// {
//     fp_set_bytearray(rop->m_x, x, 32);
//     fp_set_bytearray(rop->m_y, y, 32);
//     fp_setone(rop->m_z);
// }


// Set the coordinates of a G1 *by copying the coordinates from another 
void G1_set(G1 *rop, const G1 *op)
{
    fp_set(rop->m_x, op->m_x);
    fp_set(rop->m_y, op->m_y);
    fp_set(rop->m_z, op->m_z);
}

void G1_add_affine(G1 *rop, const G1 *op1, const G1 *op2, const ATE_CTX *ctx)
{
    fp_t tfp1, tfp2, tfp3, tfp4, tfp5, tfp6, tfp7, tfp8, tfp9; // Temporary variables needed for intermediary results
    fp_square(tfp1, op1->m_z, ctx->p, ctx->n0);
    fp_mul(tfp2, op1->m_z, tfp1, ctx->p, ctx->n0);
    fp_mul(tfp3, op2->m_x, tfp1, ctx->p, ctx->n0);
    fp_mul(tfp4, op2->m_y, tfp2, ctx->p, ctx->n0);
    fp_sub(tfp5, tfp3, op1->m_x, ctx->p);
    fp_sub(tfp6, tfp4, op1->m_y, ctx->p);

    if (fp_iszero(tfp5) && fp_iszero(tfp6))
        G1_double(rop, op1, ctx);

    fp_square(tfp7, tfp5, ctx->p, ctx->n0);
    fp_mul(tfp8, tfp7, tfp5, ctx->p, ctx->n0);
    fp_mul(tfp9, op1->m_x, tfp7, ctx->p, ctx->n0);

    fp_double(tfp1, tfp9, ctx->p);
    fp_add(tfp1, tfp1, tfp8, ctx->p);
    fp_square(rop->m_x, tfp6, ctx->p, ctx->n0);
    fp_sub(rop->m_x, rop->m_x, tfp1, ctx->p);
    fp_sub(tfp1, tfp9, rop->m_x, ctx->p);
    fp_mul(tfp2, tfp1, tfp6, ctx->p, ctx->n0);
    fp_mul(tfp3, op1->m_y, tfp8, ctx->p, ctx->n0);
    fp_sub(rop->m_y, tfp2, tfp3, ctx->p);
    fp_mul(rop->m_z, op1->m_z, tfp5, ctx->p, ctx->n0);
}

void G1_add(G1 *rop, const G1 *op1, const G1 *op2, const ATE_CTX *ctx)
{
    fp_t u1, u2, s1, s2, h, r, t1, t2, t3, t4;
    if (fp_iszero(op1->m_z)) {
        G1_copy(rop, op2);
        return;
    }
    if (fp_iszero(op2->m_z)) {
        G1_copy(rop, op1);
        return;
    }
    fp_square(t1, op1->m_z, ctx->p, ctx->n0); /* z1^2 */
    fp_square(t2, op2->m_z, ctx->p, ctx->n0); /* z2^2 */
    fp_mul(u1, op1->m_x, t2, ctx->p, ctx->n0); /* x1 * z2^2 */
    fp_mul(u2, op2->m_x, t1, ctx->p, ctx->n0); /* x2 * z1^2 */
    fp_mul(t1, op1->m_z, t1, ctx->p, ctx->n0); /* z1^3 */
    fp_mul(t2, op2->m_z, t2, ctx->p, ctx->n0); /* z2^3 */
    fp_mul(s1, op1->m_y, t2, ctx->p, ctx->n0); /* y1 * z2^3 */
    fp_mul(s2, op2->m_y, t1, ctx->p, ctx->n0); /* y2 * z1^3 */
    if (fp_cmp(u1, u2) == 0) {
        if (fp_cmp(s1, s2) != 0) {
            fp_setzero(rop->m_x);
            fp_setone(rop->m_y, ctx->rp);
            fp_setzero(rop->m_z);
            return;
        }
        else {
            G1_double(rop, op1, ctx);
            return;
        }
    }
    fp_sub(h, u2, u1, ctx->p);
    fp_sub(r, s2, s1, ctx->p);
    fp_square(rop->m_x, r, ctx->p, ctx->n0);
    fp_square(t1, h, ctx->p, ctx->n0); /* h^2 */
    fp_mul(t2, t1, h, ctx->p, ctx->n0); /* h^3 */
    fp_sub(rop->m_x, rop->m_x, t2, ctx->p); /* r^2 - h^3 */
    fp_mul(t3, u1, t1, ctx->p, ctx->n0); /* u1 * h^2 */
    fp_double(t4, t3, ctx->p); /* 2u1 * h^2 */
    fp_sub(rop->m_x, rop->m_x, t4, ctx->p); /* x = r^2 - h^3 - 2u1 * h^2 */
    fp_sub(t4, t3, rop->m_x, ctx->p); /* u1 * h^2 - x */
    fp_mul(rop->m_y, r, t4, ctx->p, ctx->n0); /* r * (u1 * h^2 - x) */
    fp_mul(t2, s1, t2, ctx->p, ctx->n0); /* s1 * h^3 */
    fp_sub(rop->m_y, rop->m_y, t2, ctx->p); /* y = r * (u1 * h^2 - x) - s1 * h^3 */
    fp_mul(t1, h, op1->m_z, ctx->p, ctx->n0);
    fp_mul(rop->m_z, t1, op2->m_z, ctx->p, ctx->n0); /* z = h * z1 * z2 */
}

void G1_double(G1 *rop, const G1 *op, const ATE_CTX *ctx)
{
    fp_t tfp1, tfp2, tfp3, tfp4; // Temporary variables needed for intermediary results
    fp_square(tfp1, op->m_y, ctx->p, ctx->n0);
    fp_mul(tfp2, tfp1, op->m_x, ctx->p, ctx->n0);
    fp_double(tfp2, tfp2, ctx->p);
    fp_double(tfp2, tfp2, ctx->p);
    fp_square(tfp3, tfp1, ctx->p, ctx->n0);
    fp_double(tfp3, tfp3, ctx->p);
    fp_double(tfp3, tfp3, ctx->p);
    fp_double(tfp3, tfp3, ctx->p);
    fp_square(tfp4, op->m_x, ctx->p, ctx->n0);
    fp_triple(tfp4, tfp4, ctx->p);
    fp_square(rop->m_x, tfp4, ctx->p, ctx->n0);
    fp_double(tfp1, tfp2, ctx->p);
    fp_sub(rop->m_x, rop->m_x, tfp1, ctx->p);
    fp_sub(tfp1, tfp2, rop->m_x, ctx->p);

    fp_mul(rop->m_z, op->m_y, op->m_z, ctx->p, ctx->n0);
    fp_double(rop->m_z, rop->m_z, ctx->p);
    fp_mul(rop->m_y, tfp4, tfp1, ctx->p, ctx->n0);
    fp_sub(rop->m_y, rop->m_y, tfp3, ctx->p);
}

/* rop = scalar * op */
void G1_mul(G1 *rop, const G1 *op, const BIGNUM *scalar, const ATE_CTX *ctx)
{
    // int i;
    // G1 r;
    // G1_set(&r, op);

    // for(i = BN_num_bits(scalar) - 1; i > 0; i--)
    // {
    //     G1_double(&r, &r, ctx);
    //     if(BN_is_bit_set(scalar, i - 1)) 
    //     {
    //         G1_add(&r, &r, op, ctx);
    //     }
    // }
    // G1_set(rop, &r);
    G1_windowed_mul(rop, scalar, op, ctx);
}

// // Negate a point, store in rop:
// void G1_neg(G1 *rop, const G1 *op, const ATE_CTX *ctx)
// {
//     fp_neg(curvepoint_dummy_fp1, op->m_y, ctx->p);
//     fp_set(rop->m_x, op->m_x);
//     fp_set(rop->m_y, curvepoint_dummy_fp1);
//     fp_set(rop->m_z, op->m_z);
// }

// Transform to Affine Coordinates (z=1)
void G1_makeaffine(G1 *op, const ATE_CTX *ctx)
{
    fp_t dummy;
    if(fp_iszero(op->m_z))
    {
        fp_setzero(op->m_x);
        fp_setone(op->m_y, ctx->rp);
        fp_setzero(op->m_z);
    }
    else
    {
        fp_invert(dummy, op->m_z, ctx);
        fp_mul(op->m_x, op->m_x, dummy, ctx->p, ctx->n0);
        fp_mul(op->m_x, op->m_x, dummy, ctx->p, ctx->n0);

        fp_mul(op->m_y, op->m_y, dummy, ctx->p, ctx->n0);
        fp_mul(op->m_y, op->m_y, dummy, ctx->p, ctx->n0);
        fp_mul(op->m_y, op->m_y, dummy, ctx->p, ctx->n0);

        fp_setone(op->m_z, ctx->rp);
    }
}

int G1_is_on_curve(const G1 *op, const ATE_CTX *ctx)
{
    fp_t tx, ty;
    G1 tmp;
    G1_set(&tmp, op);
    G1_makeaffine(&tmp, ctx);

    fp_square(ty, tmp.m_y, ctx->p, ctx->n0); /* y^2 */
    fp_square(tx, tmp.m_x, ctx->p, ctx->n0);
    fp_mul(tx, tx, tmp.m_x, ctx->p, ctx->n0); /* x^3 */
    fp_add(tx, tx, ctx->b, ctx->p); /* x^3 + b */
    
    return fp_cmp(tx, ty) == 0;
}

// print G1:
void G1_print(const G1 *op, const ATE_CTX *ctx)
{
    G1 tmp;
    G1_copy(&tmp, op);
    G1_makeaffine(&tmp, ctx);
    fp_print(tmp.m_x, ctx);
    fp_print(tmp.m_y, ctx);
}

int G1_to_bin(uint8_t s[2*N_BYTES], const G1 *P, const ATE_CTX *ctx)
{
    G1 tmp;
    G1_copy(&tmp, P);
    G1_makeaffine(&tmp, ctx);
    fp_to_bin(s, tmp.m_x, ctx);
    fp_to_bin(s + N_BYTES, tmp.m_y, ctx);
    return GML_OK;
}

int G1_from_bin(G1 *P, const uint8_t s[2*N_BYTES], const ATE_CTX *ctx)
{
    fp_from_bin(P->m_x, s, ctx);
    fp_from_bin(P->m_y, s + N_BYTES, ctx);
    fp_setone(P->m_z, ctx->rp);
    return GML_OK;
}

int G1_point_compress(uint8_t s[2*N_BYTES + 1], const G1 *P, const ATE_CTX *ctx)
{
    s[0] = 0x04;
    s++;
    G1_to_bin(s, P, ctx);
    return GML_OK;
}

int G1_point_uncompress(G1 *P, const uint8_t s[2*N_BYTES + 1], const ATE_CTX *ctx)
{
    if (s[0] != 0x04)
        return GML_ERROR;

    s++;
    G1_from_bin(P, s, ctx);
    return GML_OK;
}

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

int fp6_cmp(const fp6_t op1, const fp6_t op2)
{
    if (fp2_cmp(op1->m_a, op2->m_a) != 0 ||
        fp2_cmp(op1->m_b, op2->m_b) != 0 ||
        fp2_cmp(op1->m_c, op2->m_c) != 0)
        return 2;

    return 0;
}

// Set fp6_t rop to given value:
void fp6_set(fp6_t rop, const fp6_t op)
{
    fp2_set(rop->m_a, op->m_a);
    fp2_set(rop->m_b, op->m_b);
    fp2_set(rop->m_c, op->m_c);
}

// Initialize an fp6, set to value given in three fp2s
void fp6_set_fp2(fp6_t rop, const fp2_t a, const fp2_t b, const fp2_t c)
{
    fp2_set(rop->m_a, a);
    fp2_set(rop->m_b, b);
    fp2_set(rop->m_c, c);
}

// Initialize an fp6, set to value given in six strings
void fp6_set_hexstr(fp6_t rop, const char *a1, const char *a0, const char *b1, const char *b0, const char *c1, const char *c0, const ATE_CTX *ctx)
{
    fp2_set_hexstr(rop->m_a, a1, a0, ctx);
    fp2_set_hexstr(rop->m_b, b1, b0, ctx);
    fp2_set_hexstr(rop->m_c, c1, c0, ctx);
}

// Set rop to one:
void fp6_setone(fp6_t rop, const fp_t rp)
{
    fp2_setzero(rop->m_a);
    fp2_setzero(rop->m_b);
    fp2_setone(rop->m_c, rp);
}

// Set rop to zero:
void fp6_setzero(fp6_t rop)
{
    fp2_setzero(rop->m_a);
    fp2_setzero(rop->m_b);
    fp2_setzero(rop->m_c);
}

int fp6_iszero(const fp6_t op)
{
    if (fp2_iszero(op->m_a) && fp2_iszero(op->m_b) && fp2_iszero(op->m_c))
        return 1;

    return 0;
}

// Add two fp6, store result in rop:
void fp6_add(fp6_t rop, const fp6_t op1, const fp6_t op2, const fp_t p)
{
    fp2_add(rop->m_a, op1->m_a, op2->m_a, p);
    fp2_add(rop->m_b, op1->m_b, op2->m_b, p);
    fp2_add(rop->m_c, op1->m_c, op2->m_c, p);
}

// Subtract op2 from op1, store result in rop:
void fp6_sub(fp6_t rop, const fp6_t op1, const fp6_t op2, const fp_t p)
{
    fp2_sub(rop->m_a, op1->m_a, op2->m_a, p);
    fp2_sub(rop->m_b, op1->m_b, op2->m_b, p);
    fp2_sub(rop->m_c, op1->m_c, op2->m_c, p);
}

// Subtract op2 from op1, store result in rop:
void fp6_neg(fp6_t rop, const fp6_t op, const fp_t p)
{
    fp2_neg(rop->m_a, op->m_a, p);
    fp2_neg(rop->m_b, op->m_b, p);
    fp2_neg(rop->m_c, op->m_c, p);
}

// Multiply two fp6, store result in rop:
void fp6_mul(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx)
{
    fp2_t tmp1, tmp2, tmp3, tmp4, tmp5, tmp6; // Needed for intermediary values

    // See "Multiplication and Squaring in Pairing-Friendly Fields", section 4, Karatsuba method
    fp2_mul(tmp3, op1->m_a, op2->m_a, ctx);
    fp2_mul(tmp2, op1->m_b, op2->m_b, ctx);
    fp2_mul(tmp1, op1->m_c, op2->m_c, ctx);

    fp2_add(tmp4, op1->m_a, op1->m_b, ctx->p);
    fp2_add(tmp5, op2->m_a, op2->m_b, ctx->p);
    fp2_mul(tmp6, tmp4, tmp5, ctx); 
    fp2_sub(tmp6, tmp6, tmp2, ctx->p);
    fp2_sub(tmp6, tmp6, tmp3, ctx->p);
    fp2_mulxi(tmp6, tmp6, ctx->p);
    // fp2_mul(tmp6, tmp6, ctx->xi, ctx);
    fp2_add(tmp6, tmp6, tmp1, ctx->p);

    fp2_add(tmp4, op1->m_b, op1->m_c, ctx->p);
    fp2_add(tmp5, op2->m_b, op2->m_c, ctx->p);
    fp2_mul(rop->m_b, tmp4, tmp5, ctx);
    fp2_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
    fp2_sub(rop->m_b, rop->m_b, tmp2, ctx->p);
    fp2_mulxi(tmp4, tmp3, ctx->p);
    // fp2_mul(tmp4, tmp3, ctx->xi, ctx);
    fp2_add(rop->m_b, rop->m_b, tmp4, ctx->p);

    fp2_add(tmp4, op1->m_a, op1->m_c, ctx->p);
    fp2_add(tmp5, op2->m_a, op2->m_c, ctx->p);

    fp2_set(rop->m_c, tmp6);

    fp2_mul(rop->m_a, tmp4, tmp5, ctx);
    fp2_sub(rop->m_a, rop->m_a, tmp1, ctx->p);
    fp2_add(rop->m_a, rop->m_a, tmp2, ctx->p);
    fp2_sub(rop->m_a, rop->m_a, tmp3, ctx->p);
}

/* op2 is sparse
 * op2->m_a = 0
 */
void fp6_mul_sparse1(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx)
{
    fp2_t tmp1, tmp2, tmp4, tmp5, tmp6; // Needed for intermediary values

    fp2_mul(tmp2, op1->m_b, op2->m_b, ctx);
    fp2_mul(tmp1, op1->m_c, op2->m_c, ctx);

    fp2_mul(tmp6, op1->m_a, op2->m_b, ctx);
    fp2_mulxi(tmp6, tmp6, ctx->p);
    fp2_add(tmp6, tmp6, tmp1, ctx->p);

    fp2_add(tmp4, op1->m_b, op1->m_c, ctx->p);
    fp2_add(tmp5, op2->m_b, op2->m_c, ctx->p);
    fp2_mul(rop->m_b, tmp4, tmp5, ctx);
    fp2_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
    fp2_sub(rop->m_b, rop->m_b, tmp2, ctx->p);

    fp2_mul(tmp4, op1->m_a, op2->m_c, ctx);
    fp2_set(rop->m_c, tmp6);
    fp2_add(rop->m_a, tmp4, tmp2, ctx->p);
}

/* both op1 and op2 are sparse
 * op2->m_a = op2->m_a = 0
 */
void fp6_mul_sparse2(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx)
{
    fp2_t tmp1, tmp2, tmp4, tmp5; // Needed for intermediary values

    fp2_mul(tmp2, op1->m_b, op2->m_b, ctx);
    fp2_mul(tmp1, op1->m_c, op2->m_c, ctx);

    fp2_add(tmp4, op1->m_b, op1->m_c, ctx->p);
    fp2_add(tmp5, op2->m_b, op2->m_c, ctx->p);
    fp2_mul(rop->m_b, tmp4, tmp5, ctx);
    fp2_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
    fp2_sub(rop->m_b, rop->m_b, tmp2, ctx->p);

    fp2_set(rop->m_a, tmp2);
    fp2_set(rop->m_c, tmp1);
}

/* op2 is sparse
 * op2->m_a = op2->m_b = 0
 */
void fp6_mul_sparse3(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx)
{
    fp2_mul(rop->m_a, op1->m_a, op2->m_c, ctx);
    fp2_mul(rop->m_b, op1->m_b, op2->m_c, ctx);
    fp2_mul(rop->m_c, op1->m_c, op2->m_c, ctx);
}

// Square an fp6, store result in rop:
void fp6_square(fp6_t rop, const fp6_t op, const ATE_CTX *ctx)
{
    fp6_mul(rop, op, op, ctx);
}

// Multiply with tau:
void fp6_multau(fp6_t rop, const fp6_t op, const ATE_CTX *ctx)
{
    fp2_t tmp1;
    fp2_set(tmp1, op->m_b);
    fp2_set(rop->m_b, op->m_c);
    fp2_mulxi(rop->m_c, op->m_a, ctx->p);
    // fp2_mul(rop->m_c, op->m_a, ctx->xi, ctx);
    fp2_set(rop->m_a, tmp1);
}

void fp6_mul_fp(fp6_t rop, const fp6_t op1, const fp_t op2, const ATE_CTX *ctx)
{
    fp2_mul_fp(rop->m_a, op1->m_a, op2, ctx);
    fp2_mul_fp(rop->m_b, op1->m_b, op2, ctx);
    fp2_mul_fp(rop->m_c, op1->m_c, op2, ctx);
}

void fp6_mul_fp2(fp6_t rop, const fp6_t op1, const fp2_t op2, const ATE_CTX *ctx)
{
    fp2_mul(rop->m_a, op1->m_a, op2, ctx);
    fp2_mul(rop->m_b, op1->m_b, op2, ctx);
    fp2_mul(rop->m_c, op1->m_c, op2, ctx);
}

void fp6_invert(fp6_t rop, const fp6_t op, const ATE_CTX *ctx)
{
    fp2_t tmp1, tmp2, tmp3, tmp4, tmp5;  // Needed to store intermediary results

    // See "Implementing cryptographic pairings"
    fp2_square(tmp1, op->m_c, ctx);
    fp2_mul(tmp5, op->m_a, op->m_b, ctx);
    fp2_mulxi(tmp5, tmp5, ctx->p);
    // fp2_mul(tmp5, tmp5, ctx->xi, ctx);
    fp2_sub(tmp1, tmp1, tmp5, ctx->p); // A
    
    fp2_square(tmp2, op->m_a, ctx);
    fp2_mulxi(tmp2, tmp2, ctx->p);
    // fp2_mul(tmp2, tmp2, ctx->xi, ctx);
    fp2_mul(tmp5, op->m_b, op->m_c, ctx);
    fp2_sub(tmp2, tmp2, tmp5, ctx->p); // B

    fp2_square(tmp3, op->m_b, ctx);
    fp2_mul(tmp5, op->m_a, op->m_c, ctx);
    fp2_sub(tmp3, tmp3, tmp5, ctx->p); // C

    fp2_mul(tmp4, tmp3, op->m_b, ctx);
    fp2_mulxi(tmp4, tmp4, ctx->p);
    // fp2_mul(tmp4, tmp4, ctx->xi, ctx);
    fp2_mul(tmp5, tmp1, op->m_c, ctx);
    fp2_add(tmp4, tmp4, tmp5, ctx->p);
    fp2_mul(tmp5, tmp2, op->m_a, ctx);
    fp2_mulxi(tmp5, tmp5, ctx->p);
    // fp2_mul(tmp5, tmp5, ctx->xi, ctx);
    fp2_add(tmp4, tmp4, tmp5, ctx->p); // F
    
    fp2_invert(tmp4, tmp4, ctx);

    fp2_mul(rop->m_a, tmp3, tmp4, ctx);
    fp2_mul(rop->m_b, tmp2, tmp4, ctx);
    fp2_mul(rop->m_c, tmp1, tmp4, ctx);
}

void fp6_frobenius_p(fp6_t rop, const fp6_t op, const ATE_CTX *ctx)
{
    fp2_t tmp; // Needed to store intermediary results

    fp6_set(rop, op);
    fp_neg((rop->m_a)->m_a, (rop->m_a)->m_a, ctx->p);
    fp_neg((rop->m_b)->m_a, (rop->m_b)->m_a, ctx->p);
    fp_neg((rop->m_c)->m_a, (rop->m_c)->m_a, ctx->p);

    fp2_mul(rop->m_b, rop->m_b, ctx->ypminus1, ctx);
    fp2_square(tmp, ctx->ypminus1, ctx);
    fp2_mul(rop->m_a, rop->m_a, tmp, ctx);
}

void fp6_frobenius_p2(fp6_t rop, const fp6_t op, const ATE_CTX *ctx)
{
    fp_t tmp; // Needed for intermediary results

    fp_square(tmp, ctx->zeta, ctx->p, ctx->n0);
    fp2_set(rop->m_c, op->m_c);
    fp2_mul_fp(rop->m_b, op->m_b, tmp, ctx);
    fp2_mul_fp(rop->m_a, op->m_a, ctx->zeta, ctx);
}

void fp6_to_bin(uint8_t s[6*N_BYTES], fp6_t op, const ATE_CTX *ctx)
{
    fp2_to_bin(s, op->m_a, ctx);
    fp2_to_bin(s + 2*N_BYTES, op->m_b, ctx);
    fp2_to_bin(s + 4*N_BYTES, op->m_c, ctx);
}

// print fp6:
void fp6_print(const fp6_t op, const ATE_CTX *ctx)
{
    fp2_print(op->m_a, ctx);
    fp2_print(op->m_b, ctx);
    fp2_print(op->m_c, ctx);
}

/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <assert.h>
#include "pairing_lcl.h"

// #define ALPHA -2

int fp2_cmp(const fp2_t op1, const fp2_t op2)
{
    if (fp_cmp(op1->m_a, op2->m_a) != 0 ||
        fp_cmp(op1->m_b, op2->m_b) != 0)
        return 2;
    return 0;
}

// Set fp2_t rop to given value:
void fp2_set(fp2_t rop, const fp2_t op)
{
    fp_set(rop->m_a, op->m_a);
    fp_set(rop->m_b, op->m_b);
}

// Set fp2_t rop to given value:
void fp2_set_fp(fp2_t rop, const fp_t op)
{
    fp_setzero(rop->m_a);
    fp_set(rop->m_b, op);
}

// Set rop to one
void fp2_setone(fp2_t rop, const fp_t rp)
{
    fp_setzero(rop->m_a);
    fp_setone(rop->m_b, rp);
}

// Set rop to zero
void fp2_setzero(fp2_t rop)
{
    fp_setzero(rop->m_a);
    fp_setzero(rop->m_b);;
}

int fp2_iszero(const fp2_t op)
{
    if (fp_iszero(op->m_a) && fp_iszero(op->m_b))
        return 1;

    return 0;
}

// Set an fp2_t to value given in two strings
void fp2_set_hexstr(fp2_t rop, const char* a_str, const char* b_str, const ATE_CTX *ctx)
{
    fp_set_hexstr(rop->m_a, a_str, ctx);
    fp_set_hexstr(rop->m_b, b_str, ctx);
}


// Multiply an fp by xi which is used to construct F_p^6
//void fp2_mulxi_fp(fp2_t rop, const fp_t op)
//{
//    //TODO Check for XI
//    fp_set(rop->m_a, op);
//}

/* side channel */
void fp2_pow(fp2_t rop, const fp2_t op, BIGNUM *exp, const ATE_CTX *ctx)
{
    fp2_t dummy;
    int i;
    fp2_set(dummy, op);
    fp2_set(rop, op);
    for (i = BN_num_bits(exp) - 1; i > 0; i--) {
        fp2_square(rop, rop, ctx);
        if (BN_is_bit_set(exp, i - 1))
            fp2_mul(rop, rop, dummy, ctx);
    }
}

// Inverse multiple of an fp2, store result in rop:
void fp2_invert(fp2_t rop, const fp2_t op, const ATE_CTX *ctx)
{
// static int nnn2=0;
// nnn2++;
// printf("%d\n",nnn2);
    fp_t tmp1, tmp2;  // Needed for intermediary results

    fp_mul(tmp1, op->m_a, op->m_a, ctx->p, ctx->n0);
    fp_mul(tmp2, op->m_b, op->m_b, ctx->p, ctx->n0);

    fp_double(tmp1, tmp1, ctx->p);
    fp_add(tmp2, tmp2, tmp1, ctx->p);

    fp_invert(tmp2, tmp2, ctx);

    fp_mul(rop->m_b, op->m_b, tmp2, ctx->p, ctx->n0);
    fp_neg(tmp2, tmp2, ctx->p);
    fp_mul(rop->m_a, op->m_a, tmp2, ctx->p, ctx->n0);
}

int fp2_sqrt(fp2_t rop, const fp2_t op, const ATE_CTX *ctx)
{
    fp_t zero, t1, t2, t3, t4;

    fp_setzero(zero);
    if (fp_cmp(op->m_a, zero) == 0) { // op->m_a = 0
        if (fp_sqrt(rop->m_b, op->m_b, ctx) == GML_OK) {
            fp_setzero(rop->m_a);
            return GML_OK;
        }
    }

    fp_square(t1, op->m_b, ctx->p, ctx->n0); // b^2
    fp_square(t2, op->m_a, ctx->p, ctx->n0); // a^2
    fp_double(t2, t2, ctx->p);
    fp_add(t3, t1, t2, ctx->p); // t3 = 2a^2 + b^2
    if (fp_sqrt(t3, t3, ctx) == GML_OK) {
        fp_sub(t4, t3, op->m_b, ctx->p); // -b + sqrt(2a^2 + b^2)
        fp_div_by_2(t4, t4, ctx->p);
        fp_div_by_2(t4, t4, ctx->p); // (-b + sqrt(2a^2 + b^2)) / 4
        if (fp_sqrt(t4, t4, ctx) == GML_OK && fp_cmp(t4, zero) != 0) {
            fp_set(t1, op->m_a);
            fp_set(rop->m_a, t4);
            fp_double(t4, t4, ctx->p);
            fp_invert(t4, t4, ctx);
            fp_mul(rop->m_b, t4, t1, ctx->p, ctx->n0);
            return GML_OK;
        }
        else {
            fp_neg(t3, t3, ctx->p);
            fp_sub(t4, t3, op->m_b, ctx->p); // -b - sqrt(2a^2 + b^2)
            fp_div_by_2(t4, t4, ctx->p);
            fp_div_by_2(t4, t4, ctx->p); // (-b - sqrt(2a^2 + b^2)) / 4
            if (fp_sqrt(t4, t4, ctx) == GML_OK && fp_cmp(t4, zero) != 0) {
                fp_set(t1, op->m_a);
                fp_set(rop->m_a, t4);
                fp_double(t4, t4, ctx->p);
                fp_invert(t4, t4, ctx);
                fp_mul(rop->m_b, t4, t1, ctx->p, ctx->n0);
                return GML_OK;
            }
            else
                return GML_ERROR;
        }
    }
    else
        return GML_ERROR;
}

void fp2_to_bin(uint8_t s[2*N_BYTES], const fp2_t op, const ATE_CTX *ctx)
{
    fp_to_bin(s, op->m_a, ctx);
    fp_to_bin(s + N_BYTES, op->m_b, ctx);
}

void fp2_from_bin(fp2_t rop, const uint8_t s[2*N_BYTES], const ATE_CTX *ctx)
{
    fp_from_bin(rop->m_a, s, ctx);
    fp_from_bin(rop->m_b, s + N_BYTES, ctx);
}

// print fp2:
void fp2_print(const fp2_t op, const ATE_CTX *ctx)
{
    fp_print(op->m_a, ctx);
    fp_print(op->m_b, ctx);
}

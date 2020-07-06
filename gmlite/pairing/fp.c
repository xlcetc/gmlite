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
#include <string.h>
#include <assert.h>
#include "../ec/ec_lcl.h"
#include "../bn/bn_lcl.h"
#include "pairing_lcl.h"

/* 0 : equal, else : not equal */
int fp_cmp(const fp_t op1, const fp_t op2)
{
    int i;
    for (i = 0; i < N_LIMBS; i++) {
        if (op1->d[i] != op2->d[i])
            return 2;
    }
    return 0;
}

// Set fp_t rop to given value:
void fp_set(fp_t rop, const fp_t op)
{
    int i;
    for (i = 0; i < N_LIMBS; i++)
        rop->d[i] = op->d[i];
}

// Set fp_t rop to given value given as hex string
void fp_set_hexstr(fp_t rop, const char* op, const ATE_CTX *ctx)
{
    // Initialize all limbs with 0:
    int i, j = 0;
    const char *scan = op;
    int size = 0;
    unsigned char byte_str[N_LIMBS*8];
    unsigned char b8[8];

    fp_setzero(rop);

    // Determine the length of op:
    while (*scan != 0) {
        ++scan;
        ++size;
    }
    assert(size <= N_LIMBS*16);

    hex_to_u8((uint8_t*)op, size, byte_str);
    for (i = size/2 - 8; i >= 0; i -= 8) {
        u8_to_u64(byte_str + i, 8, rop->d + j, ORDER_BIG_ENDIAN);
        j++;
    }

    if (i < 0 && i > -8) {
        memset(b8, 0, 8);
        memcpy(b8 - i, byte_str, i + 8);
        u8_to_u64(b8, 8, rop->d + j, ORDER_BIG_ENDIAN);
    }

    fp_mul(rop, rop, ctx->rrp, ctx->p, ctx->n0);
}

// Set rop to one
void fp_setone(fp_t rop, const fp_t rp)
{
    int i;
    for (i = 0; i < N_LIMBS; i++)
        rop->d[i] = rp->d[i];
}

// Set rop to zero
void fp_setzero(fp_t rop)
{
    int i;
    for (i = 0; i < N_LIMBS; i++)
        rop->d[i] = 0;
}

// Return 1 if op is zero, 0 otherwise
int fp_iszero(const fp_t op)
{
    int i;
    for (i = 0; i < N_LIMBS; i++)
        if(op->d[i]) return 0;
    return 1;
}

// inline void fp_mul(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p, const fp_t n0)
// {
//     bn_mul_mont(rop->d, op1->d, op2->d, p->d, n0->d, N_LIMBS);
// }

/* rop = op^-1 mod p */
int fp_invert(fp_t rop, const fp_t op, const ATE_CTX *ctx)
{
    int ret = GML_ERROR;
    BIGNUM *p = NULL;
    BIGNUM *OP = NULL;
    BN_CTX *bn_ctx = NULL;

    p = BN_new();
    OP = BN_new();
    bn_ctx = BN_CTX_new();

    if (p == NULL || OP== NULL || bn_ctx == NULL)
        goto end;

    /* TODO : init p once, it's constant */
    BN_set_words(p, (BN_ULONG*)ctx->p->d, N_LIMBS);
    BN_set_words(OP, (BN_ULONG*)op->d, N_LIMBS);
    if (!BN_mod_inverse_Lehmer(OP, OP, p, bn_ctx))
        goto end;

    bn_copy_words(rop->d, OP, N_LIMBS);
    fp_mul(rop, rop, ctx->rrp, ctx->p, ctx->n0);
    fp_mul(rop, rop, ctx->rrp, ctx->p, ctx->n0);
    ret = 1;
end:
    BN_free(p);
    BN_free(OP);
    BN_CTX_free(bn_ctx);
    return ret;
}

void fp_pow(fp_t rop, const fp_t op, BIGNUM *exp, const ATE_CTX *ctx)
{
    fp_t dummy;
    int i;
    fp_set(dummy, op);
    fp_set(rop, op);
    for (i = BN_num_bits(exp) - 1; i > 0; i--) {
        fp_square(rop, rop, ctx->p, ctx->n0);
        if (BN_is_bit_set(exp, i - 1))
            fp_mul(rop, rop, dummy, ctx->p, ctx->n0);
    }
}

int fp_sqrt(fp_t rop, const fp_t op, const ATE_CTX *ctx)
{
    int ret = GML_ERROR;
    BIGNUM *z = BN_new();
    BIGNUM *u = BN_new();
    BIGNUM *v = BN_new();
    fp_t tmp, one, minus_one, t;
    fp_setzero(one);

    if (fp_cmp(op, one) == 0) {
        BN_free(u);
        BN_free(v);
        BN_free(z);
        fp_setzero(rop);
        return 1;
    }

    one->d[0] = 1;
    fp_sub(minus_one, ctx->p, one, ctx->p);
    fp_mul(one, one, ctx->rrp, ctx->p, ctx->n0);
    fp_mul(minus_one, minus_one, ctx->rrp, ctx->p, ctx->n0);
    BN_set_words(u, ctx->p->d, 4);

    if (ctx->p_type == P_MOD_8_EQ_5) {
        BN_sub_word(u, 5);
        BN_div_word(u, 8);

        BN_copy(v, u);
        BN_mul_word(v, 2);
        BN_add_word(v, 1); // 2u+1
        fp_pow(tmp, op, v, ctx);

        if (fp_cmp(tmp, one) == 0) {
            BN_copy(v, u);
            BN_add_word(v, 1);
            fp_pow(rop, op, v, ctx);
            ret = 1;
            goto end;
        }
        else if (fp_cmp(tmp, minus_one) == 0) {
            fp_add(t, op, op, ctx->p);
            fp_add(tmp, t, t, ctx->p);
            BN_copy(v, u);
            fp_pow(rop, tmp, v, ctx);
            fp_mul(rop, rop, t, ctx->p, ctx->n0);
            ret = 1;
            goto end;
        }
        else
            goto end;
    }
    else if (ctx->p_type == P_MOD_4_EQ_3) {
        BN_sub_word(u, 3);
        BN_div_word(u, 4);

        BN_copy(v, u);
        BN_add_word(v, 1); // u+1
        fp_pow(t, op, v, ctx);
        
        fp_mul(tmp, t, t, ctx->p ,ctx->n0);
        if (fp_cmp(tmp, op) == 0) {
            fp_set(rop, t);
            ret = 1;
            goto end;
        }
        else
            goto end;
    }
    else
        goto end;

end:
    BN_free(u);
    BN_free(v);
    BN_free(z);
    return ret;
}

// Print the element to stdout:
void fp_print(const fp_t op, const ATE_CTX *ctx)
{
    fp_t tmp ,one;
    uint8_t hex[N_LIMBS*16];

    fp_set(tmp, op);
    fp_setzero(one);
    one->d[0] = 1;

    fp_mul(tmp, tmp, one, ctx->p, ctx->n0);
    for (int i = 0; i < N_LIMBS; i++)
        u64_to_hex(&tmp->d[N_LIMBS - i - 1], 1, hex + 16*i);

    for (int i = 0; i < N_LIMBS*16; i++)
        printf("%c", hex[i]);

    printf("\n");
}

void fp_to_bin(uint8_t s[N_BYTES], const fp_t op, const ATE_CTX *ctx)
{
    int i = N_LIMBS - 1;
    fp_t tmp, one;

    fp_setzero(one);
    one->d[0] = 1;
    fp_mul(tmp, op, one, ctx->p, ctx->n0);

    while (i >= 0) {
        u64_to_u8(&tmp->d[i], 1, s, ORDER_BIG_ENDIAN);
        s += 8;
        i--;
    }
}

void fp_from_bin(fp_t rop, const uint8_t s[N_LIMBS], const ATE_CTX *ctx)
{
    int i = N_LIMBS - 1;

    while (i >= 0) {
        u8_to_u64(s, 8, &rop->d[i], ORDER_BIG_ENDIAN);
        s += 8;
        i--;
    }

    fp_mul(rop, rop, ctx->rrp, ctx->p, ctx->n0);
}
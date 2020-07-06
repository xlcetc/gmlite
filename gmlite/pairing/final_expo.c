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

void final_expo(GT *rop, const ATE_CTX *ctx)
{
    BIGNUM *exp;
    fp_t tt;

    // First part: (p^6 - 1)
    fp12_t dummy1, dummy2, dummy3, fp, fp2, fp3;
    fp12_set(dummy1, rop);

    // p^6
    fp6_neg(rop->m_a, rop->m_a, ctx->p);

    fp12_invert(dummy2, dummy1, ctx);
    fp12_mul(rop, rop, dummy2, ctx);

    // Second part: (p^2 + 1)
    fp12_set(dummy1, rop);
    fp12_frobenius_p2(rop, rop, ctx);
    fp12_mul(rop, rop, dummy1, ctx);

    // Third part: Hard part
    fp12_set(dummy1, rop);
    fp6_neg(dummy1->m_a, dummy1->m_a, ctx->p);

    exp = BN_new();
    BN_set_words(exp, ctx->t->d, N_LIMBS);
    BN_mul_word(exp, 6);
    BN_add_word(exp, 5);

    fp12_pow1(dummy2, dummy1, exp, ctx); // dummy2 = f^{-(6x+5)}
    
    fp12_frobenius_p(dummy3, dummy2, ctx);
    fp12_mul(dummy3, dummy3, dummy2, ctx); // dummy3 = f^{-(6x+5)p}*f^{-(6x+5)}
    fp12_frobenius_p(fp, rop, ctx);
    fp12_frobenius_p2(fp2, rop, ctx);
    fp12_frobenius_p(fp3, fp2, ctx);
    
    fp12_square(dummy1, rop, ctx);
    fp12_square(dummy1, dummy1, ctx);

    fp12_mul(rop, rop, fp, ctx); // rop = f*f^p

    BN_set_word(exp, 9);
    fp12_pow1(rop, rop, exp, ctx);
    fp12_mul(rop, rop, dummy1, ctx);
    fp12_mul(rop, rop, dummy2, ctx);
    fp12_mul(rop, rop, dummy3, ctx);
    fp12_mul(rop, rop, fp3, ctx);

    fp12_square(dummy1, fp, ctx);
    fp12_mul(dummy1, dummy1, fp2, ctx);
    fp12_mul(dummy1, dummy1, dummy3, ctx);

    /* TODO : ...... */
    fp_setzero(tt);
    bn_sqr_words(tt->d, ctx->t->d, 1);
    BN_set_words(exp, tt->d, N_LIMBS);
    BN_mul_word(exp, 6);
    BN_add_word(exp, 1);
    fp12_pow1(dummy1, dummy1, exp, ctx);
    fp12_mul(rop, rop, dummy1, ctx);

    BN_free(exp);
}


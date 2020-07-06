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

static void linefunction_add_ate(
        fp12_t rop1, 
        G2 *rop2, 
        const G2 *op1, 
        const G2 *op2, 
        const G1 *op3,
        const fp2_t r2, /* r2 = y^2, see "Faster Computation of Tate Pairings" */
        const ATE_CTX *ctx
        )
{
    fp2_t tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9, tmp10, z2; // Temporary variables needed for intermediary results
    fp6_t tfp61, tfp62;

    fp2_square(z2, op1->m_z, ctx);
    fp2_mul(tmp0, op2->m_x, z2, ctx); /* tmp0 = B = x2 * T1  = x2z1^2*/

    fp2_add(tmp1, op2->m_y, op1->m_z, ctx->p);
    fp2_square(tmp1, tmp1, ctx);
    fp2_sub(tmp1, tmp1, r2, ctx->p);
    fp2_sub(tmp1, tmp1, z2, ctx->p);
    fp2_mul(tmp1, tmp1, z2, ctx); /* tmp1 = D = ((y2 + Z1)^2 - R2 - T1)T1  = 2y2z1^3 */

    fp2_sub(tmp2, tmp0, op1->m_x, ctx->p); /* tmp2 = H = B - X1  = x2z1^2 - x1*/

    fp2_square(tmp3, tmp2, ctx); /* tmp3 = I = H^2  = (x2z1^2 - x1)^2*/

    fp2_double(tmp4, tmp3, ctx->p); 
    fp2_double(tmp4, tmp4, ctx->p); /* tmp4 = E = 4I = 4(x2z1^2 - x1)^2*/

    fp2_mul(tmp5, tmp2, tmp4, ctx); /* tmp5 = J = HE =  4(x2z1^2 - x1)(x2z1^2 - x1)^2*/

    fp2_sub(tmp6, tmp1, op1->m_y, ctx->p); 
    fp2_sub(tmp6, tmp6, op1->m_y, ctx->p); /* tmp6 = r = 2(D - 2Y1) = (2y2z1^3 - 2y1)*/
    
    fp2_mul(tmp9, tmp6, op2->m_x, ctx); /* Needed later: tmp9 = x2(2y2z1^3 - 2y1)*/

    fp2_mul(tmp7, op1->m_x, tmp4, ctx); /* tmp7 = V = X1*E = 4x1(x2z1^2 - x1)^2*/

    fp2_square(rop2->m_x, tmp6, ctx);
    fp2_sub(rop2->m_x, rop2->m_x, tmp5, ctx->p);
    fp2_sub(rop2->m_x, rop2->m_x, tmp7, ctx->p);
    fp2_sub(rop2->m_x, rop2->m_x, tmp7, ctx->p); /* X3 = r^2 - J - 2V = (2y2z1^3 - 2y1)^2 - 4(x2z1^2 - x1)(x2z1^2 - x1)^2 - 8x1(x2z1^2 - x1)^2*/

    fp2_add(rop2->m_z, op1->m_z, tmp2, ctx->p);
    fp2_square(rop2->m_z, rop2->m_z, ctx);
    fp2_sub(rop2->m_z, rop2->m_z, z2, ctx->p);
    fp2_sub(rop2->m_z, rop2->m_z, tmp3, ctx->p); /* Z3 = (z1 + H)^2 - T1 - I  = 2z1(x2z1^2 - x1) */
    
    fp2_add(tmp10, op2->m_y, rop2->m_z, ctx->p); /* Needed later: tmp10 = y2 + z3*/

    fp2_sub(tmp8, tmp7, rop2->m_x, ctx->p);
    fp2_mul(tmp8, tmp8, tmp6, ctx);
    fp2_mul(tmp0, op1->m_y, tmp5, ctx);
    fp2_double(tmp0, tmp0, ctx->p);
    fp2_sub(rop2->m_y, tmp8, tmp0, ctx->p); /* Y3 = r(V - X3) - 2Y1*J = (2y2z1^3 - 2y1)(4x1(x2z1^2 - x1)^2 - x3) - 8y1(x2z1^2 - x1)(x2z1^2 - x1)^2*/

    
    fp2_square(z2, rop2->m_z, ctx); /* T3 = Z3^2 */

    fp2_square(tmp10, tmp10, ctx); /* tmp10 = (y2 + z3)^2 */
    fp2_sub(tmp10, tmp10, r2, ctx->p);
    fp2_sub(tmp10, tmp10, z2, ctx->p); 
    fp2_double(tmp9, tmp9, ctx->p);
    fp2_sub(tmp9, tmp9, tmp10, ctx->p); /* tmp9 = 4x2(y2z1^3 - y1) - 2z3y2 */

    fp2_mul_fp(tmp10, rop2->m_z, op3->m_y, ctx); /* tmp10 = z3y_Q */
    fp2_double(tmp10, tmp10, ctx->p);

    fp2_neg(tmp6, tmp6, ctx->p);
    fp2_mul_fp(tmp1, tmp6, op3->m_x, ctx);
    fp2_double(tmp1, tmp1, ctx->p);

    fp2_setzero(tmp2);

    fp6_set_fp2(tfp61, tmp2, tmp9, tmp1);
    fp6_set_fp2(tfp62, tmp2, tmp2, tmp10);

    fp12_set_fp6(rop1, tfp61, tfp62);
}

static void linefunction_double_ate(fp12_t rop1, G2 *rop2, const G2 *op1, const G1 *op3, const ATE_CTX *ctx)
{
    fp2_t tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp7, dummy, z2; // Temporary variables needed for intermediary results
    fp6_t tfp61, tfp62;

    fp2_square(z2, op1->m_z, ctx);

    fp2_square(tmp0, op1->m_x, ctx); /* tmp0 = A = X1^2 = x1^2 */
    fp2_square(tmp1, op1->m_y, ctx); /* tmp1 = B = Y1^2 = y1^2 */
    fp2_square(tmp2, tmp1, ctx); /* tmp2 = C = B^2 = y1^4 */

    fp2_add(tmp3, op1->m_x, tmp1, ctx->p);
    fp2_square(tmp3, tmp3, ctx);
    fp2_sub(tmp3, tmp3, tmp0, ctx->p);
    fp2_sub(tmp3, tmp3, tmp2, ctx->p);
    fp2_double(tmp3, tmp3, ctx->p); /* tmp3 = D = 2(X1 + B)^2 - A - C) = 4x1y1^2 */

    fp2_triple(tmp4, tmp0, ctx->p); /* tmp4 = E = 3A = 3x1^2 */
    
    fp2_add(tmp7, tmp4, op1->m_x, ctx->p); /* Needed later */

    fp2_square(tmp5, tmp4, ctx); /* tmp5 = G = E^2 = 9x1^4 */

    fp2_sub(rop2->m_x, tmp5, tmp3, ctx->p);
    fp2_sub(rop2->m_x, rop2->m_x, tmp3, ctx->p); /* X3 = G - 2D = 9x1^4 - 8x1y1^2 */

    fp2_add(rop2->m_z, op1->m_y, op1->m_z, ctx->p);
    fp2_square(rop2->m_z, rop2->m_z, ctx);
    fp2_sub(rop2->m_z, rop2->m_z, tmp1, ctx->p);
    fp2_sub(rop2->m_z, rop2->m_z, z2, ctx->p); /* Z3 = (Y1 + Z1)^2 - B - T1 = 2y1z1; */

    fp2_sub(rop2->m_y, tmp3, rop2->m_x, ctx->p);
    fp2_mul(rop2->m_y, rop2->m_y, tmp4, ctx); 
    fp2_double(dummy, tmp2, ctx->p);
    fp2_double(dummy, dummy, ctx->p);
    fp2_double(dummy, dummy, ctx->p);
    fp2_sub(rop2->m_y, rop2->m_y, dummy, ctx->p); /* Y3 = E(D - X3) - 8C = 3x1^2(4x1y1^2 - X3) - 8y1^4 */

    fp2_mul(tmp3, tmp4, z2, ctx);
    fp2_double(tmp3, tmp3, ctx->p);
    fp2_neg(tmp3, tmp3, ctx->p);
    fp2_mul_fp(tmp3, tmp3, op3->m_x, ctx); /* tmp3 = -6x1^2z1^2 * x_Q */

    fp2_square(tmp7, tmp7, ctx);
    fp2_sub(tmp7, tmp7, tmp0, ctx->p);
    fp2_sub(tmp7, tmp7, tmp5, ctx->p);
    fp2_double(dummy, tmp1, ctx->p);
    fp2_double(dummy, dummy, ctx->p);
    fp2_sub(tmp7, tmp7, dummy, ctx->p); /* tmp7 = 6x1^3 - 4y1^2 */

    fp2_mul(tmp0, rop2->m_z, z2, ctx);
    fp2_double(tmp0, tmp0, ctx->p);
    fp2_mul_fp(tmp0, tmp0, op3->m_y, ctx);

    fp2_setzero(tmp1);

    fp6_set_fp2(tfp61, tmp1, tmp7, tmp3);
    fp6_set_fp2(tfp62, tmp1, tmp1, tmp0);

    fp12_set_fp6(rop1, tfp61, tfp62);
}

void miller_loop(GT *rop, const G1 *P, const G2 *Q, const ATE_CTX *ctx)
{
    // P and Q are assumed to be in affine coordinates!
    fp12_t dummy1, dummy2;
    G2 r, t, minusQ;
    fp2_t r2;
    int i;

    fp12_setone(rop, ctx->rp);

    G2_set(&r, Q);

    G2_set(&minusQ, Q);
    fp2_neg(minusQ.m_y, minusQ.m_y, ctx->p);
    fp2_square(r2, Q->m_y, ctx);

    for (i = 1; i < ctx->naf_len; i++) {
        linefunction_double_ate(dummy1, &r, &r, P, ctx);

        fp12_square(rop, rop, ctx);
        fp12_mul_sparse1(rop, rop, dummy1, ctx);

        if (ctx->naf[i] == 1) {
            linefunction_add_ate(dummy2, &r, &r, Q, P, r2, ctx);
            // fp12_mul_sparse2(dummy1, dummy1, dummy2, ctx);
            fp12_mul_sparse1(rop, rop, dummy2, ctx);
        }
        else if (ctx->naf[i] == -1) {
            linefunction_add_ate(dummy2, &r, &r, &minusQ, P, r2, ctx);
            // fp12_mul_sparse2(dummy1, dummy1, dummy2, ctx);
            fp12_mul_sparse1(rop, rop, dummy2, ctx);
        }
        // fp12_mul(rop, rop, dummy1, ctx);
    }

    G2_frobenius(&t, Q, ctx);
    fp2_square(r2, t.m_y, ctx);
    linefunction_add_ate(dummy1, &r, &r, &t, P, r2, ctx);

    G2_frobenius(&t, &t, ctx);
    fp2_neg(t.m_y, t.m_y, ctx->p);
    fp2_square(r2, t.m_y, ctx);
    linefunction_add_ate(dummy2, &r, &r, &t, P, r2, ctx);

    fp12_mul_sparse2(dummy1, dummy1, dummy2, ctx);
    fp12_mul(rop, rop, dummy1, ctx);
}

void optate(GT *rop, const G1 *P, const G2 *Q, const ATE_CTX *ctx)
{
    miller_loop(rop, P, Q, ctx);
    final_expo(rop, ctx);
}

// void ate(GT *rop, const G2 *op2, const G1 *op1, const ATE_CTX *ctx)
// {
//     fp12_t dummy;
//     BIGNUM *tminus1;
//     G2 *r;
//     fp2_t r2;
//     unsigned long int i;
    
//     fp12_setone(rop, ctx->rp);

//     tminus1 = BN_new();
//     BN_set_words(tminus1, ctx->trace->d, N_LIMBS);
//     BN_sub_word(tminus1, 1);

//     G2_set(r, op2);
//     fp2_setone(r->m_t, ctx->rp); /* As r has to be in affine coordinates this is ok */
    
//     fp2_square(r2, op2->m_y, ctx);

//     for(i = BN_num_bits(tminus1) - 1; i > 0; i--)
//     {
//         linefunction_double_ate(dummy, r, r, op1, ctx);
//         fp12_square(rop, rop, ctx);
//         fp12_mul(rop, rop, dummy, ctx);

//         if (BN_is_bit_set(tminus1, i - 1)) 
//         {
//             printf("1");
//             linefunction_add_ate(dummy, r, r, op2, op1, r2, ctx);
//             fp12_mul(rop, rop, dummy, ctx);
//         }
//         else
//         {
//             printf("0");
//         }
        
//     }

//     final_expo(rop, ctx);

// }

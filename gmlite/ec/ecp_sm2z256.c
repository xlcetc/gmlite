/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/******************************************************************************
 *                                                                            *
 * Copyright 2014 Intel Corporation                                           *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 *                                                                            *
 ******************************************************************************
 *                                                                            *
 * Developers and authors:                                                    *
 * Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *
 * (1) Intel Corporation, Israel Development Center                           *
 * (2) University of Haifa                                                    *
 * Reference:                                                                 *
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with *
 *                          256 Bit Primes"                                   *
 *                                                                            *
 ******************************************************************************/

#include <string.h>
#include <gmlite/crypto.h>
#include <gmlite/cpuid.h>
#include <internal/bn_int.h>
#include "ec_lcl.h"
#include "../sm2/sm2_lcl.h"

#if BN_BITS2 != 64
# define TOBN(hi,lo)    lo,hi
#else
# define TOBN(hi,lo)    ((BN_ULONG)hi<<32|lo)
#endif

#if defined(__GNUC__)
# define ALIGN32        __attribute((aligned(32)))
#elif defined(_MSC_VER)
# define ALIGN32        __declspec(align(32))
#else
# define ALIGN32
#endif

#define ALIGNPTR(p,N)   ((unsigned char *)p+N-(size_t)p%N)
#define P256_LIMBS      (256/BN_BITS2)

typedef unsigned short u16;

typedef struct {
    BN_ULONG X[P256_LIMBS];
    BN_ULONG Y[P256_LIMBS];
    BN_ULONG Z[P256_LIMBS];
} P256_POINT;

typedef struct {
    BN_ULONG X[P256_LIMBS];
    BN_ULONG Y[P256_LIMBS];
} P256_POINT_AFFINE;

typedef P256_POINT_AFFINE PRECOMP256_ROW[64];
static SM2Z256_PRE_COMP *ecp_sm2z256_pre_comp_new(const EC_GROUP *group);

/* structure for precomputed multiples of the generator */
struct sm2z256_pre_comp_st {
    const EC_GROUP *group;      /* Parent EC_GROUP object */
    size_t w;                   /* Window size */
    /*
     * Constant time access to the X and Y coordinates of the pre-computed,
     * generator multiplies, in the Montgomery domain. Pre-calculated
     * multiplies are stored in affine form.
     */
    PRECOMP256_ROW *precomp;
    void *precomp_storage;
    int references;
    // CRYPTO_RWLOCK *lock;
};

/* Functions implemented in assembly */
/*
 * Most of below mentioned functions *preserve* the property of inputs
 * being fully reduced, i.e. being in [0, modulus) range. Simply put if
 * inputs are fully reduced, then output is too. Note that reverse is
 * not true, in sense that given partially reduced inputs output can be
 * either, not unlikely reduced. And "most" in first sentence refers to
 * the fact that given the calculations flow one can tolerate that
 * addition, 1st function below, produces partially reduced result *if*
 * multiplications by 2 and 3, which customarily use addition, fully
 * reduce it. This effectively gives two options: a) addition produces
 * fully reduced result [as long as inputs are, just like remaining
 * functions]; b) addition is allowed to produce partially reduced
 * result, but multiplications by 2 and 3 perform additional reduction
 * step. Choice between the two can be platform-specific, but it was a)
 * in all cases so far...
 */
/* Modular add: res = a+b mod P   */
void ecp_sm2z256_add(BN_ULONG res[P256_LIMBS],
                     const BN_ULONG a[P256_LIMBS],
                     const BN_ULONG b[P256_LIMBS]);
/* Modular mul by 2: res = 2*a mod P */
void ecp_sm2z256_mul_by_2(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG a[P256_LIMBS]);
/* Modular mul by 3: res = 3*a mod P */
void ecp_sm2z256_mul_by_3(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG a[P256_LIMBS]);

/* Modular div by 2: res = a/2 mod P */
void ecp_sm2z256_div_by_2(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG a[P256_LIMBS]);
/* Modular sub: res = a-b mod P   */
void ecp_sm2z256_sub(BN_ULONG res[P256_LIMBS],
                     const BN_ULONG a[P256_LIMBS],
                     const BN_ULONG b[P256_LIMBS]);
/* Modular neg: res = -a mod P    */
void ecp_sm2z256_neg(BN_ULONG res[P256_LIMBS], const BN_ULONG a[P256_LIMBS]);
/* Montgomery mul: res = a*b*2^-256 mod P */
void ecp_sm2z256_mul_mont(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG a[P256_LIMBS],
                          const BN_ULONG b[P256_LIMBS]);
/* Montgomery sqr: res = a*a*2^-256 mod P */
void ecp_sm2z256_sqr_mont(BN_ULONG res[P256_LIMBS],
                          const BN_ULONG a[P256_LIMBS]);
/* Convert a number from Montgomery domain, by multiplying with 1 */
void ecp_sm2z256_from_mont(BN_ULONG res[P256_LIMBS],
                           const BN_ULONG in[P256_LIMBS]);
/* Convert a number to Montgomery domain, by multiplying with 2^512 mod P*/
void ecp_sm2z256_to_mont(BN_ULONG res[P256_LIMBS],
                         const BN_ULONG in[P256_LIMBS]);
/* Functions that perform constant time access to the precomputed tables */
void ecp_sm2z256_scatter_w5(P256_POINT *val,
                            const P256_POINT *in_t, int idx);
void ecp_sm2z256_gather_w5(P256_POINT *val,
                           const P256_POINT *in_t, int idx);
void ecp_sm2z256_scatter_w7(P256_POINT_AFFINE *val,
                            const P256_POINT_AFFINE *in_t, int idx);
void ecp_sm2z256_gather_w7(P256_POINT_AFFINE *val,
                           const P256_POINT_AFFINE *in_t, int idx);

/* One converted into the Montgomery domain */
static const BN_ULONG ONE[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0x00000000, 0xffffffff),
    TOBN(0x00000000, 0x00000000), TOBN(0x00000001, 0x00000000)
};

// static SM2Z256_PRE_COMP *ecp_sm2z256_pre_comp_new(const EC_GROUP *group);

/* Precomputed tables for the default generator */
extern const PRECOMP256_ROW ecp_sm2z256_precomputed[37];

/* Recode window to a signed digit, see ecp_nistputil.c for details */
static unsigned int _booth_recode_w5(unsigned int in)
{
    unsigned int s, d;

    s = ~((in >> 5) - 1);
    d = (1 << 6) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);

    return (d << 1) + (s & 1);
}

static unsigned int _booth_recode_w7(unsigned int in)
{
    unsigned int s, d;

    s = ~((in >> 7) - 1);
    d = (1 << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);

    return (d << 1) + (s & 1);
}

static void copy_conditional(BN_ULONG dst[P256_LIMBS],
                             const BN_ULONG src[P256_LIMBS], BN_ULONG move)
{
    BN_ULONG mask1 = 0-move;
    BN_ULONG mask2 = ~mask1;

    dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
    dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
    dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
    dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
    if (P256_LIMBS == 8) {
        dst[4] = (src[4] & mask1) ^ (dst[4] & mask2);
        dst[5] = (src[5] & mask1) ^ (dst[5] & mask2);
        dst[6] = (src[6] & mask1) ^ (dst[6] & mask2);
        dst[7] = (src[7] & mask1) ^ (dst[7] & mask2);
    }
}

static BN_ULONG is_zero(BN_ULONG in)
{
    in |= (0 - in);
    in = ~in;
    in >>= BN_BITS2 - 1;
    return in;
}

static BN_ULONG is_equal(const BN_ULONG a[P256_LIMBS],
                         const BN_ULONG b[P256_LIMBS])
{
    BN_ULONG res;

    res = a[0] ^ b[0];
    res |= a[1] ^ b[1];
    res |= a[2] ^ b[2];
    res |= a[3] ^ b[3];
    if (P256_LIMBS == 8) {
        res |= a[4] ^ b[4];
        res |= a[5] ^ b[5];
        res |= a[6] ^ b[6];
        res |= a[7] ^ b[7];
    }

    return is_zero(res);
}

static BN_ULONG is_one(const BIGNUM *z)
{
    BN_ULONG res = 0;
    BN_ULONG *a = bn_get_words(z);

    if (bn_get_top(z) == (P256_LIMBS - P256_LIMBS / 8)) {
        res = a[0] ^ ONE[0];
        res |= a[1] ^ ONE[1];
        res |= a[2] ^ ONE[2];
        res |= a[3] ^ ONE[3];
        if (P256_LIMBS == 8) {
            res |= a[4] ^ ONE[4];
            res |= a[5] ^ ONE[5];
            res |= a[6] ^ ONE[6];
            /*
             * no check for a[7] (being zero) on 32-bit platforms,
             * because value of "one" takes only 7 limbs.
             */
        }
        res = is_zero(res);
    }

    return res;
}

#ifndef ECP_SM2Z256_REFERENCE_IMPLEMENTATION
// the following functions are not correct in asm
void ecp_sm2z256_point_double(P256_POINT *r, const P256_POINT *a);
void ecp_sm2z256_point_add(P256_POINT *r,
                           const P256_POINT *a, const P256_POINT *b);
void ecp_sm2z256_point_add_affine(P256_POINT *r,
                                  const P256_POINT *a,
                                  const P256_POINT_AFFINE *b);
#else
/* Point double: r = 2*a */
static void ecp_sm2z256_point_double(P256_POINT *r, const P256_POINT *a)
{
    BN_ULONG S[P256_LIMBS];
    BN_ULONG M[P256_LIMBS];
    BN_ULONG Zsqr[P256_LIMBS];
    BN_ULONG tmp0[P256_LIMBS];

    const BN_ULONG *in_x = a->X;
    const BN_ULONG *in_y = a->Y;
    const BN_ULONG *in_z = a->Z;

    BN_ULONG *res_x = r->X;
    BN_ULONG *res_y = r->Y;
    BN_ULONG *res_z = r->Z;

    ecp_sm2z256_mul_by_2(S, in_y);

    ecp_sm2z256_sqr_mont(Zsqr, in_z);

    ecp_sm2z256_sqr_mont(S, S);

    ecp_sm2z256_mul_mont(res_z, in_z, in_y);
    ecp_sm2z256_mul_by_2(res_z, res_z);

    ecp_sm2z256_add(M, in_x, Zsqr);
    ecp_sm2z256_sub(Zsqr, in_x, Zsqr);

    ecp_sm2z256_sqr_mont(res_y, S);
    ecp_sm2z256_div_by_2(res_y, res_y);

    ecp_sm2z256_mul_mont(M, M, Zsqr);
    ecp_sm2z256_mul_by_3(M, M);

    ecp_sm2z256_mul_mont(S, S, in_x);
    ecp_sm2z256_mul_by_2(tmp0, S);

    ecp_sm2z256_sqr_mont(res_x, M);

    ecp_sm2z256_sub(res_x, res_x, tmp0);
    ecp_sm2z256_sub(S, S, res_x);

    ecp_sm2z256_mul_mont(S, S, M);
    ecp_sm2z256_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
static void ecp_sm2z256_point_add(P256_POINT *r,
                                  const P256_POINT *a, const P256_POINT *b)
{
    BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
    BN_ULONG U1[P256_LIMBS], S1[P256_LIMBS];
    BN_ULONG Z1sqr[P256_LIMBS];
    BN_ULONG Z2sqr[P256_LIMBS];
    BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
    BN_ULONG Hsqr[P256_LIMBS];
    BN_ULONG Rsqr[P256_LIMBS];
    BN_ULONG Hcub[P256_LIMBS];

    BN_ULONG res_x[P256_LIMBS];
    BN_ULONG res_y[P256_LIMBS];
    BN_ULONG res_z[P256_LIMBS];

    BN_ULONG in1infty, in2infty;

    const BN_ULONG *in1_x = a->X;
    const BN_ULONG *in1_y = a->Y;
    const BN_ULONG *in1_z = a->Z;

    const BN_ULONG *in2_x = b->X;
    const BN_ULONG *in2_y = b->Y;
    const BN_ULONG *in2_z = b->Z;

    /*
     * Infinity in encoded as (,,0)
     */
    in1infty = (in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3]);
    if (P256_LIMBS == 8)
        in1infty |= (in1_z[4] | in1_z[5] | in1_z[6] | in1_z[7]);

    in2infty = (in2_z[0] | in2_z[1] | in2_z[2] | in2_z[3]);
    if (P256_LIMBS == 8)
        in2infty |= (in2_z[4] | in2_z[5] | in2_z[6] | in2_z[7]);

    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_sm2z256_sqr_mont(Z2sqr, in2_z);        /* Z2^2 */
    ecp_sm2z256_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */

    ecp_sm2z256_mul_mont(S1, Z2sqr, in2_z);    /* S1 = Z2^3 */
    ecp_sm2z256_mul_mont(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

    ecp_sm2z256_mul_mont(S1, S1, in1_y);       /* S1 = Y1*Z2^3 */
    ecp_sm2z256_mul_mont(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
    ecp_sm2z256_sub(R, S2, S1);                /* R = S2 - S1 */

    ecp_sm2z256_mul_mont(U1, in1_x, Z2sqr);    /* U1 = X1*Z2^2 */
    ecp_sm2z256_mul_mont(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
    ecp_sm2z256_sub(H, U2, U1);                /* H = U2 - U1 */

    /*
     * This should not happen during sign/ecdh, so no constant time violation
     */
    if (is_equal(U1, U2) && !in1infty && !in2infty) {
        if (is_equal(S1, S2)) {
            ecp_sm2z256_point_double(r, a);
            return;
        } else {
            memset(r, 0, sizeof(*r));
            return;
        }
    }

    ecp_sm2z256_sqr_mont(Rsqr, R);             /* R^2 */
    ecp_sm2z256_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
    ecp_sm2z256_sqr_mont(Hsqr, H);             /* H^2 */
    ecp_sm2z256_mul_mont(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
    ecp_sm2z256_mul_mont(Hcub, Hsqr, H);       /* H^3 */

    ecp_sm2z256_mul_mont(U2, U1, Hsqr);        /* U1*H^2 */
    ecp_sm2z256_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

    ecp_sm2z256_sub(res_x, Rsqr, Hsqr);
    ecp_sm2z256_sub(res_x, res_x, Hcub);

    ecp_sm2z256_sub(res_y, U2, res_x);

    ecp_sm2z256_mul_mont(S2, S1, Hcub);
    ecp_sm2z256_mul_mont(res_y, R, res_y);
    ecp_sm2z256_sub(res_y, res_y, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_z, in2_z, in1infty);

    copy_conditional(res_x, in1_x, in2infty);
    copy_conditional(res_y, in1_y, in2infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}

/* Point addition when b is known to be affine: r = a+b */
static void ecp_sm2z256_point_add_affine(P256_POINT *r,
                                         const P256_POINT *a,
                                         const P256_POINT_AFFINE *b)
{
    BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
    BN_ULONG Z1sqr[P256_LIMBS];
    BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
    BN_ULONG Hsqr[P256_LIMBS];
    BN_ULONG Rsqr[P256_LIMBS];
    BN_ULONG Hcub[P256_LIMBS];

    BN_ULONG res_x[P256_LIMBS];
    BN_ULONG res_y[P256_LIMBS];
    BN_ULONG res_z[P256_LIMBS];

    BN_ULONG in1infty, in2infty;

    const BN_ULONG *in1_x = a->X;
    const BN_ULONG *in1_y = a->Y;
    const BN_ULONG *in1_z = a->Z;

    const BN_ULONG *in2_x = b->X;
    const BN_ULONG *in2_y = b->Y;

    /*
     * Infinity in encoded as (,,0)
     */
    in1infty = (in1_z[0] | in1_z[1] | in1_z[2] | in1_z[3]);
    if (P256_LIMBS == 8)
        in1infty |= (in1_z[4] | in1_z[5] | in1_z[6] | in1_z[7]);

    /*
     * In affine representation we encode infinity as (0,0), which is
     * not on the curve, so it is OK
     */
    in2infty = (in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] |
                in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3]);
    if (P256_LIMBS == 8)
        in2infty |= (in2_x[4] | in2_x[5] | in2_x[6] | in2_x[7] |
                     in2_y[4] | in2_y[5] | in2_y[6] | in2_y[7]);

    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_sm2z256_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */

    ecp_sm2z256_mul_mont(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
    ecp_sm2z256_sub(H, U2, in1_x);             /* H = U2 - U1 */

    ecp_sm2z256_mul_mont(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

    ecp_sm2z256_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

    ecp_sm2z256_mul_mont(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
    ecp_sm2z256_sub(R, S2, in1_y);             /* R = S2 - S1 */

    ecp_sm2z256_sqr_mont(Hsqr, H);             /* H^2 */
    ecp_sm2z256_sqr_mont(Rsqr, R);             /* R^2 */
    ecp_sm2z256_mul_mont(Hcub, Hsqr, H);       /* H^3 */

    ecp_sm2z256_mul_mont(U2, in1_x, Hsqr);     /* U1*H^2 */
    ecp_sm2z256_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

    ecp_sm2z256_sub(res_x, Rsqr, Hsqr);
    ecp_sm2z256_sub(res_x, res_x, Hcub);
    ecp_sm2z256_sub(H, U2, res_x);

    ecp_sm2z256_mul_mont(S2, in1_y, Hcub);
    ecp_sm2z256_mul_mont(H, H, R);
    ecp_sm2z256_sub(res_y, H, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_x, in1_x, in2infty);

    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_y, in1_y, in2infty);

    copy_conditional(res_z, ONE, in1infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}
#endif

/* r = in^-1 mod p */
static void ecp_sm2z256_mod_inverse(BN_ULONG r[P256_LIMBS],
                                    const BN_ULONG in[P256_LIMBS])
{
    BN_ULONG a1[P256_LIMBS];
    BN_ULONG a2[P256_LIMBS];
    BN_ULONG a3[P256_LIMBS];
    BN_ULONG a4[P256_LIMBS];
    BN_ULONG a5[P256_LIMBS];
    int i;

    ecp_sm2z256_sqr_mont(a1, in);
    ecp_sm2z256_mul_mont(a2, a1, in);
    ecp_sm2z256_sqr_mont(a3, a2);
    ecp_sm2z256_sqr_mont(a3, a3);
    ecp_sm2z256_mul_mont(a3, a3, a2);
    ecp_sm2z256_sqr_mont(a4, a3);
    ecp_sm2z256_sqr_mont(a4, a4);
    ecp_sm2z256_sqr_mont(a4, a4);
    ecp_sm2z256_sqr_mont(a4, a4);
    ecp_sm2z256_mul_mont(a4, a4, a3);
    ecp_sm2z256_sqr_mont(a5, a4);
    for (i = 0; i < 7; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a5, a5, a4);
    for (i = 0; i < 8; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a5, a5, a4);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_mul_mont(a5, a5, a3);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_mul_mont(a5, a5, a2);
    ecp_sm2z256_sqr_mont(a5, a5);
    ecp_sm2z256_mul_mont(a5, a5, in);
    ecp_sm2z256_sqr_mont(a4, a5);
    ecp_sm2z256_mul_mont(a3, a4, a1);
    ecp_sm2z256_sqr_mont(a5, a4);
    for (i = 0; i < 30; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a4, a5, a4);
    ecp_sm2z256_sqr_mont(a4, a4);
    ecp_sm2z256_mul_mont(a4, a4, in);
    ecp_sm2z256_mul_mont(a3, a4, a2);
    for (i = 0; i < 33; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a2, a5, a3);
    ecp_sm2z256_mul_mont(a3, a2, a3);
    for (i = 0; i < 32; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a2, a5, a3);
    ecp_sm2z256_mul_mont(a3, a2, a3);
    ecp_sm2z256_mul_mont(a4, a2, a4);
    for (i = 0; i < 32; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a2, a5, a3);
    ecp_sm2z256_mul_mont(a3, a2, a3);
    ecp_sm2z256_mul_mont(a4, a2, a4);
    for (i = 0; i < 32; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a2, a5, a3);
    ecp_sm2z256_mul_mont(a3, a2, a3);
    ecp_sm2z256_mul_mont(a4, a2, a4);
    for (i = 0; i < 32; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(a2, a5, a3);
    ecp_sm2z256_mul_mont(a3, a2, a3);
    ecp_sm2z256_mul_mont(a4, a2, a4);
    for (i = 0; i < 32; i++) {
        ecp_sm2z256_sqr_mont(a5, a5);
    }
    ecp_sm2z256_mul_mont(r, a4, a5);
}

/*
 * ecp_sm2z256_bignum_to_field_elem copies the contents of |in| to |out| and
 * returns one if it fits. Otherwise it returns zero.
 */
static int ecp_sm2z256_bignum_to_field_elem(BN_ULONG out[P256_LIMBS],
                                                   const BIGNUM *in)
{
    return bn_copy_words(out, in, P256_LIMBS);
}

/* r = sum(scalar[i]*point[i]) */
static int ecp_sm2z256_windowed_mul(const EC_GROUP *group,
                                           P256_POINT *r,
                                           const BIGNUM **scalar,
                                           const EC_POINT **point,
                                           size_t num, BN_CTX *ctx)
{
    size_t i;
    int j, ret = 0;
    unsigned int idx;
    unsigned char (*p_str)[33] = NULL;
    const unsigned int window_size = 5;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    P256_POINT *temp;           /* place for 5 temporary points */
    const BIGNUM **scalars = NULL;
    P256_POINT (*table)[16] = NULL;
    void *table_storage = NULL;

    if ((num * 16 + 6) > CRYPTO_malloc_MAX_NELEMS(P256_POINT)
        || (table_storage =
            CRYPTO_malloc((num * 16 + 5) * sizeof(P256_POINT) + 64)) == NULL
        || (p_str =
            CRYPTO_malloc(num * 33 * sizeof(unsigned char))) == NULL
        || (scalars = CRYPTO_malloc(num * sizeof(BIGNUM *))) == NULL) {
        //ECerr(EC_F_ECP_SM2Z256_WINDOWED_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    table = (void *)ALIGNPTR(table_storage, 64);
    temp = (P256_POINT *)(table + num);

    for (i = 0; i < num; i++) {
        P256_POINT *row = table[i];

        /* This is an unusual input, we don't guarantee constant-timeness. */
        if ((BN_num_bits(scalar[i]) > 256) || BN_is_negative(scalar[i])) {
            BIGNUM *mod;

            if ((mod = BN_CTX_get(ctx)) == NULL)
                goto err;
            if (!BN_nnmod(mod, scalar[i], group->order, ctx)) {
                // //ECerr(EC_F_ECP_SM2Z256_WINDOWED_MUL, ERR_R_BN_LIB);
                goto err;
            }
            scalars[i] = mod;
        } else
        scalars[i] = scalar[i];

        for (j = 0; j < bn_get_top(scalars[i]) * BN_BYTES; j += BN_BYTES) {
            BN_ULONG d = bn_get_words(scalars[i])[j / BN_BYTES];

            p_str[i][j + 0] = (unsigned char)d;
            p_str[i][j + 1] = (unsigned char)(d >> 8);
            p_str[i][j + 2] = (unsigned char)(d >> 16);
            p_str[i][j + 3] = (unsigned char)(d >>= 24);
            if (BN_BYTES == 8) {
                d >>= 8;
                p_str[i][j + 4] = (unsigned char)d;
                p_str[i][j + 5] = (unsigned char)(d >> 8);
                p_str[i][j + 6] = (unsigned char)(d >> 16);
                p_str[i][j + 7] = (unsigned char)(d >> 24);
            }
        }
        for (; j < 33; j++)
            p_str[i][j] = 0;

        if (!ecp_sm2z256_bignum_to_field_elem(temp[0].X, point[i]->X)
            || !ecp_sm2z256_bignum_to_field_elem(temp[0].Y, point[i]->Y)
            || !ecp_sm2z256_bignum_to_field_elem(temp[0].Z, point[i]->Z)) {
            // //ECerr(EC_F_ECP_SM2Z256_WINDOWED_MUL,
            //       EC_R_COORDINATES_OUT_OF_RANGE);
            goto err;
        }

        /*
         * row[0] is implicitly (0,0,0) (the point at infinity), therefore it
         * is not stored. All other values are actually stored with an offset
         * of -1 in table.
         */

        ecp_sm2z256_scatter_w5  (row, &temp[0], 1);
        ecp_sm2z256_point_double(&temp[1], &temp[0]);              /*1+1=2  */
        ecp_sm2z256_scatter_w5  (row, &temp[1], 2);
        ecp_sm2z256_point_add   (&temp[2], &temp[1], &temp[0]);    /*2+1=3  */
        ecp_sm2z256_scatter_w5  (row, &temp[2], 3);
        ecp_sm2z256_point_double(&temp[1], &temp[1]);              /*2*2=4  */
        ecp_sm2z256_scatter_w5  (row, &temp[1], 4);
        ecp_sm2z256_point_double(&temp[2], &temp[2]);              /*2*3=6  */
        ecp_sm2z256_scatter_w5  (row, &temp[2], 6);
        ecp_sm2z256_point_add   (&temp[3], &temp[1], &temp[0]);    /*4+1=5  */
        ecp_sm2z256_scatter_w5  (row, &temp[3], 5);
        ecp_sm2z256_point_add   (&temp[4], &temp[2], &temp[0]);    /*6+1=7  */
        ecp_sm2z256_scatter_w5  (row, &temp[4], 7);
        ecp_sm2z256_point_double(&temp[1], &temp[1]);              /*2*4=8  */
        ecp_sm2z256_scatter_w5  (row, &temp[1], 8);
        ecp_sm2z256_point_double(&temp[2], &temp[2]);              /*2*6=12 */
        ecp_sm2z256_scatter_w5  (row, &temp[2], 12);
        ecp_sm2z256_point_double(&temp[3], &temp[3]);              /*2*5=10 */
        ecp_sm2z256_scatter_w5  (row, &temp[3], 10);
        ecp_sm2z256_point_double(&temp[4], &temp[4]);              /*2*7=14 */
        ecp_sm2z256_scatter_w5  (row, &temp[4], 14);
        ecp_sm2z256_point_add   (&temp[2], &temp[2], &temp[0]);    /*12+1=13*/
        ecp_sm2z256_scatter_w5  (row, &temp[2], 13);
        ecp_sm2z256_point_add   (&temp[3], &temp[3], &temp[0]);    /*10+1=11*/
        ecp_sm2z256_scatter_w5  (row, &temp[3], 11);
        ecp_sm2z256_point_add   (&temp[4], &temp[4], &temp[0]);    /*14+1=15*/
        ecp_sm2z256_scatter_w5  (row, &temp[4], 15);
        ecp_sm2z256_point_add   (&temp[2], &temp[1], &temp[0]);    /*8+1=9  */
        ecp_sm2z256_scatter_w5  (row, &temp[2], 9);
        ecp_sm2z256_point_double(&temp[1], &temp[1]);              /*2*8=16 */
        ecp_sm2z256_scatter_w5  (row, &temp[1], 16);
    }

    idx = 255;

    wvalue = p_str[0][(idx - 1) / 8];
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;

    /*
     * We gather to temp[0], because we know it's position relative
     * to table
     */
    ecp_sm2z256_gather_w5(&temp[0], table[0], _booth_recode_w5(wvalue) >> 1);
    memcpy(r, &temp[0], sizeof(temp[0]));

    while (idx >= 5) {
        for (i = (idx == 255 ? 1 : 0); i < num; i++) {
            unsigned int off = (idx - 1) / 8;

            wvalue = p_str[i][off] | p_str[i][off + 1] << 8;
            wvalue = (wvalue >> ((idx - 1) % 8)) & mask;

            wvalue = _booth_recode_w5(wvalue);

            ecp_sm2z256_gather_w5(&temp[0], table[i], wvalue >> 1);

            ecp_sm2z256_neg(temp[1].Y, temp[0].Y);
            copy_conditional(temp[0].Y, temp[1].Y, (wvalue & 1));

            ecp_sm2z256_point_add(r, r, &temp[0]);
        }

        idx -= window_size;

        ecp_sm2z256_point_double(r, r);
        ecp_sm2z256_point_double(r, r);
        ecp_sm2z256_point_double(r, r);
        ecp_sm2z256_point_double(r, r);
        ecp_sm2z256_point_double(r, r);
    }

    /* Final window */
    for (i = 0; i < num; i++) {
        wvalue = p_str[i][0];
        wvalue = (wvalue << 1) & mask;

        wvalue = _booth_recode_w5(wvalue);

        ecp_sm2z256_gather_w5(&temp[0], table[i], wvalue >> 1);

        ecp_sm2z256_neg(temp[1].Y, temp[0].Y);
        copy_conditional(temp[0].Y, temp[1].Y, wvalue & 1);

        ecp_sm2z256_point_add(r, r, &temp[0]);
    }

    ret = GML_OK;
 err:
    CRYPTO_free(table_storage);
    CRYPTO_free(p_str);
    CRYPTO_free((void*)scalars);
    return ret;
}

/* Coordinates of G, for which we have precomputed tables */
const static BN_ULONG def_xG[P256_LIMBS] = {
     TOBN(0x61328990, 0xf418029e), TOBN(0x3e7981ed, 0xdca6c050),
     TOBN(0xd6a1ed99, 0xac24c3c3), TOBN(0x91167a5e, 0xe1c13b05)
};

const static BN_ULONG def_yG[P256_LIMBS] = {
     TOBN(0xc1354e59, 0x3c2d0ddd), TOBN(0xc1f5e578, 0x8d3295fa),
     TOBN(0x8d4cfb06, 0x6e2a48f8), TOBN(0x63cd65d4, 0x81d735bd)
};

/*
 * ecp_sm2z256_is_affine_G returns one if |generator| is the standard, P-256
 * generator.
 */
static int ecp_sm2z256_is_affine_G(const EC_POINT *generator)
{
    return (bn_get_top(generator->X) == P256_LIMBS) &&
        (bn_get_top(generator->Y) == P256_LIMBS) &&
        is_equal(bn_get_words(generator->X), def_xG) &&
        is_equal(bn_get_words(generator->Y), def_yG) &&
        is_one(generator->Z);
}

static int ecp_sm2z256_mult_precompute(EC_GROUP *group, BN_CTX *ctx)
{
    /*
     * We precompute a table for a Booth encoded exponent (wNAF) based
     * computation. Each table holds 64 values for safe access, with an
     * implicit value of infinity at index zero. We use window of size 7, and
     * therefore require ceil(256/7) = 37 tables.
     */
    // const BIGNUM *order;
    EC_POINT *P = NULL, *T = NULL;
    const EC_POINT *generator;
    // SM2Z256_PRE_COMP *pre_comp;
    BN_CTX *new_ctx = NULL;
    int ret = GML_ERROR;
    // size_t w;

    // PRECOMP256_ROW *preComputedTable = NULL;
    unsigned char *precomp_storage = NULL;

    /* if there is an old SM2Z256_PRE_COMP object, throw it away */
    EC_pre_comp_free(group);
    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        // //ECerr(EC_F_ECP_SM2Z256_MULT_PRECOMPUTE, EC_R_UNDEFINED_GENERATOR);
        return 0;
    }

    if (ecp_sm2z256_is_affine_G(generator)) {
        /*
         * No need to calculate tables for the standard generator because we
         * have them statically.
         */
        return 1;
    }

    // if ((pre_comp = ecp_sm2z256_pre_comp_new(group)) == NULL)
    //     return 0;

    // if (ctx == NULL) {
    //     ctx = new_ctx = BN_CTX_new();
    //     if (ctx == NULL)
    //         goto err;
    // }

    // BN_CTX_start(ctx);

    // order = EC_GROUP_get0_order(group);
    // if (order == NULL)
    //     goto err;

    // if (BN_is_zero(order)) {
    //     //ECerr(EC_F_ECP_SM2Z256_MULT_PRECOMPUTE, EC_R_UNKNOWN_ORDER);
    //     goto err;
    // }

    // w = 7;

    // if ((precomp_storage =
    //      CRYPTO_malloc(37 * 64 * sizeof(P256_POINT_AFFINE) + 64)) == NULL) {
    //     //ECerr(EC_F_ECP_SM2Z256_MULT_PRECOMPUTE, ERR_R_MALLOC_FAILURE);
    //     goto err;
    // }

    // preComputedTable = (void *)ALIGNPTR(precomp_storage, 64);

    // P = EC_POINT_new(group);
    // T = EC_POINT_new(group);
    // if (P == NULL || T == NULL)
    //     goto err;

    // /*
    //  * The zero entry is implicitly infinity, and we skip it, storing other
    //  * values with -1 offset.
    //  */
    // if (!EC_POINT_copy(T, generator))
    //     goto err;

    // for (k = 0; k < 64; k++) {
    //     if (!EC_POINT_copy(P, T))
    //         goto err;
    //     for (j = 0; j < 37; j++) {
    //         P256_POINT_AFFINE temp;
    //         /*
    //          * It would be faster to use EC_POINTs_make_affine and
    //          * make multiple points affine at the same time.
    //          */
    //         if (!EC_POINT_make_affine(group, P, ctx))
    //             goto err;
    //         if (!ecp_sm2z256_bignum_to_field_elem(temp.X, P->X) ||
    //             !ecp_sm2z256_bignum_to_field_elem(temp.Y, P->Y)) {
    //             //ECerr(EC_F_ECP_SM2Z256_MULT_PRECOMPUTE,
    //                   EC_R_COORDINATES_OUT_OF_RANGE);
    //             goto err;
    //         }
    //         ecp_sm2z256_scatter_w7(preComputedTable[j], &temp, k);
    //         for (i = 0; i < 7; i++) {
    //             if (!EC_POINT_dbl(group, P, P, ctx))
    //                 goto err;
    //         }
    //     }
    //     if (!EC_POINT_add(group, T, T, generator, ctx))
    //         goto err;
    // }

    // pre_comp->group = group;
    // pre_comp->w = w;
    // pre_comp->precomp = preComputedTable;
    // pre_comp->precomp_storage = precomp_storage;
    // precomp_storage = NULL;
    // SETPRECOMP(group, sm2z256, pre_comp);
    // pre_comp = NULL;
    // ret = GML_OK;

//  err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);

    // EC_sm2z256_pre_comp_free(pre_comp);
    CRYPTO_free(precomp_storage);
    EC_POINT_free(P);
    EC_POINT_free(T);
    return ret;
}

static int ecp_sm2z256_point_mult_precompute_table(const EC_GROUP *group, void **pre, EC_POINT *point, BN_CTX *ctx)
{
    /*
     * We precompute a table for a Booth encoded exponent (wNAF) based
     * computation. Each table holds 64 values for safe access, with an
     * implicit value of infinity at index zero. We use window of size 7, and
     * therefore require ceil(256/7) = 37 tables.
     */
    EC_POINT *P = NULL, *T = NULL;
    SM2Z256_PRE_COMP *pre_comp;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order = NULL;
    int ret = GML_ERROR;
    size_t w, i, j, k;

    PRECOMP256_ROW *preComputedTable = NULL;
    unsigned char *precomp_storage = NULL;

    /* if there is an old SM2Z256_PRE_COMP object, throw it away */
    if (group == NULL)
        return GML_ERROR;

    pre_comp = (SM2Z256_PRE_COMP*)*pre;
    if (pre_comp != NULL)
        EC_sm2z256_pre_comp_free(pre_comp);
    if ((pre_comp = ecp_sm2z256_pre_comp_new(group)) == NULL)
        return GML_ERROR;

    if (ctx == NULL) {
        ctx = bn_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);

    order = EC_GROUP_get0_order(group);
    if (order == NULL)
        goto err;

    if (BN_is_zero(order))
        goto err;

    w = 7;

    if ((precomp_storage = CRYPTO_malloc(37 * 64 * sizeof(P256_POINT_AFFINE) + 64)) == NULL)
        goto err;

    preComputedTable = (void *)ALIGNPTR(precomp_storage, 64);

    P = EC_POINT_new(group);
    T = EC_POINT_new(group);
    if (P == NULL || T == NULL)
        goto err;

    /*
     * The zero entry is implicitly infinity, and we skip it, storing other
     * values with -1 offset.
     */
    if (!EC_POINT_copy(T, point))
        goto err;

    for (k = 0; k < 64; k++) {
        if (!EC_POINT_copy(P, T))
            goto err;
        for (j = 0; j < 37; j++) {
            P256_POINT_AFFINE temp;
            /*
             * It would be faster to use EC_POINTs_make_affine and
             * make multiple points affine at the same time.
             */
            if (!EC_POINT_make_affine(group, P, ctx))
                goto err;
            if (!ecp_sm2z256_bignum_to_field_elem(temp.X, P->X) ||
                !ecp_sm2z256_bignum_to_field_elem(temp.Y, P->Y)) {
                goto err;
            }
            ecp_sm2z256_scatter_w7(preComputedTable[j], &temp, k);
            for (i = 0; i < 7; i++) {
                if (!EC_POINT_dbl(group, P, P, ctx))
                    goto err;
            }
        }
        if (!EC_POINT_add(group, T, T, point, ctx))
            goto err;
    }

    pre_comp->group = group;
    pre_comp->w = w;
    pre_comp->precomp = preComputedTable;
    pre_comp->precomp_storage = precomp_storage;
    *pre = pre_comp;
    precomp_storage = NULL;
    pre_comp = NULL;
    ret = GML_OK;

    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(P);
    EC_POINT_free(T);
    return ret;
err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(bn_ctx);

    EC_sm2z256_pre_comp_free(pre_comp);
    EC_POINT_free(P);
    EC_POINT_free(T);
    return ret;
}

/*
 * Note that by default ECP_NISTZ256_AVX2 is undefined. While it's great
 * code processing 4 points in parallel, corresponding serial operation
 * is several times slower, because it uses 29x29=58-bit multiplication
 * as opposite to 64x64=128-bit in integer-only scalar case. As result
 * it doesn't provide *significant* performance improvement. Note that
 * just defining ECP_NISTZ256_AVX2 is not sufficient to make it work,
 * you'd need to compile even asm/ecp_nistz256-avx.pl module.
 */
#if defined(ECP_NISTZ256_AVX2)
# if !(defined(__x86_64) || defined(__x86_64__) || \
       defined(_M_AMD64) || defined(_MX64)) || \
     !(defined(__GNUC__) || defined(_MSC_VER)) /* this is for ALIGN32 */
#  undef ECP_NISTZ256_AVX2
# else
/* Constant time access, loading four values, from four consecutive tables */
void ecp_sm2z256_avx2_multi_gather_w7(void *result, const void *in,
                                      int index0, int index1, int index2,
                                      int index3);
void ecp_sm2z256_avx2_transpose_convert(void *RESULTx4, const void *in);
void ecp_sm2z256_avx2_convert_transpose_back(void *result, const void *Ax4);
void ecp_sm2z256_avx2_point_add_affine_x4(void *RESULTx4, const void *Ax4,
                                          const void *Bx4);
void ecp_sm2z256_avx2_point_add_affines_x4(void *RESULTx4, const void *Ax4,
                                           const void *Bx4);
void ecp_sm2z256_avx2_to_mont(void *RESULTx4, const void *Ax4);
void ecp_sm2z256_avx2_from_mont(void *RESULTx4, const void *Ax4);
void ecp_sm2z256_avx2_set1(void *RESULTx4);
int ecp_sm2z_avx2_eligible(void);

static void booth_recode_w7(unsigned char *sign,
                            unsigned char *digit, unsigned char in)
{
    unsigned char s, d;

    s = ~((in >> 7) - 1);
    d = (1 << 8) - in - 1;
    d = (d & s) | (in & ~s);
    d = (d >> 1) + (d & 1);

    *sign = s & 1;
    *digit = d;
}

/*
 * ecp_sm2z256_avx2_mul_g performs multiplication by G, using only the
 * precomputed table. It does 4 affine point additions in parallel,
 * significantly speeding up point multiplication for a fixed value.
 */
static void ecp_sm2z256_avx2_mul_g(P256_POINT *r,
                                   unsigned char p_str[33],
                                   const P256_POINT_AFFINE(*preComputedTable)[64])
{
    const unsigned int window_size = 7;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    /* Using 4 windows at a time */
    unsigned char sign0, digit0;
    unsigned char sign1, digit1;
    unsigned char sign2, digit2;
    unsigned char sign3, digit3;
    unsigned int idx = 0;
    BN_ULONG tmp[P256_LIMBS];
    int i;

    ALIGN32 BN_ULONG aX4[4 * 9 * 3] = { 0 };
    ALIGN32 BN_ULONG bX4[4 * 9 * 2] = { 0 };
    ALIGN32 P256_POINT_AFFINE point_arr[4];
    ALIGN32 P256_POINT res_point_arr[4];

    /* Initial four windows */
    wvalue = *((u16 *) & p_str[0]);
    wvalue = (wvalue << 1) & mask;
    idx += window_size;
    booth_recode_w7(&sign0, &digit0, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign1, &digit1, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign2, &digit2, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign3, &digit3, wvalue);

    ecp_sm2z256_avx2_multi_gather_w7(point_arr, preComputedTable[0],
                                     digit0, digit1, digit2, digit3);

    ecp_sm2z256_neg(tmp, point_arr[0].Y);
    copy_conditional(point_arr[0].Y, tmp, sign0);
    ecp_sm2z256_neg(tmp, point_arr[1].Y);
    copy_conditional(point_arr[1].Y, tmp, sign1);
    ecp_sm2z256_neg(tmp, point_arr[2].Y);
    copy_conditional(point_arr[2].Y, tmp, sign2);
    ecp_sm2z256_neg(tmp, point_arr[3].Y);
    copy_conditional(point_arr[3].Y, tmp, sign3);

    ecp_sm2z256_avx2_transpose_convert(aX4, point_arr);
    ecp_sm2z256_avx2_to_mont(aX4, aX4);
    ecp_sm2z256_avx2_to_mont(&aX4[4 * 9], &aX4[4 * 9]);
    ecp_sm2z256_avx2_set1(&aX4[4 * 9 * 2]);

    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign0, &digit0, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign1, &digit1, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign2, &digit2, wvalue);
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    idx += window_size;
    booth_recode_w7(&sign3, &digit3, wvalue);

    ecp_sm2z256_avx2_multi_gather_w7(point_arr, preComputedTable[4 * 1],
                                     digit0, digit1, digit2, digit3);

    ecp_sm2z256_neg(tmp, point_arr[0].Y);
    copy_conditional(point_arr[0].Y, tmp, sign0);
    ecp_sm2z256_neg(tmp, point_arr[1].Y);
    copy_conditional(point_arr[1].Y, tmp, sign1);
    ecp_sm2z256_neg(tmp, point_arr[2].Y);
    copy_conditional(point_arr[2].Y, tmp, sign2);
    ecp_sm2z256_neg(tmp, point_arr[3].Y);
    copy_conditional(point_arr[3].Y, tmp, sign3);

    ecp_sm2z256_avx2_transpose_convert(bX4, point_arr);
    ecp_sm2z256_avx2_to_mont(bX4, bX4);
    ecp_sm2z256_avx2_to_mont(&bX4[4 * 9], &bX4[4 * 9]);
    /* Optimized when both inputs are affine */
    ecp_sm2z256_avx2_point_add_affines_x4(aX4, aX4, bX4);

    for (i = 2; i < 9; i++) {
        wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += window_size;
        booth_recode_w7(&sign0, &digit0, wvalue);
        wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += window_size;
        booth_recode_w7(&sign1, &digit1, wvalue);
        wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += window_size;
        booth_recode_w7(&sign2, &digit2, wvalue);
        wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
        wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
        idx += window_size;
        booth_recode_w7(&sign3, &digit3, wvalue);

        ecp_sm2z256_avx2_multi_gather_w7(point_arr,
                                         preComputedTable[4 * i],
                                         digit0, digit1, digit2, digit3);

        ecp_sm2z256_neg(tmp, point_arr[0].Y);
        copy_conditional(point_arr[0].Y, tmp, sign0);
        ecp_sm2z256_neg(tmp, point_arr[1].Y);
        copy_conditional(point_arr[1].Y, tmp, sign1);
        ecp_sm2z256_neg(tmp, point_arr[2].Y);
        copy_conditional(point_arr[2].Y, tmp, sign2);
        ecp_sm2z256_neg(tmp, point_arr[3].Y);
        copy_conditional(point_arr[3].Y, tmp, sign3);

        ecp_sm2z256_avx2_transpose_convert(bX4, point_arr);
        ecp_sm2z256_avx2_to_mont(bX4, bX4);
        ecp_sm2z256_avx2_to_mont(&bX4[4 * 9], &bX4[4 * 9]);

        ecp_sm2z256_avx2_point_add_affine_x4(aX4, aX4, bX4);
    }

    ecp_sm2z256_avx2_from_mont(&aX4[4 * 9 * 0], &aX4[4 * 9 * 0]);
    ecp_sm2z256_avx2_from_mont(&aX4[4 * 9 * 1], &aX4[4 * 9 * 1]);
    ecp_sm2z256_avx2_from_mont(&aX4[4 * 9 * 2], &aX4[4 * 9 * 2]);

    ecp_sm2z256_avx2_convert_transpose_back(res_point_arr, aX4);
    /* Last window is performed serially */
    wvalue = *((u16 *) & p_str[(idx - 1) / 8]);
    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
    booth_recode_w7(&sign0, &digit0, wvalue);
    ecp_sm2z256_gather_w7((P256_POINT_AFFINE *)r,
                          preComputedTable[36], digit0);
    ecp_sm2z256_neg(tmp, r->Y);
    copy_conditional(r->Y, tmp, sign0);
    memcpy(r->Z, ONE, sizeof(ONE));
    /* Sum the four windows */
    ecp_sm2z256_point_add(r, r, &res_point_arr[0]);
    ecp_sm2z256_point_add(r, r, &res_point_arr[1]);
    ecp_sm2z256_point_add(r, r, &res_point_arr[2]);
    ecp_sm2z256_point_add(r, r, &res_point_arr[3]);
}
# endif
#endif

// static int ecp_sm2z256_set_from_affine(EC_POINT *out, const EC_GROUP *group,
//                                               const P256_POINT_AFFINE *in,
//                                               BN_CTX *ctx)
// {
//     BIGNUM *x, *y;
//     BN_ULONG d_x[P256_LIMBS], d_y[P256_LIMBS];
//     int ret = GML_ERROR;

//     x = BN_new();
//     if (x == NULL)
//         return 0;
//     y = BN_new();
//     if (y == NULL) {
//         BN_free(x);
//         return 0;
//     }
//     memcpy(d_x, in->X, sizeof(d_x));
//     bn_set_static_words(x, d_x, P256_LIMBS);

//     memcpy(d_y, in->Y, sizeof(d_y));
//     bn_set_static_words(y, d_y, P256_LIMBS);

//     ret = EC_POINT_set_affine_coordinates_GFp(group, out, x, y, ctx);

//     BN_free(x);
//     BN_free(y);

//     return ret;
// }

/* r = scalar*G + sum(scalars[i]*points[i]) */
static int ecp_sm2z256_points_mul(const EC_GROUP *group,
                                         EC_POINT *r,
                                         const BIGNUM *scalar,
                                         size_t num,
                                         const EC_POINT *points[],
                                         const BIGNUM *scalars[], BN_CTX *ctx)
{
    int i = 0, ret = 0, p_is_infinity = 0;
    size_t j;
    unsigned char p_str[33] = { 0 };
    const PRECOMP256_ROW *preComputedTable = NULL;
    // const SM2Z256_PRE_COMP *pre_comp = NULL;
    const EC_POINT *generator = NULL;
    BN_CTX *new_ctx = NULL;
    // const BIGNUM **new_scalars = NULL;
    // const EC_POINT **new_points = NULL;
    unsigned int idx = 0;
    const unsigned int window_size = 7;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    ALIGN32 union {
        P256_POINT p;
        P256_POINT_AFFINE a;
    } t, p;
    BIGNUM *tmp_scalar;

    if ((num + 1) == 0 || (num + 1) > CRYPTO_malloc_MAX_NELEMS(void *)) {
        // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (group->meth != r->meth) {
        // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    if ((scalar == NULL) && (num == 0))
        return EC_POINT_set_to_infinity(group, r);

    for (j = 0; j < num; j++) {
        if (group->meth != points[j]->meth) {
            // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);

    if (scalar) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, EC_R_UNDEFINED_GENERATOR);
            // goto err;
        }

        if (preComputedTable == NULL && ecp_sm2z256_is_affine_G(generator)) {
            /*
             * If there is no precomputed data, but the generator is the
             * default, a hardcoded table of precomputed data is used. This
             * is because applications, such as Apache, do not use
             * EC_KEY_precompute_mult.
             */
            preComputedTable = ecp_sm2z256_precomputed;
        }

        if (preComputedTable) {
            if ((BN_num_bits(scalar) > 256)
                || BN_is_negative(scalar)) {
                if ((tmp_scalar = BN_CTX_get(ctx)) == NULL)
                    goto err;

                if (!BN_nnmod(tmp_scalar, scalar, group->order, ctx)) {
                    // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, ERR_R_BN_LIB);
                    goto err;
                }
                scalar = tmp_scalar;
            }

            for (i = 0; i < bn_get_top(scalar) * BN_BYTES; i += BN_BYTES) {
                BN_ULONG d = bn_get_words(scalar)[i / BN_BYTES];

                p_str[i + 0] = (unsigned char)d;
                p_str[i + 1] = (unsigned char)(d >> 8);
                p_str[i + 2] = (unsigned char)(d >> 16);
                p_str[i + 3] = (unsigned char)(d >>= 24);
                if (BN_BYTES == 8) {
                    d >>= 8;
                    p_str[i + 4] = (unsigned char)d;
                    p_str[i + 5] = (unsigned char)(d >> 8);
                    p_str[i + 6] = (unsigned char)(d >> 16);
                    p_str[i + 7] = (unsigned char)(d >> 24);
                }
            }

            for (; i < 33; i++)
                p_str[i] = 0;

#if defined(ECP_SM2Z256_AVX2)
printf("%s %d: ECP_SM2Z256_AVX2 defined\n", __FILE__, __LINE__);
            if (ecp_sm2z_avx2_eligible()) {
                ecp_sm2z256_avx2_mul_g(&p.p, p_str, preComputedTable);
            } else
#endif
            {
                BN_ULONG infty;

                /* First window */
                wvalue = (p_str[0] << 1) & mask;
                idx += window_size;

                wvalue = _booth_recode_w7(wvalue);

                ecp_sm2z256_gather_w7(&p.a, preComputedTable[0],
                                      wvalue >> 1);

                ecp_sm2z256_neg(p.p.Z, p.p.Y);
                copy_conditional(p.p.Y, p.p.Z, wvalue & 1);

                /*
                 * Since affine infinity is encoded as (0,0) and
                 * Jacobian ias (,,0), we need to harmonize them
                 * by assigning "one" or zero to Z.
                 */
                infty = (p.p.X[0] | p.p.X[1] | p.p.X[2] | p.p.X[3] |
                         p.p.Y[0] | p.p.Y[1] | p.p.Y[2] | p.p.Y[3]);
                if (P256_LIMBS == 8)
                    infty |= (p.p.X[4] | p.p.X[5] | p.p.X[6] | p.p.X[7] |
                              p.p.Y[4] | p.p.Y[5] | p.p.Y[6] | p.p.Y[7]);

                infty = 0 - is_zero(infty);
                infty = ~infty;

                p.p.Z[0] = ONE[0] & infty;
                p.p.Z[1] = ONE[1] & infty;
                p.p.Z[2] = ONE[2] & infty;
                p.p.Z[3] = ONE[3] & infty;
                if (P256_LIMBS == 8) {
                    p.p.Z[4] = ONE[4] & infty;
                    p.p.Z[5] = ONE[5] & infty;
                    p.p.Z[6] = ONE[6] & infty;
                    p.p.Z[7] = ONE[7] & infty;
                }

                for (i = 1; i < 37; i++) {
                    unsigned int off = (idx - 1) / 8;
                    wvalue = p_str[off] | p_str[off + 1] << 8;
                    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
                    idx += window_size;

                    wvalue = _booth_recode_w7(wvalue);

                    ecp_sm2z256_gather_w7(&t.a,
                                          preComputedTable[i], wvalue >> 1);

                    ecp_sm2z256_neg(t.p.Z, t.a.Y);
                    copy_conditional(t.a.Y, t.p.Z, wvalue & 1);
                    ecp_sm2z256_point_add_affine(&p.p, &p.p, &t.a);
                }
            }
        } else {
            p_is_infinity = 1;
        }
    } else
        p_is_infinity = 1;

    // if (no_precomp_for_generator) {
    //     /*
    //      * Without a precomputed table for the generator, it has to be
    //      * handled like a normal point.
    //      */
    //     new_scalars = CRYPTO_malloc((num + 1) * sizeof(BIGNUM *));
    //     if (new_scalars == NULL) {
    //         // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, ERR_R_MALLOC_FAILURE);
    //         goto err;
    //     }

    //     new_points = CRYPTO_malloc((num + 1) * sizeof(EC_POINT *));
    //     if (new_points == NULL) {
    //         // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, ERR_R_MALLOC_FAILURE);
    //         goto err;
    //     }

    //     memcpy(new_scalars, scalars, num * sizeof(BIGNUM *));
    //     new_scalars[num] = scalar;
    //     memcpy(new_points, points, num * sizeof(EC_POINT *));
    //     new_points[num] = generator;

    //     scalars = new_scalars;
    //     points = new_points;
    //     num++;
    // }

    if (num) {
        P256_POINT *out = &t.p;
        if (p_is_infinity)
            out = &p.p;

        if (!ecp_sm2z256_windowed_mul(group, out, scalars, points, num, ctx))
            goto err;

        if (!p_is_infinity)
            ecp_sm2z256_point_add(&p.p, &p.p, out);
    }

    /* Not constant-time, but we're only operating on the public output. */
    if (!bn_set_words(r->X, p.p.X, P256_LIMBS) ||
        !bn_set_words(r->Y, p.p.Y, P256_LIMBS) ||
        !bn_set_words(r->Z, p.p.Z, P256_LIMBS)) {
        goto err;
    }
    r->Z_is_one = is_one(r->Z) & 1;

    ret = GML_OK;

err:
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

/* r = scalar*pubkey */
static int ecp_sm2z256_mul_with_precomp(const EC_GROUP *group,
                                        EC_POINT *r,
                                        const BIGNUM *scalar,
                                        void *table,
                                        BN_CTX *ctx)
{
    int i = 0, ret = 0, p_is_infinity = 0;
    unsigned char p_str[33] = { 0 };
    const PRECOMP256_ROW *preComputedTable = NULL;
    // const SM2Z256_PRE_COMP *pre_comp = NULL;
    BN_CTX *new_ctx = NULL;
    unsigned int idx = 0;
    const unsigned int window_size = 7;
    const unsigned int mask = (1 << (window_size + 1)) - 1;
    unsigned int wvalue;
    ALIGN32 union {
        P256_POINT p;
        P256_POINT_AFFINE a;
    } t, p;
    BIGNUM *tmp_scalar;

    if (group->meth != r->meth) {
        // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return GML_ERROR;
    }

    if (table == NULL)
        return GML_ERROR;

    if (scalar == NULL)
        return EC_POINT_set_to_infinity(group, r);

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);

    if (scalar) {
        preComputedTable = ((SM2Z256_PRE_COMP*)table)->precomp;

        if (preComputedTable) {
            if ((BN_num_bits(scalar) > 256)
                || BN_is_negative(scalar)) {
                if ((tmp_scalar = BN_CTX_get(ctx)) == NULL)
                    goto err;

                if (!BN_nnmod(tmp_scalar, scalar, group->order, ctx)) {
                    // //ECerr(EC_F_ECP_SM2Z256_POINTS_MUL, ERR_R_BN_LIB);
                    goto err;
                }
                scalar = tmp_scalar;
            }

            for (i = 0; i < bn_get_top(scalar) * BN_BYTES; i += BN_BYTES) {
                BN_ULONG d = bn_get_words(scalar)[i / BN_BYTES];

                p_str[i + 0] = (unsigned char)d;
                p_str[i + 1] = (unsigned char)(d >> 8);
                p_str[i + 2] = (unsigned char)(d >> 16);
                p_str[i + 3] = (unsigned char)(d >>= 24);
                if (BN_BYTES == 8) {
                    d >>= 8;
                    p_str[i + 4] = (unsigned char)d;
                    p_str[i + 5] = (unsigned char)(d >> 8);
                    p_str[i + 6] = (unsigned char)(d >> 16);
                    p_str[i + 7] = (unsigned char)(d >> 24);
                }
            }

            for (; i < 33; i++)
                p_str[i] = 0;

#if defined(ECP_SM2Z256_AVX2)
printf("%s %d: ECP_SM2Z256_AVX2 defined\n", __FILE__, __LINE__);
            if (ecp_sm2z_avx2_eligible()) {
                ecp_sm2z256_avx2_mul_g(&p.p, p_str, preComputedTable);
            } else
#endif
            {
                BN_ULONG infty;

                /* First window */
                wvalue = (p_str[0] << 1) & mask;
                idx += window_size;

                wvalue = _booth_recode_w7(wvalue);

                ecp_sm2z256_gather_w7(&p.a, preComputedTable[0],
                                      wvalue >> 1);

                ecp_sm2z256_neg(p.p.Z, p.p.Y);
                copy_conditional(p.p.Y, p.p.Z, wvalue & 1);

                /*
                 * Since affine infinity is encoded as (0,0) and
                 * Jacobian ias (,,0), we need to harmonize them
                 * by assigning "one" or zero to Z.
                 */
                infty = (p.p.X[0] | p.p.X[1] | p.p.X[2] | p.p.X[3] |
                         p.p.Y[0] | p.p.Y[1] | p.p.Y[2] | p.p.Y[3]);
                if (P256_LIMBS == 8)
                    infty |= (p.p.X[4] | p.p.X[5] | p.p.X[6] | p.p.X[7] |
                              p.p.Y[4] | p.p.Y[5] | p.p.Y[6] | p.p.Y[7]);

                infty = 0 - is_zero(infty);
                infty = ~infty;

                p.p.Z[0] = ONE[0] & infty;
                p.p.Z[1] = ONE[1] & infty;
                p.p.Z[2] = ONE[2] & infty;
                p.p.Z[3] = ONE[3] & infty;
                if (P256_LIMBS == 8) {
                    p.p.Z[4] = ONE[4] & infty;
                    p.p.Z[5] = ONE[5] & infty;
                    p.p.Z[6] = ONE[6] & infty;
                    p.p.Z[7] = ONE[7] & infty;
                }

                for (i = 1; i < 37; i++) {
                    unsigned int off = (idx - 1) / 8;
                    wvalue = p_str[off] | p_str[off + 1] << 8;
                    wvalue = (wvalue >> ((idx - 1) % 8)) & mask;
                    idx += window_size;

                    wvalue = _booth_recode_w7(wvalue);

                    ecp_sm2z256_gather_w7(&t.a,
                                          preComputedTable[i], wvalue >> 1);

                    ecp_sm2z256_neg(t.p.Z, t.a.Y);
                    copy_conditional(t.a.Y, t.p.Z, wvalue & 1);
                    ecp_sm2z256_point_add_affine(&p.p, &p.p, &t.a);
                }
            }
        } else {
            p_is_infinity = 1;
            // no_precomp_for_generator = 1;
        }
    } else
        p_is_infinity = 1;

    /* Not constant-time, but we're only operating on the public output. */
    if (!bn_set_words(r->X, p.p.X, P256_LIMBS) ||
        !bn_set_words(r->Y, p.p.Y, P256_LIMBS) ||
        !bn_set_words(r->Z, p.p.Z, P256_LIMBS)) {
        goto err;
    }
    r->Z_is_one = is_one(r->Z) & 1;

    ret = GML_OK;

err:
    if (ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

static int ecp_sm2z256_get_affine(const EC_GROUP *group,
                                         const EC_POINT *point,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    BN_ULONG z_inv2[P256_LIMBS];
    BN_ULONG z_inv3[P256_LIMBS];
    BN_ULONG x_aff[P256_LIMBS];
    BN_ULONG y_aff[P256_LIMBS];
    BN_ULONG point_x[P256_LIMBS], point_y[P256_LIMBS], point_z[P256_LIMBS];
    BN_ULONG x_ret[P256_LIMBS], y_ret[P256_LIMBS];

    if (EC_POINT_is_at_infinity(group, point)) {
        // //ECerr(EC_F_ECP_SM2Z256_GET_AFFINE, EC_R_POINT_AT_INFINITY);
        return 0;
    }

    if (!ecp_sm2z256_bignum_to_field_elem(point_x, point->X) ||
        !ecp_sm2z256_bignum_to_field_elem(point_y, point->Y) ||
        !ecp_sm2z256_bignum_to_field_elem(point_z, point->Z)) {
        // //ECerr(EC_F_ECP_SM2Z256_GET_AFFINE, EC_R_COORDINATES_OUT_OF_RANGE);
        return 0;
    }

    ecp_sm2z256_mod_inverse(z_inv3, point_z);
    ecp_sm2z256_sqr_mont(z_inv2, z_inv3);
    ecp_sm2z256_mul_mont(x_aff, z_inv2, point_x);

    if (x != NULL) {
        ecp_sm2z256_from_mont(x_ret, x_aff);
        if (!bn_set_words(x, x_ret, P256_LIMBS))
            return 0;
    }

    if (y != NULL) {
        ecp_sm2z256_mul_mont(z_inv3, z_inv3, z_inv2);
        ecp_sm2z256_mul_mont(y_aff, z_inv3, point_y);
        ecp_sm2z256_from_mont(y_ret, y_aff);
        if (!bn_set_words(y, y_ret, P256_LIMBS))
            return 0;
    }

    return 1;
}

static SM2Z256_PRE_COMP *ecp_sm2z256_pre_comp_new(const EC_GROUP *group)
{
    SM2Z256_PRE_COMP *ret = NULL;

    if (!group)
        return NULL;

    ret = CRYPTO_zalloc(sizeof(*ret));

    if (ret == NULL) {
        // //ECerr(EC_F_ECP_SM2Z256_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    ret->group = group;
    ret->w = 7;                 /* default */
    ret->references = 1;

    // ret->lock = CRYPTO_THREAD_lock_new();
    // if (ret->lock == NULL) {
    //     // //ECerr(EC_F_ECP_SM2Z256_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
    //     CRYPTO_free(ret);
    //     return NULL;
    // }
    return ret;
}

SM2Z256_PRE_COMP *EC_sm2z256_pre_comp_dup(SM2Z256_PRE_COMP *p)
{
    // int i;
    // if (p != NULL)
    //     CRYPTO_atomic_add(&p->references, 1, &i, p->lock);
    return p;
}

void EC_sm2z256_pre_comp_free(SM2Z256_PRE_COMP *pre)
{
    if (pre == NULL)
        return;

    CRYPTO_free(pre->precomp_storage);
    CRYPTO_free(pre);
}


// static int ecp_sm2z256_window_have_precompute_mult(const EC_GROUP *group)
// {
//     /* There is a hard-coded table for the default generator. */
//     const EC_POINT *generator = EC_GROUP_get0_generator(group);

//     if (generator != NULL && ecp_sm2z256_is_affine_G(generator)) {
//         /* There is a hard-coded table for the default generator. */
//         return 1;
//     }

//     return HAVEPRECOMP(group, sm2z256);
// }

const EC_METHOD *EC_GFp_sm2z256_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        0, /*todo : delete it */
        ec_GFp_mont_group_init,
        ec_GFp_mont_group_finish,
        ec_GFp_mont_group_clear_finish,
        ec_GFp_mont_group_copy,
        ec_GFp_mont_group_set_curve,
        ec_GFp_simple_group_get_curve,
        ec_GFp_simple_group_get_degree,
        ec_group_simple_order_bits,
        ec_GFp_simple_group_check_discriminant,
        ec_GFp_simple_point_init,
        ec_GFp_simple_point_finish,
        ec_GFp_simple_point_clear_finish,
        ec_GFp_simple_point_copy,
        ec_GFp_simple_point_set_to_infinity,
        ec_GFp_simple_set_Jprojective_coordinates_GFp,
        ec_GFp_simple_get_Jprojective_coordinates_GFp,
        ec_GFp_simple_point_set_affine_coordinates,
        ecp_sm2z256_get_affine,
        0, 0, 0,
        ec_GFp_simple_add,
        ec_GFp_simple_dbl,
        ec_GFp_simple_invert,
        ec_GFp_simple_is_at_infinity,
        ec_GFp_simple_is_on_curve,
        ec_GFp_simple_cmp,
        ec_GFp_simple_make_affine,
        ec_GFp_simple_points_make_affine,
        ecp_sm2z256_points_mul,                    /* mul */
        ecp_sm2z256_mul_with_precomp,              /* precompute_mult */
        0,                                         /* precompute table for G */
        ecp_sm2z256_point_mult_precompute_table,   /* precompute table for other point */
        0,   /* have_precompute_mult */
        ec_GFp_mont_field_mul,
        ec_GFp_mont_field_sqr,
        0,                                          /* field_div */
        ec_GFp_mont_field_encode,
        ec_GFp_mont_field_decode,
        ec_GFp_mont_field_set_to_one
    };

    return &ret;
}

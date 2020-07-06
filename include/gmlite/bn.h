/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_BN_H
# define HEADER_BN_H

#include <stddef.h>
#include <gmlite/common.h>
#include <gmlite/gm_typ.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * 64-bit processor with LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_ULONG        unsigned long
#  define BN_BYTES        8
# endif

/*
 * 64-bit processor other than LP64 ABI
 */
# ifdef SIXTY_FOUR_BIT
#  define BN_ULONG        unsigned long long
#  define BN_BYTES        8
# endif

# ifdef THIRTY_TWO_BIT
#  define BN_ULONG        unsigned int
#  define BN_BYTES        4
# endif

# define BN_BITS2       (BN_BYTES * 8)
# define BN_BITS        (BN_BITS2 * 2)
# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))

# define BN_FLG_MALLOCED         0x01
# define BN_FLG_STATIC_DATA      0x02

/*
 * avoid leaking exponent information through timing,
 * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
 * BN_div() will call BN_div_no_branch,
 * BN_mod_inverse() will call BN_mod_inverse_no_branch.
 */
# define BN_FLG_CONSTTIME        0x04
# define BN_FLG_SECURE           0x08

void BN_set_flags(BIGNUM *b, int n);
int BN_get_flags(const BIGNUM *b, int n);

#define OSSL_NELEM(x)    (sizeof(x)/sizeof(x[0]))

/*
 * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
 * has not been otherwise initialised or used.
 */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);

# define BN_prime_checks 0      /* default: select number of iterations based
                                 * on the size of the number */

# define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

GML_EXPORT int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
GML_EXPORT int BN_is_zero(const BIGNUM *a);
GML_EXPORT int BN_is_one(const BIGNUM *a);
GML_EXPORT int BN_is_word(const BIGNUM *a, const BN_ULONG w);
GML_EXPORT int BN_is_odd(const BIGNUM *a);

# define BN_one(a)       (BN_set_word((a),1))

void BN_zero_ex(BIGNUM *a);

// # if OPENSSL_API_COMPAT >= 0x00908000L
# define BN_zero(a)      BN_zero_ex(a)
// # else
// #  define BN_zero(a)      (BN_set_word((a),0))
// # endif

const BIGNUM *BN_value_one(void);
GML_EXPORT BN_CTX *BN_CTX_new(void);
GML_EXPORT BN_CTX *BN_CTX_secure_new(void);
GML_EXPORT void BN_CTX_free(BN_CTX *c);
GML_EXPORT void BN_CTX_start(BN_CTX *ctx);
GML_EXPORT BIGNUM *BN_CTX_get(BN_CTX *ctx);
GML_EXPORT void BN_CTX_end(BN_CTX *ctx);
GML_EXPORT int BN_rand(BIGNUM *rnd, int bits);
// int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
GML_EXPORT int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
// int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
GML_EXPORT int BN_num_bits(const BIGNUM *a);
GML_EXPORT int BN_num_bits_word(BN_ULONG l);
GML_EXPORT int BN_security_bits(int L, int N);
GML_EXPORT BIGNUM *BN_new(void);
GML_EXPORT BIGNUM *BN_secure_new(void);
GML_EXPORT void BN_clear_free(BIGNUM *a);
GML_EXPORT BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
GML_EXPORT void BN_swap(BIGNUM *a, BIGNUM *b);
GML_EXPORT BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
GML_EXPORT int BN_bn2bin(const BIGNUM *a, unsigned char *to);
GML_EXPORT int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
GML_EXPORT BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
GML_EXPORT int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
GML_EXPORT int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
GML_EXPORT int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
GML_EXPORT int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
GML_EXPORT int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
GML_EXPORT int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
GML_EXPORT int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
GML_EXPORT void BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  a  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
GML_EXPORT int BN_is_negative(const BIGNUM *b);

GML_EXPORT int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
           BN_CTX *ctx);
# define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
GML_EXPORT int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
GML_EXPORT int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
GML_EXPORT int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
GML_EXPORT int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
GML_EXPORT int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);
GML_EXPORT int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx);
GML_EXPORT int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
GML_EXPORT int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
GML_EXPORT int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
GML_EXPORT int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx);
GML_EXPORT int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

GML_EXPORT BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
GML_EXPORT BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
GML_EXPORT int BN_mul_word(BIGNUM *a, BN_ULONG w);
GML_EXPORT int BN_add_word(BIGNUM *a, BN_ULONG w);
GML_EXPORT int BN_sub_word(BIGNUM *a, BN_ULONG w);
GML_EXPORT int BN_set_word(BIGNUM *a, BN_ULONG w);
GML_EXPORT BN_ULONG BN_get_word(const BIGNUM *a);

GML_EXPORT int BN_get_top(const BIGNUM *a);
GML_EXPORT int BN_set_words(BIGNUM *a, const BN_ULONG *words, int num_words);

GML_EXPORT int BN_cmp(const BIGNUM *a, const BIGNUM *b);
GML_EXPORT void BN_free(BIGNUM *a);
GML_EXPORT int BN_is_bit_set(const BIGNUM *a, int n);
GML_EXPORT int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
GML_EXPORT int BN_lshift1(BIGNUM *r, const BIGNUM *a);
GML_EXPORT int BN_mask_bits(BIGNUM *a, int n);
GML_EXPORT int BN_print(const BIGNUM *a);
GML_EXPORT int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
GML_EXPORT int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
GML_EXPORT int BN_rshift1(BIGNUM *r, const BIGNUM *a);
GML_EXPORT void BN_clear(BIGNUM *a);
GML_EXPORT BIGNUM *BN_dup(const BIGNUM *a);
GML_EXPORT int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
GML_EXPORT int BN_set_bit(BIGNUM *a, int n);
GML_EXPORT int BN_clear_bit(BIGNUM *a, int n);
GML_EXPORT char *BN_bn2hex(const BIGNUM *a);
// GML_EXPORT char *BN_bn2dec(const BIGNUM *a);
GML_EXPORT int BN_hex2bn(BIGNUM **a, const char *str);
GML_EXPORT int BN_dec2bn(BIGNUM **a, const char *str);
GML_EXPORT int BN_asc2bn(BIGNUM **a, const char *str);

GML_EXPORT int BN_print_bn_hex(const char *s, BIGNUM *z);

GML_EXPORT int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

GML_EXPORT BIGNUM *BN_mod_inverse(BIGNUM *ret,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

GML_EXPORT int BN_mod_inverse_Lehmer(BIGNUM *in, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);

GML_EXPORT BIGNUM *BN_mod_sqrt(BIGNUM *ret,
                    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

GML_EXPORT void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);

GML_EXPORT BN_MONT_CTX *BN_MONT_CTX_new(void);
GML_EXPORT int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
GML_EXPORT int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                     BN_CTX *ctx);
GML_EXPORT int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
                       BN_CTX *ctx);
GML_EXPORT void BN_MONT_CTX_free(BN_MONT_CTX *mont);
GML_EXPORT int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
GML_EXPORT BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);

# ifdef  __cplusplus
}
# endif

#endif
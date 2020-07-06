/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
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
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#ifndef HEADER_EC_LCL_H
#define HEADER_EC_LCL_H

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <gmlite/ec.h>
#include <gmlite/bn.h>
#include <gmlite/crypto.h>

/* Use default functions for poin2oct, oct2point and compressed coordinates */
#define EC_FLAGS_DEFAULT_OCT    0x1

/* Use custom formats for EC_GROUP, EC_POINT and EC_KEY */
#define EC_FLAGS_CUSTOM_CURVE   0x2

/* Curve does not support signing operations */
#define EC_FLAGS_NO_SIGN        0x4

/*
 * Structure details are not part of the exported interface, so all this may
 * change in future versions.
 */

struct ec_method_st {
    /* Various method flags */
    int flags;
    /* used by EC_METHOD_get_field_type: */
    int field_type;             /* a NID */
    /*
     * used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free,
     * EC_GROUP_copy:
     */
    int (*group_init) (EC_GROUP *);
    void (*group_finish) (EC_GROUP *);
    void (*group_clear_finish) (EC_GROUP *);
    int (*group_copy) (EC_GROUP *, const EC_GROUP *);
    /* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
    /* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
    int (*group_set_curve) (EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
    int (*group_get_curve) (const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                            BN_CTX *);
    /* used by EC_GROUP_get_degree: */
    int (*group_get_degree) (const EC_GROUP *);
    int (*group_order_bits) (const EC_GROUP *);
    /* used by EC_GROUP_check: */
    int (*group_check_discriminant) (const EC_GROUP *, BN_CTX *);
    /*
     * used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free,
     * EC_POINT_copy:
     */
    int (*point_init) (EC_POINT *);
    void (*point_finish) (EC_POINT *);
    void (*point_clear_finish) (EC_POINT *);
    int (*point_copy) (EC_POINT *, const EC_POINT *);
    /*-
     * used by EC_POINT_set_to_infinity,
     * EC_POINT_set_Jprojective_coordinates_GFp,
     * EC_POINT_get_Jprojective_coordinates_GFp,
     * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
     * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
     */
    int (*point_set_to_infinity) (const EC_GROUP *, EC_POINT *);
    int (*point_set_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  EC_POINT *, const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
    int (*point_get_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  const EC_POINT *, BIGNUM *x,
                                                  BIGNUM *y, BIGNUM *z,
                                                  BN_CTX *);
    int (*point_set_affine_coordinates) (const EC_GROUP *, EC_POINT *,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *);
    int (*point_get_affine_coordinates) (const EC_GROUP *, const EC_POINT *,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *);
    int (*point_set_compressed_coordinates) (const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
    size_t (*point2oct) (const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *);
    int (*oct2point) (const EC_GROUP *, EC_POINT *, const unsigned char *buf,
                      size_t len, BN_CTX *);
    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    int (*add) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                const EC_POINT *b, BN_CTX *);
    int (*dbl) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    int (*invert) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    /*
     * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
     */
    int (*is_at_infinity) (const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve) (const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp) (const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine) (const EC_GROUP *, size_t num, EC_POINT *[],
                               BN_CTX *);
    /*
     * used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult,
     * EC_POINT_have_precompute_mult (default implementations are used if the
     * 'mul' pointer is 0):
     */
    int (*mul) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
    int (*mul_with_precomp) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                        void *table, BN_CTX *ctx);
    /* precompute table for generator G */
    int (*precompute_mult_table) (const EC_GROUP *group, BN_CTX *);
    /* precompute table for other point P */
    int (*point_precompute_mult_table) (const EC_GROUP *group, void **pre, EC_POINT *point, BN_CTX *ctx);
    int (*have_precompute_mult) (const EC_GROUP *group);
    /* internal functions */
    /*
     * 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and
     * 'dbl' so that the same implementations of point operations can be used
     * with different optimized implementations of expensive field
     * operations:
     */
    int (*field_mul) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    int (*field_div) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /* e.g. to Montgomery */
    int (*field_encode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /* e.g. from Montgomery */
    int (*field_decode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    int (*field_set_to_one) (const EC_GROUP *, BIGNUM *r, BN_CTX *);
};

/*
 * Types and functions to manipulate pre-computed values.
 */
typedef struct sm2p256_pre_comp_st SM2P256_PRE_COMP;
typedef struct sm2z256_pre_comp_st SM2Z256_PRE_COMP;
typedef struct ec_pre_comp_st EC_PRE_COMP;

struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order;
    // int curve_name;             /* optional NID for named curve */
    // int asn1_flag;              /* flag to control the asn1 encoding */
    // point_conversion_form_t asn1_form;
    // unsigned char *seed;        /* optional seed for parameters (appears in
    //                              * ASN1) */
    // size_t seed_len;
    /*
     * The following members are handled by the method functions, even if
     * they appear generic
     */
    /*
     * Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    BIGNUM *field;
    /*
     * Field specification for curves over GF(2^m). The irreducible f(t) is
     * then of the form: t^poly[0] + t^poly[1] + ... + t^poly[k] where m =
     * poly[0] > poly[1] > ... > poly[k] = 0. The array is terminated with
     * poly[k+1]=-1. All elliptic curve irreducibles have at most 5 non-zero
     * terms.
     */
    // int poly[6];
    /*
     * Curve coefficients. (Here the assumption is that BIGNUMs can be used
     * or abused for all kinds of fields, not just GF(p).) For characteristic
     * > 3, the curve is defined by a Weierstrass equation of the form y^2 =
     * x^3 + a*x + b. For characteristic 2, the curve is defined by an
     * equation of the form y^2 + x*y = x^3 + a*x^2 + b.
     */
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    // int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
    //                        BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;

    union {
        SM2P256_PRE_COMP *sm2p256;
        SM2Z256_PRE_COMP *sm2z256;
        // EC_PRE_COMP *ec;
    } pre_comp;
};

struct ec_point_st {
    const EC_METHOD *meth;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};

void EC_pre_comp_free(EC_GROUP *group);
void EC_sm2p256_pre_comp_free(SM2P256_PRE_COMP *);
void EC_sm2z256_pre_comp_free(SM2Z256_PRE_COMP *);

/** Returns the basic GFp ec methods which provides the basis for the
 *  optimized methods.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_simple_method(void);

/** Returns GFp methods using montgomery multiplication.
 *  \return  EC_METHOD object
 */
const EC_METHOD *EC_GFp_mont_method(void);
/*
 * method functions in ec_mult.c (ec_lib.c uses these as defaults if
 * group->method->mul is 0)
 */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
int ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *);
int ec_wNAF_have_precompute_mult(const EC_GROUP *group);

/* method functions in ecp_smpl.c */
int ec_GFp_simple_group_init(EC_GROUP *);
void ec_GFp_simple_group_finish(EC_GROUP *);
void ec_GFp_simple_group_clear_finish(EC_GROUP *);
int ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_simple_group_set_curve(EC_GROUP *, const BIGNUM *p,
                                  const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a,
                                  BIGNUM *b, BN_CTX *);
int ec_GFp_simple_group_get_degree(const EC_GROUP *);
int ec_GFp_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int ec_GFp_simple_point_init(EC_POINT *);
void ec_GFp_simple_point_finish(EC_POINT *);
void ec_GFp_simple_point_clear_finish(EC_POINT *);
int ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                  EC_POINT *, const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
int ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *,
                                                  const EC_POINT *, BIGNUM *x,
                                                  BIGNUM *y, BIGNUM *z,
                                                  BN_CTX *);
int ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                               const BIGNUM *x,
                                               const BIGNUM *y, BN_CTX *);
int ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *,
                                               const EC_POINT *, BIGNUM *x,
                                               BIGNUM *y, BN_CTX *);
int ec_GFp_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
int ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      const EC_POINT *b, BN_CTX *);
int ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      BN_CTX *);
int ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
int ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int ec_GFp_simple_points_make_affine(const EC_GROUP *, size_t num,
                                     EC_POINT *[], BN_CTX *);
int ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
int ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                            BN_CTX *);

/* method functions in ecp_mont.c */
int ec_GFp_mont_group_init(EC_GROUP *);
int ec_GFp_mont_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                                const BIGNUM *b, BN_CTX *);
void ec_GFp_mont_group_finish(EC_GROUP *);
void ec_GFp_mont_group_clear_finish(EC_GROUP *);
int ec_GFp_mont_group_copy(EC_GROUP *, const EC_GROUP *);
int ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *);
int ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *);
int ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GFp_mont_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);

/* method functions in ecp_nist.c */
int ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src);
int ec_GFp_nist_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                                const BIGNUM *b, BN_CTX *);
int ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *);
int ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *);

int ec_precompute_mont_data(EC_GROUP *);
int ec_group_simple_order_bits(const EC_GROUP *group);

# if !defined(SM2_NO_ASM) && (defined(__x86_64) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)) && (BN_BITS2 == 64)
const EC_METHOD *EC_GFp_sm2z256_method(void);
# endif

EC_GROUP* EC_GROUP_new_sm2();
EC_GROUP* EC_GROUP_new_sm9();

#endif
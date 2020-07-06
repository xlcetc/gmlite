/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_PAIRING_H
# define HEADER_PAIRING_H

#include <gmlite/bn.h>
#include <gmlite/common.h>
#include <gmlite/ec.h>

/* TODO : add pairing error code */

# ifdef __cplusplus
extern "C" {
# endif

typedef struct G1_struct_t G1;
typedef struct G2_struct_t G2;
typedef struct GT_struct_t GT;
typedef struct ate_ctx_st ATE_CTX;

GML_EXPORT ATE_CTX* PAIRING_init(const char *T, const char *P, const char *N, const char *B,
                const char *G1X, const char *G1Y,
                const char *G2XA, const char *G2XB, const char *G2YA, const char *G2YB);

GML_EXPORT void PAIRING_free(ATE_CTX *ctx);

GML_EXPORT const EC_GROUP* PAIRING_get_ec_group(const ATE_CTX *ctx);
/*  */
// GML_EXPORT int PAIRING_set_ec_group(ATE_CTX *ctx, const EC_GROUP *group);

/* G1 generator */
GML_EXPORT const G1* PAIRING_get0_generator1(const ATE_CTX *ctx);
GML_EXPORT int PAIRING_get_generator1(G1 *P, const ATE_CTX *ctx);
/* G2 generator */
GML_EXPORT const G2* PAIRING_get0_generator2(const ATE_CTX *ctx);
GML_EXPORT int PAIRING_get_generator2(G2 *Q, const ATE_CTX *ctx);

/* group order */
GML_EXPORT const BIGNUM* PAIRING_get0_order(const ATE_CTX *ctx);

/* G1 method */
GML_EXPORT G1* G1_new();
GML_EXPORT void G1_free(G1 *op);
/* rop = op */
GML_EXPORT int G1_copy(G1 *rop, const G1 *op);
/* rop = generator of G1 **/
GML_EXPORT int G1_set_generator(G1 *rop, const ATE_CTX *ctx);
/* rop = op1 + op2 */
GML_EXPORT void G1_add_affine(G1 *rop, const G1 *op1, const G1 *op2, const ATE_CTX *ctx);
/* rop = op1 + op2 */
GML_EXPORT void G1_add(G1 *rop, const G1 *op1, const G1 *op2, const ATE_CTX *ctx);
/* rop = 2 * op */
GML_EXPORT void G1_double(G1 *rop, const G1 *op, const ATE_CTX *ctx);
/* rop = scalar * op */
GML_EXPORT void G1_mul(G1 *rop, const G1 *op, const BIGNUM *scalar, const ATE_CTX *ctx);
/* transform to affine coordinates */
GML_EXPORT void G1_makeaffine(G1 *op, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G1_is_on_curve(const G1 *op, const ATE_CTX *ctx);
/*  */
GML_EXPORT void G1_print(const G1 *op, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G1_to_bin(uint8_t *s, const G1 *P, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G1_from_bin(G1 *P, const uint8_t *s, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G1_point_compress(uint8_t *s, const G1 *P, const ATE_CTX *ctx);

GML_EXPORT int G1_point_uncompress(G1 *P, const uint8_t *s, const ATE_CTX *ctx);

/* G2 method */
GML_EXPORT G2* G2_new();
GML_EXPORT void G2_free(G2 *op);
/* rop = op */
GML_EXPORT int G2_copy(G2 *rop, const G2 *op);
/* rop = generator of G2 **/
GML_EXPORT int G2_set_generator(G2 *rop, const ATE_CTX *ctx);
/* rop = op1 + op2 */
GML_EXPORT void G2_add_affine(G2 *rop, const G2 *op1, const G2 *op2, const ATE_CTX *ctx);
/* rop = op1 + op2 */
GML_EXPORT void G2_add(G2 *rop, const G2 *op1, const G2 *op2, const ATE_CTX *ctx);
/* rop = 2 * op */
GML_EXPORT void G2_double(G2 *rop, const G2 *op, const ATE_CTX *ctx);
/* rop = scalar * op */
GML_EXPORT void G2_mul(G2 *rop, const G2 *op, const BIGNUM *scalar, const ATE_CTX *ctx);
/* transform to affine coordinates */
GML_EXPORT void G2_makeaffine(G2 *op, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G2_is_on_curve(const G2 *op, const ATE_CTX *ctx);
/*  */
GML_EXPORT void G2_print(const G2 *op, const ATE_CTX *ctx);
/* convert to binary directly */
GML_EXPORT int G2_to_bin(uint8_t *s, const G2 *Q, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G2_from_bin(G2 *Q, const uint8_t *s, const ATE_CTX *ctx);
/*  */
GML_EXPORT int G2_point_compress(uint8_t *s, const G2 *Q, const ATE_CTX *ctx);

GML_EXPORT int G2_point_uncompress(G2 *Q, const uint8_t *s, const ATE_CTX *ctx);

/* GT method, TODO: GT_pow, GT_print, etc */
GML_EXPORT GT* GT_new();
GML_EXPORT void GT_free(GT *op);

GML_EXPORT void GT_to_bin(uint8_t *s, GT *op, const ATE_CTX *ctx);

GML_EXPORT void fp12_mul(GT *rop, const GT *op1, const GT *op2, const ATE_CTX *ctx);
GML_EXPORT void fp12_mul_sparse1(GT *rop, const GT *op1, const GT *op2, const ATE_CTX *ctx);
GML_EXPORT void fp12_mul_sparse2(GT *rop, const GT *op1, const GT *op2, const ATE_CTX *ctx);

GML_EXPORT void fp12_pow(GT *rop, const GT *op, const BIGNUM *exp, const ATE_CTX *ctx);

GML_EXPORT int fp12_cmp(const GT *op1, const GT *op2);

GML_EXPORT void miller_loop(GT *rop, const G1 *P, const G2 *Q, const ATE_CTX *ctx);
GML_EXPORT void final_expo(GT *rop, const ATE_CTX *ctx);
/* optimal ate pairing */
GML_EXPORT void optate(GT *rop, const G1 *op1, const G2 *op2, const ATE_CTX *ctx);

GML_EXPORT void fp12_print(const GT *op, const ATE_CTX *ctx);

# ifdef __cplusplus
}
# endif

#endif
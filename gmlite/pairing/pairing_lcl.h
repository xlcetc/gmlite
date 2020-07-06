/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_PAIRING_LCL_H
#define HEADER_PAIRING_LCL_H

#include <gmlite/common.h>
#include <gmlite/ec.h>
#include <gmlite/pairing.h>
#include "../bn/bn_lcl.h"

#ifdef __cplusplus
extern "C"{
#endif

#define P_MOD_8_EQ_5  1
#define P_MOD_4_EQ_3  2

#define N_LIMBS 4
#define N_BYTES 8*N_LIMBS

struct fp_struct_st
{
    BN_ULONG d[N_LIMBS];
};
typedef struct fp_struct_st fp_t[1];

// Elements from F_{p^2} = F_p[X] / (X^2 - alpha), F_{p^2} are represented as aX + b
struct fp2_struct_st
{
    fp_t m_a;
    fp_t m_b;
};
typedef struct fp2_struct_st fp2_t[1];

// Elements from F_{p^6}= F_{p^2}[Y] / (Y^3 - xi), F_{p^6} are represented as aY^2 + bY + c 
struct fp6_struct_st
{
    fp2_t m_a;
    fp2_t m_b;
    fp2_t m_c;
};
typedef struct fp6_struct_st fp6_t[1];

// Elements from F_{p^{12}}= F_{p^6}[Z] / (Z^2 - tau), F_{p^12} are represented as aZ + b
struct GT_struct_t
{
    fp6_t m_a;
    fp6_t m_b;
};
typedef struct GT_struct_t fp12_t[1];

// Structure describing a point on a BN-curve
struct G1_struct_t
{
    fp_t m_x; // X-Coordinate (Jacobian Coordinate system)
    fp_t m_y; // Y-Coordinate (Jacobian Coordinate system)
    fp_t m_z; // Z-Coordinate (Jacobian Coordinate system)
};

struct G2_struct_t
{
    fp2_t m_x; // X-Coordinate (Jacobian Coordinate system)
    fp2_t m_y; // Y-Coordinate (Jacobian Coordinate system)
    fp2_t m_z; // Z-Coordinate (Jacobian Coordinate system)
};

/* BN curve parameters */
struct ate_ctx_st
{
    const char *curve_name;
    const EC_GROUP *group;
    // constant coefficient in the irreducible polynomial Y^3 - xi, used to construct F_{p^6} as extension of F_{p^2}
    fp2_t xi;
    // Y^{p-1} lies in F_{p^2}
    fp2_t ypminus1;
    // xi^((p-1)/2)
    fp2_t xipminus1over2;
    // Third root of unity in F_p fulfilling Z^{p^2} = -zeta * Z
    fp_t zeta;
    // Z^{p-1}, lies in F_{p^2}
    fp2_t zpminus1;
    // Z^{1-p}, lies in F_{p^2}
    fp2_t zpminus1inv;
    // generator of E(\F_p)
    G1 curve_gen;
    // generator of the subgroup of order n of E'(\F_{p^2})
    G2 twist_gen;

    /* t */
    fp_t t;
    /* b(mont) */
    fp_t b;
    /* p */
    fp_t p;
    /* group->mont_data->n0 */
    fp_t n0;
    /* R mod p */
    fp_t rp;
    /* R^2 mod p */
    fp_t rrp;
    /* order */
    BIGNUM *order;

    /* p mod ? = ? */
    int p_type;

    /* NAF of 6t+2 */
    int *naf;
    int naf_len;
};

/************ fp ************/

int fp_cmp(const fp_t op1, const fp_t op2);

// Set fp_t rop to given value:
// void fp_set_ui(fp_t rop, const BN_ULONG op);

// Set fp_t rop to value given in bytearray -- inverse function to fp_to_bytearray
void fp_set_bytearray(fp_t rop, const unsigned char *op, size_t oplen);

// Set fp_t rop to given value given as hex string
void fp_set_hexstr(fp_t rop, const char* op, const ATE_CTX *ctx);

// Set rop to one
void fp_setone(fp_t rop, const fp_t rp);

// Set rop to zero
void fp_setzero(fp_t rop);

// Return 1 if op is zero, 0 otherwise
int fp_iszero(const fp_t op);

// Set fp_t rop to given value:
void fp_set(fp_t rop, const fp_t op);

#ifndef PAIRING_NO_ASM
void fp_neg(fp_t rop, const fp_t op, const fp_t p);
void fp_double(fp_t rop, const fp_t op, const fp_t p);
void fp_div_by_2(fp_t rop, const fp_t op, const fp_t p);
void fp_triple(fp_t rop, const fp_t op, const fp_t p);
void fp_add(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p);
void fp_sub(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p);
#else
/* rop = p - op */
static gml_inline void fp_neg(fp_t rop, const fp_t op, const fp_t p)
{
    bn_sub_words(rop->d, p->d, op->d, N_LIMBS);
}

// Double an fp:
static gml_inline void fp_double(fp_t rop, const fp_t op, const fp_t p)
{
    BN_ULONG c;
    
    c = bn_add_words(rop->d, op->d, op->d, N_LIMBS);
    // Reduce if result is larger than p: 
    if (c || bn_cmp_words(rop->d, p->d, N_LIMBS) >= 0)
        bn_sub_words(rop->d, rop->d, p->d, N_LIMBS);
}

//Halve an fp: (emmm, too slow)
static gml_inline void fp_div_by_2(fp_t rop, const fp_t op, const fp_t p)
{
    BIGNUM z;
    bn_init(&z);
    if ((op->d[0] % 2) == 0) {
        BN_set_words(&z, op->d, N_LIMBS);
        BN_rshift(&z, &z, 1);
        bn_copy_words(rop->d, &z, N_LIMBS);
    }
    else {
        BN_ULONG c;
        c = (bn_add_words(rop->d, op->d, p->d, N_LIMBS)) << (64 - 1);
        BN_set_words(&z, rop->d, N_LIMBS);
        BN_rshift(&z, &z, 1);
        bn_copy_words(rop->d, &z, N_LIMBS);
        rop->d[N_LIMBS - 1] ^= c;
    }
    BN_free(&z);
}

//Triple an fp:
static gml_inline void fp_triple(fp_t rop, const fp_t op, const fp_t p)
{
    BN_ULONG c;
    fp_t tmp;

    c = bn_add_words(tmp->d, op->d, op->d, N_LIMBS);
    // Reduce if result is larger than p: 
    if (c || bn_cmp_words(tmp->d, p->d, N_LIMBS) >= 0)
        bn_sub_words(tmp->d, tmp->d, p->d, N_LIMBS);

    c = bn_add_words(rop->d, tmp->d, op->d, N_LIMBS);
    // Reduce if result is larger than p: 
    if (c || bn_cmp_words(rop->d, p->d, N_LIMBS) >= 0)
        bn_sub_words(rop->d, rop->d, p->d, N_LIMBS);
}

//Add two fp, store result in rop:
static gml_inline void fp_add(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p)
{
    BN_ULONG c;
    
    c = bn_add_words(rop->d, op1->d, op2->d, N_LIMBS);
    // Reduce if result is larger than p: 
    if (c || bn_cmp_words(rop->d, p->d, N_LIMBS) >= 0)
        bn_sub_words(rop->d, rop->d, p->d, N_LIMBS);
}

//Subtract op2 from op1, store result in rop:
static gml_inline void fp_sub(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p)
{
    BN_ULONG b;

    b = bn_sub_words(rop->d, op1->d, op2->d, N_LIMBS);
    if (b)
        bn_add_words(rop->d, rop->d, p->d, N_LIMBS);
}

#endif

static gml_inline void fp_mul(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p, const fp_t n0)
{
    bn_mul_mont(rop->d, op1->d, op2->d, p->d, n0->d, N_LIMBS);
}

void fp_square(fp_t rop, const fp_t op);
#define fp_square(rop, op, p, n0) fp_mul(rop, op, op, p, n0)

// // Set fp_t rop to given value:
// void fp_set(fp_t rop, const fp_t op);

// // Compute the negative of an fp
// void fp_neg(fp_t rop, const fp_t op, const fp_t p);

// // Double an fp:
// void fp_double(fp_t rop, const fp_t op, const fp_t p);

// // Halve an fp:
// void fp_halve(fp_t rop, const fp_t op);

// // Triple an fp:
// void fp_triple(fp_t rop, const fp_t op, const fp_t p);

// // Add two fp, store result in rop:
// void fp_add(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p);

// // Subtract op2 from op1, store result in rop:
// void fp_sub(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p);

// // Multiply two fp, store result in rop:
// void fp_mul(fp_t rop, const fp_t op1, const fp_t op2, const fp_t p, const fp_t n0);

// // Square an fp, store result in rop:
// // void fp_square(fp_t rop, const fp_t op);
// #define fp_square(rop, op, p, n0) fp_mul(rop, op, op, p, n0)

// // // Scalar multiple of an fp, store result in rop:
// // void fp_mul_mpz(fp_t rop, const fp_t op1, const mpz_t op2);

// // // Scalar multiple of an fp, store result in rop:
// // void fp_mul_ui(fp_t rop, const fp_t op1, const BN_ULONG op2);

// // rop = op / 2
// void fp_div_by_2(fp_t rop, const fp_t op, const fp_t p);

// Compute inverse of an fp, store result in rop:
int fp_invert(fp_t rop, const fp_t op1, const ATE_CTX *ctx);

int fp_sqrt(fp_t rop, const fp_t op, const ATE_CTX *ctx);

// Print the element to stdout:
void fp_print(const fp_t op, const ATE_CTX *ctx);

// // Convert fp into a bytearray, the destination must have space for NLIMBS mpz_limb_t
// void fp_to_bytearray(unsigned char * rop, const fp_t op);
void fp_to_bin(uint8_t s[N_BYTES], const fp_t op, const ATE_CTX *ctx);

void fp_from_bin(fp_t rop, const uint8_t s[N_LIMBS], const ATE_CTX *ctx);

/************ fp2 ************/

int fp2_sqrt(fp2_t rop, const fp2_t op, const ATE_CTX *ctx);

int fp2_cmp(const fp2_t op1, const fp2_t op2);

// Set fp2_t rop to given value:
void fp2_set(fp2_t rop, const fp2_t op);

// Set fp2_t rop to given value contained in the subfield F_p:
void fp2_set_fp(fp2_t rop, const fp_t op);

// Set rop to one
void fp2_setone(fp2_t rop, const fp_t rp);

// Set rop to zero
void fp2_setzero(fp2_t rop);
int fp2_iszero(const fp2_t op);

// Set an fp2_t to value given in two strings
void fp2_set_hexstr(fp2_t rop, const char* a_str, const char* b_str, const ATE_CTX *ctx);

// Double an fp2:
static gml_inline void fp2_double(fp2_t rop, const fp2_t op, const fp_t p)
{
    fp_double(rop->m_a, op->m_a, p);
    fp_double(rop->m_b, op->m_b, p);
}

// Triple an fp2:
static gml_inline void fp2_triple(fp2_t rop, const fp2_t op, const fp_t p)
{
    fp_triple(rop->m_a, op->m_a, p);
    fp_triple(rop->m_b, op->m_b, p);
}

// Add two fp2, store result in rop:
static gml_inline void fp2_add(fp2_t rop, const fp2_t op1, const fp2_t op2, const fp_t p)
{
//     static int nnn2=0;
// nnn2++;
// printf("%d\n",nnn2);
    fp_add(rop->m_a, op1->m_a, op2->m_a, p);
    fp_add(rop->m_b, op1->m_b, op2->m_b, p);
}

// Subtract op2 from op1, store result in rop:
static gml_inline void fp2_sub(fp2_t rop, const fp2_t op1, const fp2_t op2, const fp_t p)
{
    fp_sub(rop->m_a, op1->m_a, op2->m_a, p);
    fp_sub(rop->m_b, op1->m_b, op2->m_b, p);
}

// Negate op
static gml_inline void fp2_neg(fp2_t rop, const fp2_t op, const fp_t p)
{
    fp_neg(rop->m_a, op->m_a, p);
    fp_neg(rop->m_b, op->m_b, p);
}

// Multiply two fp2, store result in rop:
static gml_inline void fp2_mul(fp2_t rop, const fp2_t op1, const fp2_t op2, const ATE_CTX *ctx)
{
    fp_t tmp1, tmp2, tmp3; // Needed for intermediary results
// static int nnn2=0;

//     if((fp_iszero(op1->m_a) && fp_iszero(op1->m_b)) || (fp_iszero(op2->m_a) && fp_iszero(op2->m_b)))
//     {
// //         nnn2++;
// // printf("%d\n",nnn2);
//         fp2_setzero(rop);
//     }
//     else
    {
        fp_mul(tmp1, op1->m_a, op2->m_a, ctx->p, ctx->n0);
        fp_mul(tmp2, op1->m_b, op2->m_b, ctx->p, ctx->n0);
        fp_add(tmp3, op2->m_a, op2->m_b, ctx->p);
        fp_add(rop->m_a, op1->m_a, op1->m_b, ctx->p);
        fp_set(rop->m_b, tmp2);
        fp_mul(rop->m_a, rop->m_a, tmp3, ctx->p, ctx->n0);
        fp_sub(rop->m_a, rop->m_a, tmp1, ctx->p);
        fp_sub(rop->m_a, rop->m_a, rop->m_b, ctx->p);
// #if(ALPHA == 2)
//         fp_double(tmp1, tmp1, ctx->p);
//         fp_add(rop->m_b, rop->m_b, tmp1, ctx->p);
// #elif(ALPHA == -2)
        fp_double(tmp1, tmp1, ctx->p);
        fp_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
// #elif(ALPHA == -1)
//         fp_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
// #else
// #error "ALPHA must be -1, 2 or -2"
// #endif
    }
}

// Square an fp2, store result in rop:
static gml_inline void fp2_square(fp2_t rop, const fp2_t op, const ATE_CTX *ctx)
{
    fp_t tmp1, tmp2, tmp3; // Needed for intermediary results
// static int nnn2=0;
// nnn2++;
// printf("%d\n",nnn2);
    fp_mul(tmp1, op->m_a, op->m_b, ctx->p, ctx->n0);

    fp_add(tmp2, op->m_a, op->m_b, ctx->p);
// #if(ALPHA == 2)
//     fp_double(tmp3, op->m_a, ctx->p);
//     fp_add(rop->m_b, op->m_b, tmp3, ctx->p);
// #elif(ALPHA == -2)
    fp_double(tmp3, op->m_a, ctx->p);
	// fp_print(op->m_b, ctx);
	// fp_print(tmp3, ctx);
    // printf("%lx,\n",ctx->p->d[0]);
    // printf("%lx,\n",ctx->p->d[1]);
    // printf("%lx,\n",ctx->p->d[2]);
    // printf("%lx,\n",ctx->p->d[3]);
    fp_sub(rop->m_b, op->m_b, tmp3, ctx->p);
	// fp_print(rop->m_b, ctx);
// #elif(ALPHA == -1)
//     fp_sub(rop->m_b, op->m_b, op->m_a, ctx->p);
// #else
// #error "ALPHA must be -1, 2 or -2"
// #endif
    fp_mul(rop->m_b, rop->m_b, tmp2, ctx->p, ctx->n0);

    fp_sub(rop->m_b, rop->m_b, tmp1, ctx->p);
// #if(ALPHA == 2)
//     fp_double(tmp2, tmp1, ctx->p);
//     fp_sub(rop->m_b, rop->m_b, tmp2, ctx->p);
// #elif(ALPHA == -2)
    fp_double(tmp2, tmp1, ctx->p);
    fp_add(rop->m_b, rop->m_b, tmp2, ctx->p);
// #elif(ALPHA == -1)
//     fp_add(rop->m_b, rop->m_b, tmp1, ctx->p);
// #else
// #error "ALPHA must be -1, 2 or -2"
// #endif

    fp_double(rop->m_a, tmp1, ctx->p);
}

// Multiply by xi which is used to construct F_p^6
static gml_inline void fp2_mulxi(fp2_t rop, const fp2_t op, const fp_t p)
{
    fp_t tmp;
    /* op = ax + b, rop = (-b/2)x + a */
    fp_neg(tmp, op->m_b, p);
    fp_div_by_2(tmp, tmp, p);
    fp_set(rop->m_b, op->m_a);
    fp_set(rop->m_a, tmp);
}

// Scalar multiple of an fp2, store result in rop:
static gml_inline void fp2_mul_fp(fp2_t rop, const fp2_t op1, const fp_t op2, const ATE_CTX *ctx)
{
    fp_mul(rop->m_a, op1->m_a, op2, ctx->p, ctx->n0);
    fp_mul(rop->m_b, op1->m_b, op2, ctx->p, ctx->n0);
}

// // Double an fp2:
// void fp2_double(fp2_t rop, const fp2_t op, const fp_t p);

// // Triple an fp2:
// void fp2_triple(fp2_t rop, const fp2_t op, const fp_t p);

// // Add two fp2, store result in rop:
// void fp2_add(fp2_t rop, const fp2_t op1, const fp2_t op2, const fp_t p);

// // Subtract op2 from op1, store result in rop:
// void fp2_sub(fp2_t rop, const fp2_t op1, const fp2_t op2, const fp_t p);

// void fp2_neg(fp2_t rop, const fp2_t op, const fp_t p);

// // Multiply two fp2, store result in rop:
// void fp2_mul(fp2_t rop, const fp2_t op1, const fp2_t op2, const ATE_CTX *ctx);

// // Square anf fp2, store result in rop:
// void fp2_square(fp2_t rop, const fp2_t op, const ATE_CTX *ctx);

// // Multiply by xi which is used to construct F_p^6
// void fp2_mulxi(fp2_t rop, const fp2_t op, const fp_t p);

// // Multiply an fp by xi which is used to construct F_p^6
// //void fp2_mulxi_fp(fp2_t rop, const fp_t op);

// // Multiple of an fp2, store result in rop:
// void fp2_mul_fp(fp2_t rop, const fp2_t op1, const fp_t op2, const ATE_CTX *ctx);

void fp2_pow(fp2_t rop, const fp2_t op, BIGNUM *exp, const ATE_CTX *ctx);

// Inverse multiple of an fp2, store result in rop:
void fp2_invert(fp2_t rop, const fp2_t op1, const ATE_CTX *ctx);

void fp2_to_bin(uint8_t s[2*N_BYTES], const fp2_t op, const ATE_CTX *ctx);

void fp2_from_bin(fp2_t rop, const uint8_t s[2*N_BYTES], const ATE_CTX *ctx);

// Print the element to stdout:
void fp2_print(const fp2_t op, const ATE_CTX *ctx);

/************ fp6 ************/

int fp6_cmp(const fp6_t op1, const fp6_t op2);

// Set fp6_t rop to given value:
void fp6_set(fp6_t rop, const fp6_t op);

// Initialize an fp6, set to value given in three fp2s
void fp6_set_fp2(fp6_t rop, const fp2_t a, const fp2_t b, const fp2_t c);

// Initialize an fp6, set to value given in six strings
void fp6_set_hexstr(fp6_t rop, const char *a1, const char *a0, const char *b1, const char *b0, const char *c1, const char *c0, const ATE_CTX *ctx);

// Return 1 if op is zero, 0 otherwise
int fp6_iszero(const fp6_t op);

// Set rop to one:
void fp6_setone(fp6_t rop, const fp_t rp);

// Set rop to zero:
void fp6_setzero(fp6_t rop);

// Add two fp6, store result in rop:
void fp6_add(fp6_t rop, const fp6_t op1, const fp6_t op2, const fp_t p);

// Subtract op2 from op1, store result in rop:
void fp6_sub(fp6_t rop, const fp6_t op1, const fp6_t op2, const fp_t p);

// Negate an fp6
void fp6_neg(fp6_t rop, const fp6_t op, const fp_t p);

// Multiply two fp6, store result in rop:
void fp6_mul(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx);
void fp6_mul_sparse1(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx);
void fp6_mul_sparse2(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx);
void fp6_mul_sparse3(fp6_t rop, const fp6_t op1, const fp6_t op2, const ATE_CTX *ctx);

// Square an fp6, store result in rop:
void fp6_square(fp6_t rop, const fp6_t op, const ATE_CTX *ctx);

// Multiply with tau:
void fp6_multau(fp6_t rop, const fp6_t op, const ATE_CTX *ctx);

void fp6_mul_fp(fp6_t rop, const fp6_t op1, const fp_t op2, const ATE_CTX *ctx);

void fp6_mul_fp2(fp6_t rop, const fp6_t op1, const fp2_t op2, const ATE_CTX *ctx);

void fp6_invert(fp6_t rop, const fp6_t op, const ATE_CTX *ctx);

void fp6_frobenius_p(fp6_t rop, const fp6_t op, const ATE_CTX *ctx);

void fp6_frobenius_p2(fp6_t rop, const fp6_t op, const ATE_CTX *ctx);

void fp6_to_bin(uint8_t s[6*N_BYTES], fp6_t op, const ATE_CTX *ctx);

// Print the element to stdout:
void fp6_print(const fp6_t op, const ATE_CTX *ctx);

/************ fp12 ************/

// int fp12_cmp(const fp12_t op1, const fp12_t op2);

// Set fp12_t rop to given value:
void fp12_set(fp12_t rop, const fp12_t op);

// Initialize an fp12, set to value given in two fp6s
void fp12_set_fp6(fp12_t rop, const fp6_t a, const fp6_t b);

// Set rop to one:
void fp12_setone(fp12_t rop, const fp_t rp);

// Return 1 if op is zero, 0 otherwise
int fp12_iszero(const fp12_t op);

// Set rop to zero:
void fp12_setzero(fp12_t rop);

// Add two fp12, store result in rop:
void fp12_add(fp12_t rop, const fp12_t op1, const fp12_t op2, const fp_t p);

// Subtract op2 from op1, store result in rop:
void fp12_sub(fp12_t rop, const fp12_t op1, const fp12_t op2, const fp_t p);

void fp12_mul_fp6(fp12_t rop, const fp12_t op1, const fp6_t op2, const ATE_CTX *ctx);

// Square an fp12, store result in rop:
void fp12_square(fp12_t rop, const fp12_t op, const ATE_CTX *ctx);

void fp12_pow1(fp12_t rop, const fp12_t op, const BIGNUM *exp, const ATE_CTX *ctx);

// void fp12_pow(fp12_t rop, const fp12_t op, const BIGNUM *exp, const ATE_CTX *ctx);

void fp12_invert(fp12_t rop, const fp12_t op, const ATE_CTX *ctx);

void fp12_frobenius_p(fp12_t rop, const fp12_t op, const ATE_CTX *ctx);

void fp12_frobenius_p2(fp12_t rop, const fp12_t op, const ATE_CTX *ctx);

/************ G1 ************/

void G1_init(G1 *rop, const ATE_CTX *ctx);

void G1_init_set_str(G1 *rop, const char* x, const char* y, const ATE_CTX *ctx);

void G1_init_set(G1 *rop, const G1 *op);

void G1_set_bytearray(G1 *rop, const unsigned char* x, const unsigned char* y);

// Generate a G1 *by copying the coordinates from another 
void G1_set(G1 *point, const G1 *arg);

// Compute the Inverse of a Point *op, store result in *rop:
void G1_neg(G1 *rop, const G1 *op);

/************ G2 ************/

void G2_set(G2 *rop, const G2 *op);

void G2_set_jacobian(G2 *rop, const fp2_t x, const fp2_t y, const fp2_t z);

void G2_set_affine(G2 *rop, const fp2_t x, const fp2_t y, const ATE_CTX *ctx);

void G2_init_set_str(G2 *rop, const char* xa, const char* xb, const char* ya, const char* yb, const ATE_CTX *ctx);

void G2_set_bytearray(G2 *rop, unsigned char *ucXa, unsigned char *ucXb, unsigned char *ucYa, unsigned char *ucYb, const ATE_CTX *ctx);

void G2_frobenius(G2 *rop, const G2 *op, const ATE_CTX *ctx);



unsigned int _booth_recode_w5(unsigned int in);

int compute_6tplus2_naf(int **naf, int *naf_len, fp_t t);

#ifdef __cplusplus
}
#endif

#endif
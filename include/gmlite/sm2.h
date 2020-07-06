/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include <gmlite/common.h>
#include <gmlite/ec.h>
#include <gmlite/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TODO : add sm2 error code */

typedef struct sm2_ctx_t
{
    EC_GROUP *group;
    void *pk_precomp;
    uint8_t sk_precomp[64];
} SM2_CTX;

/* signature format
 * SM2_SIG_RS_ASN1 : signature = asn1_encode(r||s)
 * SM2_SIG_RS_ORIG : signature = r||s
 */
typedef enum SM2_SIG_MODE
{
    SM2_SIG_RS_ASN1,
    SM2_SIG_RS_ORIG
} SM2_SIG_MODE;

GML_EXPORT const EC_GROUP* SM2_get_group();

/* init sm2 context, it's used to store precomputed table for point other than generator
 * [OUT] sm2_ctx : sm2 context
 * [IN ] pubkey_x : public key x coordinate(32 bytes), optional, it can be NULL
 * [IN ] pubkey_y : public key y coordinate(32 bytes), optional, it can be NULL 
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_CTX_init(SM2_CTX *sm2_ctx, uint8_t pubkey_x[32], uint8_t pubkey_y[32]);

/* clear precomputed table in sm2 context
 * [IN] sm2_ctx : sm2 context
 */
GML_EXPORT void SM2_CTX_clear(SM2_CTX *sm2_ctx);

/* clear and free sm2 context
 * [IN] sm2_ctx : sm2 context
 */
GML_EXPORT void SM2_CTX_clear_free(SM2_CTX *sm2_ctx);

/* generate sm2 key pair (bytes)
 * [OUT] privkey : private key, 32 bytes
 * [OUT] pubkey_x : public key x coordinate, 32 bytes
 * [OUT] pubkey_y : public key y coordinate, 32 bytes
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_keygen(uint8_t privkey[32], uint8_t pubkey_x[32], uint8_t pubkey_y[32]);

/* generate key pair (BIGNUM) */
GML_EXPORT int SM2_keygen_bn(BIGNUM *privkey_bn, BIGNUM *pubkey_x_bn, BIGNUM *pubkey_y_bn);

/* compute public key from private key (bytes) 
 * [IN ] privkey : private key, 32 bytes
 * [OUT] pubkey_x : public key x coordinate, 32 bytes
 * [OUT] pubkey_y : public key y coordinate, 32 bytes
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_compute_pubkey(uint8_t privkey[32], uint8_t pubkey_x[32], uint8_t pubkey_y[32]);

/* compute public key from private key (BIGNUM) */
GML_EXPORT int SM2_compute_pubkey_bn(BIGNUM *privkey_bn, BIGNUM *pubkey_x_bn, BIGNUM *pubkey_y_bn);

/* compute sm2 hash signature 
 * [OUT] sig : signature
 * [OUT] siglen : signature length
 * [IN ] e : message hash
 * [IN ] rand : random value, shoule be NULL
 * [IN ] privkey : private key, 32 bytes
 * [IN ] mode : signature format
 * [IN ] sm2_ctx : sm2 context
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_sign(uint8_t *sig, int *siglen, const uint8_t e[32], const uint8_t rand[32], const uint8_t privkey[32], SM2_SIG_MODE mode, SM2_CTX *sm2_ctx);

/* verify sm2 hash signature 
 * [IN] sig : signature
 * [IN] siglen : signature length
 * [IN] e : message hash
 * [IN] pubkey_x : public key x coordinate, 32 bytes
 * [IN] pubkey_y : public key y coordinate, 32 bytes
 * [IN ] mode : signature format
 * [IN ] sm2_ctx : sm2 context
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_verify(uint8_t *sig, int siglen, const uint8_t e[32], const uint8_t pubkey_x[32], const uint8_t pubkey_y[32], SM2_SIG_MODE mode, SM2_CTX *sm2_ctx);

/* compute sm2 message signature 
 * [OUT] sig : signature
 * [OUT] siglen : signature length
 * [IN ] msg : message
 * [IN ] msglen : message length
 * [IN ] rand : random value, shoule be NULL
 * [IN ] pubkey_x : public key x coordinate, 32 bytes
 * [IN ] pubkey_y : public key y coordinate, 32 bytes
 * [IN ] privkey : private key, 32 bytes
 * [IN ] mode : signature format
 * [IN ] sm2_ctx : sm2 context
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_sign_ex(uint8_t *sig, int *siglen, 
                        const uint8_t *msg, int msglen, 
                        const uint8_t *id, int idlen, const uint8_t rand[32], 
                        const uint8_t pubkey_x[32], const uint8_t pubkey_y[32], const uint8_t privkey[32],
                        SM2_SIG_MODE mode, SM2_CTX *sm2_ctx);

/* verify sm2 message signature 
 * [IN] sig : signature
 * [IN] siglen : signature length
 * [IN] msg : message
 * [IN] msglen : message length
 * [IN] pubkey_x : public key x coordinate, 32 bytes
 * [IN] pubkey_y : public key y coordinate, 32 bytes
 * [IN] mode : signature format
 * [IN] sm2_ctx : sm2 context
 * RETURN GML_OK : success, GML_ERROR : fail
 */
GML_EXPORT int SM2_verify_ex(uint8_t *sig, int siglen, 
                            const uint8_t *msg, int msglen, 
                            const uint8_t *id, int idlen,
                            const uint8_t pubkey_x[32], const uint8_t pubkey_y[32], 
                            SM2_SIG_MODE mode, SM2_CTX *sm2_ctx);

/* compress sm2 point */
GML_EXPORT int SM2_point_compress(uint8_t out[65], const EC_POINT *point);

/* uncompress sm2 point */
GML_EXPORT int SM2_point_uncompress(EC_POINT *point, const uint8_t in[65]);

GML_EXPORT int SM2_encrypt(uint8_t **out, int *outlen,
                           const uint8_t *in, int inlen,
                           const uint8_t pubkey_x[32], const uint8_t pubkey_y[32]);

GML_EXPORT int SM2_decrypt(uint8_t **out, int *outlen,
                           const uint8_t *in, int inlen,
                           const uint8_t privkey[32]);

#  ifdef  __cplusplus
}
#  endif

# endif
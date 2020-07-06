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
#include <gmlite/crypto.h>
#include <gmlite/ec.h>
#include <gmlite/sm2.h>
#include <gmlite/sm3.h>
#include "sm2_lcl.h"

/* compress point
   only uncompressed form is supported now
*/
int SM2_point_compress(uint8_t out[65], const EC_POINT *point)
{
    int ret = GML_ERROR;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    const EC_GROUP *group = NULL;

    group = SM2_get_group();
    if (group == NULL)
        goto end;

    x = BN_new();
    y = BN_new();

    if (out == NULL || point == NULL || x == NULL || y == NULL)
        goto end;

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL)) 
        goto end;

    out[0] = 0x04;
    BN_bn2binpad(x, out +  1, 32);
    BN_bn2binpad(y, out + 33, 32);
    
    ret = GML_OK;
end:
    BN_free(x);
    BN_free(y);
    return ret;
}

/* uncompress point
   only uncompressed form is supported now
*/
int SM2_point_uncompress(EC_POINT *point, const uint8_t *in)
{
    int ret = GML_ERROR;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    const EC_GROUP *group = NULL;

    group = SM2_get_group();
    if (group == NULL)
        goto end;

    x = BN_new();
    y = BN_new();

    if (in == NULL || point == NULL || x == NULL || y == NULL)
        goto end;

    if (in[0] != 0x04)
        goto end;

    BN_bin2bn(in +  1, 32, x);
    BN_bin2bn(in + 33, 32, y);

    if(!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL) ||  /* make point */
        EC_POINT_is_on_curve(group, point, NULL) != 1)  /* is point on curve */
    {
        goto end;
    }

    ret = GML_OK;
end:
    BN_free(x);
    BN_free(y);
    return ret;
}

// static int SM2_ciphertext_size(EC_KEY *ec_key, int inlen)
// {
//     int ret = GML_ERROR;
//     int conv_form = POINT_CONVERSION_UNCOMPRESSED;//ec_key->conv_form;
//     switch(conv_form)
//     {
//         case POINT_CONVERSION_COMPRESSED: 
//         {
//             // ret = 1 + 32 + inlen + 32;
//             break;
//         }
//         case POINT_CONVERSION_UNCOMPRESSED:
//         {
//             ret = 1 + 64 + inlen + 32;
//             break;
//         }
//         case POINT_CONVERSION_HYBRID: 
//         {
//             // ret = 1 + 64 + inlen + 32;
//             break;
//         }
//         default: break;
//     }

//     return ret;
// }

/* in      : message to be signed
   in_len  : message length
   out     : ciphertext
   out_len : ciphertext length
*/
static int SM2_do_encrypt(const uint8_t *in, int inlen, 
                                uint8_t *out, const EC_POINT *pubkey)
{
    int ret = GML_ERROR;
    const EC_GROUP *group;
    // const EC_POINT *pubkey;
    // KDF_FUNC kdf;
    EC_POINT *ephem_point = NULL;
    EC_POINT *share_point = NULL;
    BIGNUM *n = NULL;
    BIGNUM *h = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;
    SM3_CTX sm3_ctx;

    uint8_t buf[64];
    uint8_t *t = NULL;
    int i;
    // int conv_form = ec_key->conv_form;

    t = CRYPTO_malloc(inlen);
    /* check arguments */
    if (in == NULL || t == NULL) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (inlen <= 0 || inlen > 256) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_PLAINTEXT_LENGTH);
        return 0;
    }

    // if (!(kdf = KDF_get_x9_63(md))) {
    // 	// SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_DIGEST_ALGOR);
    // 	return 0;
    // }

    group = SM2_get_group();

    /* malloc */
    if (!(ephem_point = EC_POINT_new(group))
        || !(share_point = EC_POINT_new(group))
        || !(n = BN_new())
        || !(h = BN_new())
        || !(k = BN_new())
        || !(x = BN_new())
        || !(y = BN_new())
        || !(ctx = BN_CTX_new())) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    /* init ec domain parameters */
    if (!EC_GROUP_get_order(group, n, ctx)) {
        // ECerr(EC_F_SM2_DO_ENCRYPT, EC_R_ERROR);
        goto end;
    }

    // if (!EC_GROUP_get_cofactor(group, h, ctx)) 
    // {
    // 	// ECerr(EC_F_SM2_DO_ENCRYPT, EC_R_ERROR);
    // 	goto end;
    // }
    /* h = 1 */
    BN_one(h);

    /* check [h]P_B != O */
    if (!EC_POINT_mul(group, share_point, NULL, pubkey, h, ctx)) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
        goto end;
    }

    if (EC_POINT_is_at_infinity(group, share_point)) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, SM2_R_INVALID_PUBLIC_KEY);
        goto end;
    }

    do {
        /* rand k in [1, n-1] */
        do {
            BN_rand_range(k, n);
        } while (BN_is_zero(k));
        // printf("k:\n");
        // BN_print(k);

        /* compute ephem_point [k]G = (x1, y1) */
        if (!EC_POINT_mul(group, ephem_point, k, NULL, NULL, ctx)) {
            // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
            goto end;
        }

        /* compute ECDH share_point [k]P_B = (x2, y2) */
        if (!EC_POINT_mul(group, share_point, NULL, pubkey, k, ctx)) {
            // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
            goto end;
        }

        /* compute t = KDF(x2 || y2, klen) */
        if (!EC_POINT_get_affine_coordinates_GFp(group, share_point, x, y, ctx)) {
            //SM2err(SM2_F_SM2_DO_VERIFY, ERR_R_EC_LIB);
            goto end;
        }
        
        BN_bn2binpad(x, buf, 32);
        BN_bn2binpad(y, buf + 32, 32); /* sm2p256, coordinate is 256 bit integer */

        kdf(t, inlen, buf, 64);
    } while (CRYPTO_mem_is_zero(t, inlen));

    /* set x/yCoordinates as (x1, y1) */
    if (!EC_POINT_get_affine_coordinates_GFp(group, ephem_point, x, y, ctx)) {
        // SM2err(SM2_F_SM2_DO_ENCRYPT, ERR_R_EC_LIB);
        goto end;
    }

    /* C1 : */
    out[0] = 0x04;
    BN_bn2binpad(x, out + 1,  32);
    BN_bn2binpad(y, out + 33, 32);

    /* C2 : */
    // out += (1 + (conv_form == POINT_CONVERSION_COMPRESSED ? 32 : 64));
    out += 65;
    for (i = 0; i < inlen; i++) 
        out[i] = in[i] ^ t[i];

    /* C3 : Hash(x2 || M || y2) */
    out += inlen;
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, buf, 32);
    SM3_update(&sm3_ctx, in, inlen);
    SM3_update(&sm3_ctx, buf + 32, 32);
    SM3_final(&sm3_ctx, out);

    ret = 1;
end:
    CRYPTO_free(t);
    EC_POINT_free(share_point);
    EC_POINT_free(ephem_point);
    BN_free(n);
    BN_free(h);
    BN_free(x);
    BN_free(y);
    BN_clear_free(k);
    BN_CTX_free(ctx);
    return ret;
}

static int SM2_do_decrypt(const uint8_t *in, int inlen, 
                                uint8_t *out, int *outlen, const BIGNUM *privkey)
{
    int ret = GML_ERROR;
    const EC_GROUP *group = NULL;

    EC_POINT *point = NULL;
    // EC_POINT *tmp_point = NULL;
    BIGNUM *n = NULL;
    // BIGNUM *h = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;
    SM3_CTX sm3_ctx;

    uint8_t buf[64];
    uint8_t hash[32];
    uint8_t *t = NULL;
    int clen, i;

    group = SM2_get_group();

    if (out == NULL) {
        *outlen = 0;
        return 0;
    }
    /*
    if (*outlen < cv->ciphertext->length) {
        SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_BUFFER_TOO_SMALL);
        return 0;
    }
    */

    /* malloc */
    point = EC_POINT_new(group);
    // tmp_point = EC_POINT_new(group);
    n = BN_new();
    // h = BN_new();
    x = BN_new();
    y = BN_new();
    ctx = BN_CTX_new();
    // md_ctx = EVP_MD_CTX_new();
    if (!point || !n || !x || !y || !ctx) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    /* init ec domain parameters */
    if (!EC_GROUP_get_order(group, n, ctx)) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
        goto end;
    }

    /* get x/y Coordinates as C1 = (x1, y1) */
    // SM2_point_uncompress(x, y, in, ec_key);
    if (in[0] != 0x4)
        goto end;

    BN_bin2bn(in +  1, 32, x);
    BN_bin2bn(in + 33, 32, y);

    if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx)) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
        goto end;
    }

    if (EC_POINT_is_at_infinity(group, point)) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
        goto end;
    }

    /* compute ECDH [d]C1 = (x2, y2) */
    if (!EC_POINT_mul(group, point, NULL, point, privkey, ctx)) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, ERR_R_EC_LIB);
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx)) {
        //SM2err(SM2_F_SM2_SIGN_SETUP, ERR_R_EC_LIB);
        goto end;
    }

    BN_bn2binpad(x, buf, 32);
    BN_bn2binpad(y, buf + 32, 32);

    /* t = KDF(x2 || y2, clen) */
    clen = inlen - 97;
    t = CRYPTO_malloc(clen);
    if (t == NULL)
        goto end;

    kdf(t, clen, buf, 64);

    /* compute M = C2 xor t */
    // in += (1 + (conv_form == POINT_CONVERSION_COMPRESSED ? 32 : 64));
    in += 65;
    for (i = 0; i < clen; i++) 
        out[i] = in[i] ^ t[i];

    /* check hash == Hash(x2 || M || y2) */
    in += clen;
    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, buf, 32);
    SM3_update(&sm3_ctx, out, clen);
    SM3_update(&sm3_ctx, buf + 32, 32);
    SM3_final(&sm3_ctx, hash);

    if (CRYPTO_memcmp(hash, in, 32) != 0) {
        // SM2err(SM2_F_SM2_DO_DECRYPT, SM2_R_INVALID_CIPHERTEXT);
        goto end;
    }
    *outlen = inlen - 97;

    ret = 1;
end:
    CRYPTO_free(t);
    EC_POINT_free(point);
    BN_free(n);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
    return ret;
}

int SM2_encrypt(uint8_t **out, int *outlen, 
                const uint8_t *in, int inlen,
                const uint8_t pubkey_x[32], const uint8_t pubkey_y[32])
{
    int ret = GML_ERROR;
    int clen;
    BIGNUM *bx = NULL;
    BIGNUM *by = NULL;
    BIGNUM *bz = NULL;
    EC_POINT *point = NULL;

    if (in == NULL || out == NULL || inlen < 0 || pubkey_x == NULL || pubkey_y == NULL)
        goto end;

    clen = 1 + 64 + inlen + 32;
    *out = CRYPTO_malloc(clen);
    if (*out == NULL || outlen == NULL)
        goto end;

    bx = BN_new();
    by = BN_new();
    bz = BN_new();
    point = EC_POINT_new(sm2_group);
    if (!bx || !by || !bz || !point)
        goto end;

    BN_bin2bn(pubkey_x, 32, bx);
    BN_bin2bn(pubkey_y, 32, by);
    BN_one(bz);
    /* init public key */
    if (!EC_POINT_set_Jprojective_coordinates_GFp(sm2_group, point, bx, by, bz, NULL))
        goto end;

    if (SM2_do_encrypt(in, inlen, *out, point) == GML_ERROR) {
        *outlen = 0;
        goto end;
    }

    *outlen = clen;
    ret = GML_OK;
end:
    BN_free(bx);
    BN_free(by);
    BN_free(bz);
    EC_POINT_free(point);
    return ret;
}

int SM2_decrypt(uint8_t **out, int *outlen,
                const uint8_t *in, int inlen,
                const uint8_t privkey[32])
{
    int ret = GML_ERROR;
    BIGNUM *pkey = NULL;

    if (out == NULL || outlen == NULL || in == NULL || inlen <= 0 || privkey == NULL)
        goto end;

    *outlen = 0;
    pkey = BN_new();
    if (pkey == NULL)
        return 0;

    BN_bin2bn(privkey, 32, pkey);

    if (inlen <= 96 || inlen > INT_MAX)
        goto end;

    *out = CRYPTO_malloc(inlen - 97);
    if (*out == NULL)
        goto end;

    /* do decrypt */
    if (SM2_do_decrypt(in, inlen, *out, outlen, pkey) == GML_ERROR)
        goto end;

    ret = GML_OK;
end:
    BN_free(pkey);
    return ret;
}
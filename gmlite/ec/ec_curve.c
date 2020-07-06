/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
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

#include <string.h>
#include "ec_lcl.h"

typedef struct {
    int field_type,             /* either NID_X9_62_prime_field or
                                 * NID_X9_62_characteristic_two_field */
     seed_len, param_len;
    unsigned int cofactor;      /* promoted to BN_ULONG */
} EC_CURVE_DATA;

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_SM2_PRIME_256V1 = {
    {
        0, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        /* a */
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
        /* b */
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B,
        0xCF, 0x65, 0x09, 0xA7, 0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
        /* x */
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46,
        0x6A, 0x39, 0xC9, 0x94, 0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
        /* y */
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3,
        0x6B, 0x69, 0x21, 0x53, 0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
        /* order */
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
        0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
    }
};

static const struct {
    EC_CURVE_DATA h;
    unsigned char data[0 + 32 * 6];
} _EC_SM9_BN_256V1 = {
    {
        0, 0, 32, 1
    },
    {
        /* no seed */
        /* p */
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F,
        0xF5, 0x8E, 0xC7, 0x45, 0x21, 0xF2, 0x93, 0x4B, 0x1A, 0x7A, 0xEE, 0xDB,
        0xE5, 0x6F, 0x9B, 0x27, 0xE3, 0x51, 0x45, 0x7D,
        /* a */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* b */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        /* x */
        0x93, 0xDE, 0x05, 0x1D, 0x62, 0xBF, 0x71, 0x8F, 0xF5, 0xED, 0x07, 0x04,
        0x48, 0x7D, 0x01, 0xD6, 0xE1, 0xE4, 0x08, 0x69, 0x09, 0xDC, 0x32, 0x80,
        0xE8, 0xC4, 0xE4, 0x81, 0x7C, 0x66, 0xDD, 0xDD,
        /* y */
        0x21, 0xFE, 0x8D, 0xDA, 0x4F, 0x21, 0xE6, 0x07, 0x63, 0x10, 0x65, 0x12,
        0x5C, 0x39, 0x5B, 0xBC, 0x1C, 0x1C, 0x00, 0xCB, 0xFA, 0x60, 0x24, 0x35,
        0x0C, 0x46, 0x4C, 0xD7, 0x0A, 0x3E, 0xA6, 0x16,
        /* order */
        0xB6, 0x40, 0x00, 0x00, 0x02, 0xA3, 0xA6, 0xF1, 0xD6, 0x03, 0xAB, 0x4F,
        0xF5, 0x8E, 0xC7, 0x44, 0x49, 0xF2, 0x93, 0x4B, 0x18, 0xEA, 0x8B, 0xEE,
        0xE5, 0x6E, 0xE1, 0x9C, 0xD6, 0x9E, 0xCF, 0x25,
   }
};

typedef struct _ec_list_element_st {
    int nid;
    const EC_CURVE_DATA *data;
    const EC_METHOD *(*meth) (void);
    const char *comment;
} ec_list_element;

static const ec_list_element curve_list[] = {
    /* prime field curves */
    /* secg curves */

    {0, &_EC_SM2_PRIME_256V1.h,
# if !defined(SM2_NO_ASM) && (defined(__x86_64) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)) && (BN_BITS2 == 64)
    EC_GFp_sm2z256_method,
# elif defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
    EC_GFp_sm2p256_method,
# else
    EC_GFp_mont_method,
# endif
    "SM2 curve over a 256 bit prime field"},

    {1, &_EC_SM9_BN_256V1.h, 
    EC_GFp_mont_method,
    "SM9 BN curve over a 256 bit prime field"},
};

static EC_GROUP *ec_group_new_from_data(const ec_list_element curve)
{
    EC_GROUP *group = NULL;
    EC_POINT *P = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *order =
        NULL;
    int ok = 0;
    int param_len;
    const EC_METHOD *meth;
    const EC_CURVE_DATA *data;
    const unsigned char *params;

    /* If no curve data curve method must handle everything */
    // if (curve.data == NULL)
    //     return EC_GROUP_new(curve.meth != NULL ? curve.meth() : NULL);

    if ((ctx = BN_CTX_new()) == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    data = curve.data;
    param_len = data->param_len;
    params = (const unsigned char *)(data + 1); /* skip header */

    if ((p = BN_bin2bn(params + 0 * param_len, param_len, NULL)) == NULL
        || (a = BN_bin2bn(params + 1 * param_len, param_len, NULL)) == NULL
        || (b = BN_bin2bn(params + 2 * param_len, param_len, NULL)) == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }

    if (curve.meth != 0) {
        meth = curve.meth();
        if (((group = EC_GROUP_new(meth)) == NULL) ||
            (!(group->meth->group_set_curve(group, p, a, b, ctx)))) {
            //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
            goto err;
        }
    } 

    if ((P = EC_POINT_new(group)) == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }

    if ((x = BN_bin2bn(params + 3 * param_len, param_len, NULL)) == NULL
        || (y = BN_bin2bn(params + 4 * param_len, param_len, NULL)) == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx)) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    if ((order = BN_bin2bn(params + 5 * param_len, param_len, NULL)) == NULL
        || !BN_one(x)) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
        goto err;
    }
    if (!EC_GROUP_set_generator(group, P, order, x)) {
        //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
        goto err;
    }
    // if (seed_len) {
    //     if (!EC_GROUP_set_seed(group, params - seed_len, seed_len)) {
    //         //ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
    //         goto err;
    //     }
    // }
    ok = 1;
err:
    if (!ok) {
        EC_GROUP_free(group);
        group = NULL;
    }
    EC_POINT_free(P);
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    return group;
}

EC_GROUP *EC_GROUP_new_sm2()
{
    // size_t i;
    EC_GROUP *ret = NULL;

    ret = ec_group_new_from_data(curve_list[0]);

    if (ret == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
        return NULL;
    }

    return ret;
}

EC_GROUP *EC_GROUP_new_sm9()
{
    // size_t i;
    EC_GROUP *ret = NULL;

    ret = ec_group_new_from_data(curve_list[1]);

    if (ret == NULL) {
        //ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
        return NULL;
    }

    return ret;
}

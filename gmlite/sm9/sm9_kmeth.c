/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <gmlite/bn.h>
#include <gmlite/crypto.h>
#include <gmlite/ec.h>
#include <gmlite/sm3.h>
#include <gmlite/sm9.h>
#include "sm9_lcl.h"

int SM9_compute_master_pubkey(uint8_t master_privkey[32], uint8_t master_pubkey[129])
{
    int ret = GML_ERROR;
    BIGNUM *s = NULL;
    const BIGNUM *order = NULL;
    G2 *Ppub = NULL;
    const G2 *Q = NULL;
    const ATE_CTX *p_ctx = NULL;

    if (master_privkey == NULL || master_pubkey == NULL)
        goto end;

    s = BN_new();
    Ppub = G2_new();
    p_ctx = SM9_get_pairing_ctx();

    if (s == NULL || Ppub == NULL || p_ctx == NULL)
        goto end;

    order = PAIRING_get0_order(p_ctx);
    if (order == NULL)
        goto end;

    BN_bin2bn(master_privkey, 32, s);
    if (BN_is_zero(s) || BN_cmp(s, order) >= 0)
        goto end;

    /* G2 generator */
    Q = PAIRING_get0_generator2(p_ctx);
    if (Q == NULL)
        goto end;

    /* s * Q */
    G2_mul(Ppub, Q, s, p_ctx);

    G2_point_compress(master_pubkey, Ppub, p_ctx);

    ret = GML_OK;
end:
    BN_free(s);
    G2_free(Ppub);
    return ret;
}

/* master key */
int SM9_master_keygen(uint8_t master_privkey[32], uint8_t master_pubkey[129])
{
    int ret = GML_ERROR;
    BIGNUM *s = NULL;
    const BIGNUM *order = NULL;
    const ATE_CTX *p_ctx = NULL;

    if (master_privkey == NULL || master_pubkey == NULL)
        goto end;
    
    s = BN_new();
    p_ctx = SM9_get_pairing_ctx();

    if (s == NULL || p_ctx == NULL)
        goto end;

    order = PAIRING_get0_order(p_ctx);
    if (order == NULL)
        goto end;

    /* random s */
    do {
        if (!BN_rand_range(s, order)) 
            goto end;
    } while (BN_is_zero(s));
    BN_bn2binpad(s, master_privkey, 32);

    if (SM9_compute_master_pubkey(master_privkey, master_pubkey) != GML_OK)
        goto end;

    ret = GML_OK;
end:
    BN_free(s);
    return ret;
}

int SM9_usr_keygen(uint8_t usr_privkey[65], const uint8_t *id, int idlen, const uint8_t hid, const uint8_t master_privkey[32])
{
    int ret = GML_ERROR;
    BIGNUM *t = NULL;
    BIGNUM *s = NULL;
    BN_CTX *bn_ctx = NULL;
    G1 *da = NULL;
    const G1 *P = NULL;
    const BIGNUM *order = NULL;
    const ATE_CTX *p_ctx = NULL;

    if (usr_privkey == NULL || id == NULL || idlen <= 0 || master_privkey == NULL)
        goto end;

    t = BN_new();
    s = BN_new();
    bn_ctx = BN_CTX_new();
    da = G1_new();
    p_ctx = SM9_get_pairing_ctx();

    if (t == NULL || s == NULL || bn_ctx == NULL || da == NULL || p_ctx == NULL )
        goto end;

    order = PAIRING_get0_order(p_ctx);
    if (order == NULL)
        goto end;

    P = PAIRING_get0_generator1(p_ctx);
    if (P == NULL)
        goto end;

    /* t1 = H1(IDA || hid) + s */
    BN_bin2bn(master_privkey, 32, s);
    sm9_H1(t, id, idlen, &hid, 1, order);
    BN_mod_add(t, t, s, order, bn_ctx);

    /* t1^-1 */
    if (!BN_mod_inverse_Lehmer(t, t, order, bn_ctx))
        goto end;

    /* s * t1^-1 */
    BN_mod_mul(t, t, s, order, bn_ctx);

    /* t2 * P */
    G1_mul(da, P, t, p_ctx);

    G1_point_compress(usr_privkey, da, p_ctx);

    ret = GML_OK;
end:
    BN_free(t);
    BN_free(s);
    BN_CTX_free(bn_ctx);
    G1_free(da);
    return ret;
}
/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <gmlite/bn.h>
#include <gmlite/ec.h>
#include <gmlite/pairing.h>
#include <gmlite/sm9.h>
#include "sm9_lcl.h"

int SM9_sign(uint8_t h[32], uint8_t S[65], 
             const uint8_t *msg, int msglen, uint8_t rand[32], 
             const uint8_t usr_privkey[65], const uint8_t master_pubkey[129])
{
    int ret = GML_ERROR;
    uint8_t w[384];
    BIGNUM *h_bn = NULL;
    BIGNUM *r = NULL;
    const BIGNUM *order = NULL;
    BN_CTX *bn_ctx = NULL;
    const G1 *P = NULL;
    G1 *da = NULL;
    G2 *Ppub = NULL;
    GT *g = NULL;
    const ATE_CTX *p_ctx = NULL;

    if (h == NULL || S == NULL || msg == NULL || msglen < 0 || usr_privkey == NULL || master_pubkey == NULL)
        goto end;

    h_bn = BN_new();
    r = BN_new();
    bn_ctx = BN_CTX_new();
    da = G1_new();
    Ppub = G2_new();
    g = GT_new();
    p_ctx = SM9_get_pairing_ctx();

    if (h_bn == NULL || r == NULL || bn_ctx == NULL || da == NULL ||
        Ppub == NULL || g == NULL || p_ctx == NULL )
        goto end;

    order = PAIRING_get0_order(p_ctx);
    if (order == NULL)
        goto end;

    /* P */
    P = PAIRING_get0_generator1(p_ctx);
    if (P == NULL)
        goto end;
    /* Ppub */
    G2_point_uncompress(Ppub, master_pubkey, p_ctx);

    /* g = e(P, Ppub) */
    optate(g, P, Ppub, p_ctx);

    do {
        if (rand == NULL) {
            /* random r */
            do {
                if (!BN_rand_range(r, order)) 
                    goto end;
            } while (BN_is_zero(r));
        }
        else
            BN_bin2bn(rand, 32, r);
        
        fp12_pow(g, g, r, p_ctx);

        /*  */
        GT_to_bin(w, g, p_ctx);

        /* H2(M||w, N) */
        sm9_H2(h_bn, msg, msglen, w, 384, order);

        /* r - h */
        BN_mod_sub(r, r, h_bn, order, bn_ctx);
    } while(BN_is_zero(r));

    /* da */
    G1_point_uncompress(da, usr_privkey, p_ctx);
    /* (r - h) * da */
    G1_mul(da, da, r, p_ctx);

    BN_bn2binpad(h_bn, h, 32);
    G1_point_compress(S, da, p_ctx);

    ret = GML_OK;
end:
    BN_free(h_bn);
    BN_free(r);
    BN_CTX_free(bn_ctx);
    G1_free(da);
    G2_free(Ppub);
    GT_free(g);
    return ret;
}

int SM9_verify(uint8_t h[32], uint8_t S[65], 
               const uint8_t *msg, int msglen, 
               const uint8_t *id, int idlen, uint8_t hid,
               const uint8_t master_pubkey[129])
{
    int ret = GML_ERROR;
    uint8_t w[384];
    BIGNUM *h_bn = NULL;
    BIGNUM *h1 = NULL;
    BIGNUM *r = NULL;
    const BIGNUM *order = NULL;
    BN_CTX *bn_ctx = NULL;
    const G1 *P = NULL;
    G1 *S_point = NULL;
    G2 *Q = NULL;
    G2 *Ppub = NULL;
    GT *g = NULL;
    GT *u = NULL;
    const ATE_CTX *p_ctx = NULL;

    if (h == NULL || S == NULL || msg == NULL || msglen < 0 || id == NULL || idlen <= 0 || master_pubkey == NULL)
        goto end;

    h_bn = BN_new();
    h1 = BN_new();
    r = BN_new();
    bn_ctx = BN_CTX_new();
    S_point = G1_new();
    Q = G2_new();
    Ppub = G2_new();
    g = GT_new();
    u = GT_new();
    p_ctx = SM9_get_pairing_ctx();

    if (h_bn == NULL || h1 == NULL || r == NULL || bn_ctx == NULL || S_point == NULL ||
        Q == NULL || Ppub == NULL || g == NULL || u == NULL || p_ctx == NULL)
        goto end;

    order = PAIRING_get0_order(p_ctx);
    if (order == NULL)
        goto end;

    BN_bin2bn(h, 32, h_bn);
    if (BN_is_zero(h_bn) == 1 || BN_cmp(h_bn, order) >= 0)
        goto end;

    /* S */
    G1_point_uncompress(S_point, S, p_ctx);
    if (G1_is_on_curve(S_point, p_ctx) == 0)
        goto end;

    /* P */
    P = PAIRING_get0_generator1(p_ctx);
    if (P == NULL)
        goto end;
    /* Ppub */
    G2_point_uncompress(Ppub, master_pubkey, p_ctx);
    /* g = e(P, Ppub) */
    optate(g, P, Ppub, p_ctx);

    /* g^h */
    fp12_pow(g, g, h_bn, p_ctx);

    /* h1 = H1(IDA || hid, N) */
    sm9_H1(h1, id, idlen, &hid, 1, order);

    PAIRING_get_generator2(Q, p_ctx);
    /* h1 * Q + Ppub */
    G2_mul(Q, Q, h1, p_ctx);
    G2_add(Q, Q, Ppub, p_ctx);
    G2_makeaffine(Q, p_ctx);

    /* u = e(S, Q) */
    optate(u, S_point, Q, p_ctx);

    /* u * g^h */
    fp12_mul(u, u, g, p_ctx);

    GT_to_bin(w, u, p_ctx);
    /* H2(M || w, N) */
    sm9_H2(h1, msg, msglen, w, 384, order);

    if (BN_cmp(h_bn, h1) != 0)
        goto end;

    ret = GML_OK;
end:
    BN_free(h_bn);
    BN_free(h1);
    BN_free(r);
    BN_CTX_free(bn_ctx);
    G1_free(S_point);
    G2_free(Q);
    G2_free(Ppub);
    GT_free(g);
    GT_free(u);
    return ret;
}
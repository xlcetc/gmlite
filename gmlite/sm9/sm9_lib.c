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

static int sm9_H(BIGNUM *h, const uint8_t *a, int alen, const uint8_t *b, int blen, const BIGNUM *n, uint8_t x)
{
    int ret = GML_ERROR;
    int hlen;
    uint8_t *ha = NULL;
    uint8_t ctb[4];
    uint32_t ct = 1;
    SM3_CTX sm3_ctx;
    BIGNUM *nminus1 = NULL;
    BN_CTX *ctx = NULL;

    hlen = 8 * (((5 * BN_num_bits(n)) + 31) / 32);
    ha = (uint8_t*)CRYPTO_malloc((hlen + 255)/ 8);
    nminus1 = BN_new();
    ctx = BN_CTX_new();
    if (ha == NULL || nminus1 == NULL || ctx == NULL)
        goto end;

    BN_copy(nminus1, n);
    BN_sub_word(nminus1, 1);

    for (int i = 0; i < ((hlen + 255) / 256); i++) {
        u32_to_u8(&ct, 1, ctb, ORDER_BIG_ENDIAN);
        SM3_init(&sm3_ctx);
        SM3_update(&sm3_ctx, &x, 1);
        SM3_update(&sm3_ctx, a, alen);
        SM3_update(&sm3_ctx, b, blen);
        SM3_update(&sm3_ctx, ctb, 4);
        SM3_final(&sm3_ctx, ha + 32*i);
        ct++;
    }

    BN_bin2bn(ha, hlen / 8, h);
    BN_mod(h, h, nminus1, ctx);
    BN_add_word(h, 1);

    ret = GML_OK;
end:
    CRYPTO_free(ha);
    BN_free(nminus1);
    BN_CTX_free(ctx);
    return ret;
}

int sm9_H1(BIGNUM *h, const uint8_t *a, int alen, const uint8_t *b, int blen, const BIGNUM *n)
{
    return sm9_H(h, a, alen, b, blen, n, 1);
}

int sm9_H2(BIGNUM *h, const uint8_t *a, int alen, const uint8_t *b, int blen, const BIGNUM *n)
{
    return sm9_H(h, a, alen, b, blen, n, 2);
}


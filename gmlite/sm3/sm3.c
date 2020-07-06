/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <gmlite/common.h>
#include <gmlite/cpuid.h>
#include <gmlite/crypto.h>
#include <gmlite/sm3.h>
#include <string.h>
#include "sm3_lcl.h"

// void sm3_compress_c(uint32_t digest[8], const uint8_t block[SM3_BLOCK_SIZE], int nb);
// void sm3_compress_avx(uint32_t digest[8], const uint8_t block[SM3_BLOCK_SIZE], int nb);
void sm3_compress_avx2(uint32_t digest[8], const uint8_t block[SM3_BLOCK_SIZE], int nb);
const char *sm3_impl_name = NULL;
void (*sm3_compress_impl) (uint32_t digest[8], const uint8_t *block, int nb);

/* choose fastest sm3 implementation */
void runtime_choose_sm3_implementation()
{
    if (runtime_has_avx2() && runtime_has_bmi2()) {
        sm3_impl_name = "avx2 + bmi2";
        sm3_compress_impl = &sm3_compress_avx2;
        return;
    }

    // if (runtime_has_avx()) {
    //     sm3_compress_impl = SM3_AVX_IMPL();
    //     return;
    // }

    sm3_impl_name = "c";
    sm3_compress_impl = &sm3_compress_c;
}

const char* SM3_get_impl_name()
{
    return sm3_impl_name;
}

int SM3_init(SM3_CTX *ctx)
{
    if (ctx == NULL)
        return GML_ERROR;

    ctx->digest[0] = 0x7380166FU;
    ctx->digest[1] = 0x4914B2B9U;
    ctx->digest[2] = 0x172442D7U;
    ctx->digest[3] = 0xDA8A0600U;
    ctx->digest[4] = 0xA96F30BCU;
    ctx->digest[5] = 0x163138AAU;
    ctx->digest[6] = 0xE38DEE4DU;
    ctx->digest[7] = 0xB0FB0E4EU;

    ctx->nblocks = 0;
    ctx->num = 0;
    return GML_OK;
}

int SM3_update(SM3_CTX *ctx, const uint8_t* data, unsigned int data_len)
{
    unsigned int num, n;

    if (sm3_compress_impl == NULL || ctx == NULL || data == NULL)
        return GML_ERROR;

    num = ctx->num;

    if (num) {
        unsigned int left = SM3_BLOCK_SIZE - num;
        if (data_len < left) {
            memcpy(ctx->block + num, data, data_len);
            num += data_len;
            ctx->num = num;
            return GML_OK;
        } else {
            memcpy(ctx->block + num, data, left);
            sm3_compress_impl(ctx->digest, ctx->block, 1);
            ctx->nblocks++;
            data += left;
            data_len -= left;
        }
    }

    n = (data_len >> 6);
    ctx->nblocks += n;
    if (n > 0)
        sm3_compress_impl(ctx->digest, data, n);

    data += (SM3_BLOCK_SIZE*n);
    data_len &= 0x3fU;
    ctx->num = data_len;

    if (data_len > 0)
        memcpy(ctx->block, data, data_len);

    return GML_OK;
}

int SM3_final(SM3_CTX *ctx, uint8_t *digest)
{
    int i;
    int num;
    if (sm3_compress_impl == NULL || ctx == NULL || digest == NULL)
        return GML_ERROR;

    num = ctx->num;
    uint32_t *pdigest = (uint32_t*)digest;
    uint32_t *count = (uint32_t*)(ctx->block + SM3_BLOCK_SIZE - 8);

    ctx->block[num] = 0x80U;
    if (num + 9 <= SM3_BLOCK_SIZE)
        memset(ctx->block + num + 1, 0, SM3_BLOCK_SIZE - num - 9);
    else {
        memset(ctx->block + num + 1, 0, SM3_BLOCK_SIZE - num - 1);
        sm3_compress_impl(ctx->digest, ctx->block, 1);
        memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
    }

    count[0] = to_be32((ctx->nblocks) >> 23);
    count[1] = to_be32((ctx->nblocks << 9) + (num << 3));

    sm3_compress_impl(ctx->digest, ctx->block, 1);
    for (i = 0; i < 8; i++)
        pdigest[i] = to_be32(ctx->digest[i]);

    CRYPTO_memzero((void*)ctx, sizeof(SM3_CTX));
    return GML_OK;
}

int SM3_final_noclear(SM3_CTX *ctx, uint8_t *digest)
{
    if (sm3_compress_impl == NULL || ctx == NULL || digest == NULL)
        return GML_ERROR;

    int i;
    int num;
    uint32_t *pdigest = (uint32_t*)digest;
    uint32_t tdigest[8];
    uint8_t block[SM3_BLOCK_SIZE];
    uint32_t *count = (uint32_t*)(block + SM3_BLOCK_SIZE - 8);

    tdigest[0] = ctx->digest[0];
    tdigest[1] = ctx->digest[1];
    tdigest[2] = ctx->digest[2];
    tdigest[3] = ctx->digest[3];
    tdigest[4] = ctx->digest[4];
    tdigest[5] = ctx->digest[5];
    tdigest[6] = ctx->digest[6];
    tdigest[7] = ctx->digest[7];
    num = ctx->num;
    memcpy(block, ctx->block, num);
    block[num] = 0x80U;

    if (num + 9 <= SM3_BLOCK_SIZE) 
        memset(block + num + 1, 0, SM3_BLOCK_SIZE - num - 9);
    else {
        memset(block + num + 1, 0, SM3_BLOCK_SIZE - num - 1);
        sm3_compress_impl(tdigest, block, 1);
        memset(block, 0, SM3_BLOCK_SIZE - 8);
    }

    count[0] = to_be32((ctx->nblocks) >> 23);
    count[1] = to_be32((ctx->nblocks << 9) + (num << 3));

    sm3_compress_impl(tdigest, block, 1);
    for (i = 0; i < sizeof(tdigest)/sizeof(tdigest[0]); i++) 
        pdigest[i] = to_be32(tdigest[i]);

    CRYPTO_memzero(tdigest, SM3_DIGEST_LENGTH);
    return GML_OK;
}

int SM3_once(const uint8_t *msg, unsigned int msg_len, uint8_t digest[SM3_DIGEST_LENGTH])
{
    SM3_CTX sm3_ctx;
    if (sm3_compress_impl == NULL || msg == NULL || digest == NULL)
        return GML_ERROR;

    SM3_init(&sm3_ctx);
    SM3_update(&sm3_ctx, msg, msg_len);
    SM3_final(&sm3_ctx, digest);
    return GML_OK;
}
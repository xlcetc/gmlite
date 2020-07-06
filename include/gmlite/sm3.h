/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef SM3_HEADER_H
#define SM3_HEADER_H

#include <gmlite/common.h>

#define SM3_DIGEST_LENGTH   32
#define SM3_BLOCK_SIZE      64

#ifdef __cplusplus
extern "C" {
#endif

typedef struct 
{
    uint32_t digest[8];
    uint32_t nblocks;
    uint8_t block[SM3_BLOCK_SIZE];
    int num;
}SM3_CTX;

GML_EXPORT int SM3_init(SM3_CTX *ctx);

GML_EXPORT int SM3_update(SM3_CTX *ctx, const uint8_t* in, unsigned int inlen);

GML_EXPORT int SM3_final(SM3_CTX *ctx, uint8_t digest[SM3_DIGEST_LENGTH]);

GML_EXPORT int SM3_final_noclear(SM3_CTX *ctx, uint8_t digest[SM3_DIGEST_LENGTH]);

GML_EXPORT int SM3_once(const uint8_t *msg, unsigned int msglen, uint8_t digest[SM3_DIGEST_LENGTH]);

/* get sm3 implementation's name */
GML_EXPORT const char* SM3_get_impl_name();

int ssmm33_test();

#ifdef __cplusplus
}
#endif

#endif
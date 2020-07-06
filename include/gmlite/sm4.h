/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef SM4_HEADER_H 
#define SM4_HEADER_H

# include <string.h>
# include <gmlite/common.h>

// \SM4算法密钥长度
# define SM4_KEY_LENGTH           16
// \SM4算法明文分组长度
# define SM4_BLOCK_SIZE           16
// \SM4算法的IV长度
# define SM4_IV_LENGTH            SM4_BLOCK_SIZE
# define SM4_NUM_ROUNDS           32

// \加解密标志
// \加密
# define SM4_ENC              1
// \解密
# define SM4_DEC              0

#ifdef __cplusplus
extern "C" {
#endif

// \功能：SM4算法的密钥结构体定义
struct sm4_key_st
{
    uint32_t key[SM4_NUM_ROUNDS];
};

typedef struct sm4_key_st SM4_KEY;

GML_EXPORT int SM4_set_key(const uint8_t *usrkey, int keylen, SM4_KEY *key);

/* encrypt 16 bytes block */
GML_EXPORT void SM4_encrypt_block(uint8_t out[16], const uint8_t in[16], const SM4_KEY *key);

/* decrypt 16 bytes block */
GML_EXPORT void SM4_decrypt_block(uint8_t out[16], const uint8_t in[16], const SM4_KEY *key);

// GML_EXPORT int SM4_ecb_encrypt(uint8_t *out, int *out_len, const uint8_t *in, int in_len, const SM4_KEY *key, const int flag);

GML_EXPORT int SM4_ecb(uint8_t *out, int *outlen,
                      const uint8_t *in, int inlen, 
                      const uint8_t *usrkey, int keylen, 
                      const int flag);

# ifdef __cplusplus
}
# endif // __cplusplus

#endif 

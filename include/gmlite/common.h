/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_COMMON_H
# define HEADER_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include "config.h"

#define GML_OK      1 /* success */
#define GML_ERROR   0 /* error */

#ifdef __cplusplus
extern "C" {
#endif

/* gml_inline: portable inline definition usable in public headers */
# if !defined(inline) && !defined(__cplusplus)
#  if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L
   /* just use inline */
#   define gml_inline inline
#  elif defined(__GNUC__) && __GNUC__>=2
#   define gml_inline __inline__
#  elif defined(_MSC_VER)
  /*
   * Visual Studio: inline is available in C++ only, however
   * __inline is available for C, see
   * http://msdn.microsoft.com/en-us/library/z8y1yy88.aspx
   */
#   define gml_inline __inline
#  else
#   define gml_inline
#  endif
# else
#  define gml_inline inline
# endif

#ifndef GML_BUILD_STATIC
# ifdef _WIN32
#   ifdef GML_BUILD_SHARED
#     define GML_EXPORT __declspec(dllexport)
#   else
#     define GML_EXPORT __declspec(dllimport)
    #endif
# else
#   if (defined(__GNUC__) && __GNUC__>= 4)
#     define GML_EXPORT __attribute__ ((visibility ("default")))
#   endif
# endif
#else
# define GML_EXPORT
#endif

#define ORDER_BIG_ENDIAN     0
#define ORDER_LITTLE_ENDIAN  1

# if defined(__GNUC__) && __GNUC__>=2
#  if defined(__x86_64) || defined(__x86_64__)
#   define BSWAP8(x) ({ uint64_t ret_=(x);                   \
                        asm ("bswapq %0"                \
                        : "+r"(ret_));   ret_;          })
#   define BSWAP4(x) ({ uint32_t ret_=(x);                   \
                        asm ("bswapl %0"                \
                        : "+r"(ret_));   ret_;          })
#  elif (defined(__i386) || defined(__i386__)) && !defined(I386_ONLY)
#   define BSWAP8(x) ({ uint32_t lo_=(uint64_t)(x)>>32,hi_=(x);   \
                        asm ("bswapl %0; bswapl %1"     \
                        : "+r"(hi_),"+r"(lo_));         \
                        (uint64_t)hi_<<32|lo_;               })
#   define BSWAP4(x) ({ uint32_t ret_=(x);                   \
                        asm ("bswapl %0"                \
                        : "+r"(ret_));   ret_;          })
#  elif defined(__aarch64__)
#   define BSWAP8(x) ({ uint64_t ret_;                       \
                        asm ("rev %0,%1"                \
                        : "=r"(ret_) : "r"(x)); ret_;   })
#   define BSWAP4(x) ({ uint32_t ret_;                       \
                        asm ("rev %w0,%w1"              \
                        : "=r"(ret_) : "r"(x)); ret_;   })
#  elif (defined(__arm__) || defined(__arm))
#   define BSWAP8(x) ({ uint32_t lo_=(uint64_t)(x)>>32,hi_=(x);   \
                        asm ("rev %0,%0; rev %1,%1"     \
                        : "+r"(hi_),"+r"(lo_));         \
                        (uint64_t)hi_<<32|lo_;               })
#   define BSWAP4(x) ({ uint32_t ret_;                       \
                        asm ("rev %0,%1"                \
                        : "=r"(ret_) : "r"((uint32_t)(x)));  \
                        ret_;                           })
#  endif
# elif defined(_MSC_VER)
#  if _MSC_VER>=1300
#   include <stdlib.h>
#   pragma intrinsic(_byteswap_uint64,_byteswap_ulong)
#   define BSWAP8(x)    _byteswap_uint64((uint64_t)(x))
#   define BSWAP4(x)    _byteswap_ulong((uint32_t)(x))
#  elif defined(_M_IX86)
__inline uint32_t _bswap4(uint32_t val)
{
_asm mov eax, val _asm bswap eax}
#   define BSWAP4(x)    _bswap4(x)
#  endif
# endif

#define ROTL32(a, n) (((a) << n) | ((a) >> (32-n)))
#define ROTR32(a, n) (((a) >> n) | ((a) << (32-n)))
#define ROTL64(a, n) (((a) << n) | ((a) >> (64-n)))
#define ROTR64(a, n) (((a) >> n) | ((a) << (64-n)))

#if !defined(BSWAP8)
# define BSWAP8(x)  ((ROTL64(x,  8) & 0x000000ff000000ff) | \
                     (ROTL64(x, 24) & 0x0000ff000000ff00) | \
                     (ROTR64(x, 24) & 0x00ff000000ff0000) | \
                     (ROTR64(x,  8) & 0xff000000ff000000))
#endif

#if !defined(BSWAP4)
# define BSWAP4(x)  ((ROTL32(x, 8) & 0x00ff00ff) | (ROTR32(x, 8) & 0xff00ff00))
#endif

GML_EXPORT uint32_t to_be32(const uint32_t in);
GML_EXPORT uint32_t to_le32(const uint32_t in);

GML_EXPORT int u8_to_u32(const uint8_t *in, int in_len, uint32_t *out, int order);
GML_EXPORT int u32_to_u8(const uint32_t *in, int in_len, uint8_t *out, int order);

GML_EXPORT int u8_to_u64(const uint8_t *in, int in_len, uint64_t *out, int order);
GML_EXPORT int u64_to_u8(const uint64_t *in, int in_len, uint8_t *out, int order);

GML_EXPORT int u32_to_hex(const uint32_t *in, int in_len, uint8_t *out, int order);

GML_EXPORT int u8_to_hex(const uint8_t *in, int in_len, uint8_t *out);
GML_EXPORT int hex_to_u8(const uint8_t *in, int in_len, uint8_t *out);

GML_EXPORT int hex_to_u64(const uint8_t *in, int in_len, uint64_t *out);
GML_EXPORT int u64_to_hex(const uint64_t *in, int in_len, uint8_t *out);

GML_EXPORT int CRYPTO_mem_xor(uint8_t *out, const uint8_t *in1, const uint8_t *in2, int len);

GML_EXPORT int CRYPTO_pkcs7_pad(unsigned char *buf, unsigned int unpadded_buflen, unsigned int blocksize);

GML_EXPORT int CRYPTO_pkcs7_unpad(unsigned int *unpadded_buflen_p, unsigned char *buf, unsigned int blocksize);

GML_EXPORT int CRYPTO_memcmp(const uint8_t *a, const uint8_t *b, int n);

GML_EXPORT int CRYPTO_mem_is_zero(const uint8_t *in, int n);

GML_EXPORT void print_hex(const char *name, unsigned char *s, int slen);

#ifdef __cplusplus
}
#endif

#endif
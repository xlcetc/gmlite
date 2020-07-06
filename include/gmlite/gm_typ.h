/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_OPENSSL_TYPES_H
# define HEADER_OPENSSL_TYPES_H

#include <limits.h>

#ifdef  __cplusplus
extern "C" {
#endif

# ifdef BIGNUM
#  undef BIGNUM
# endif

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_mont_ctx_st BN_MONT_CTX;

#ifdef  __cplusplus
}
#endif

#endif

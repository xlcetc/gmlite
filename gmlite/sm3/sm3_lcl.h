/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_SM3_LCL_H
#define HEADER_SM3_LCL_H

#include <gmlite/sm3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* impl name */
extern const char *sm3_impl_name;
/* compress function */
extern void (*sm3_compress_impl) (uint32_t digest[8], const uint8_t *block, int nb);

extern void sm3_compress_c(uint32_t digest[8], const uint8_t *block, int nb);

/* choose fastest implementation */
void runtime_choose_sm3_implementation();

#endif

#ifdef __cplusplus
}
#endif

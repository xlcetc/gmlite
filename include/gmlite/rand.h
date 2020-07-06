/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_RAND_H
#define HEADER_RAND_H

#include <gmlite/common.h>

#ifdef __cplusplus
extern "C" {
#endif

GML_EXPORT int RAND_buf(uint8_t *buf, int len);

#ifdef __cplusplus
}
#endif

#endif
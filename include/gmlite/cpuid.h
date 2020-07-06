/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_CPUID_H
#define HEADER_CPUID_H

#include <gmlite/common.h>

#ifdef __cplusplus
extern "C" {
#endif

GML_EXPORT int runtime_has_neon(void);

GML_EXPORT int runtime_has_sse2(void);

GML_EXPORT int runtime_has_sse3(void);

GML_EXPORT int runtime_has_ssse3(void);

GML_EXPORT int runtime_has_sse41(void);

GML_EXPORT int runtime_has_avx(void);

GML_EXPORT int runtime_has_avx2(void);

GML_EXPORT int runtime_has_avx512f(void);

GML_EXPORT int runtime_has_bmi2(void);

GML_EXPORT int runtime_has_pclmul(void);

GML_EXPORT int runtime_has_aesni(void);

GML_EXPORT int runtime_has_rdrand(void);

GML_EXPORT int runtime_has_rdseed(void);

GML_EXPORT int _runtime_get_cpu_features(void);
/* TODO : ... */
extern unsigned int cpu_info[4];


#ifdef __cplusplus
}
#endif

#endif
/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_CRYPTO_H
# define HEADER_CRYPTO_H

# include <gmlite/common.h>
# include <gmlite/gm_typ.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* initialization, it must be call once before calling any other functions */
GML_EXPORT int CRYPTO_init(void);
/* free all data initialized in CRYPTO_init */
GML_EXPORT int CRYPTO_deinit(void);

GML_EXPORT int CRYPTO_alloc_init();

GML_EXPORT void* CRYPTO_malloc(size_t size);
GML_EXPORT void* CRYPTO_zalloc(size_t size);
GML_EXPORT void CRYPTO_free(void *ptr);
GML_EXPORT void CRYPTO_memzero(void *ptr, size_t size);
GML_EXPORT void CRYPTO_clear_free(void *ptr, size_t len);

GML_EXPORT void* CRYPTO_secure_malloc(size_t size);
GML_EXPORT void* CRYPTO_secure_zalloc(size_t size);
GML_EXPORT void CRYPTO_secure_free(void *ptr);

GML_EXPORT int CRYPTO_crit_enter(void);
GML_EXPORT int CRYPTO_crit_leave(void);

# define CRYPTO_malloc_MAX_NELEMS(type)  (((1ULL<<(sizeof(size_t)*8-1))-1)/sizeof(type))

#ifdef  __cplusplus
}
#endif

#endif
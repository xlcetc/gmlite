/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#ifndef HEADER_SM9_H
#define HEADER_SM9_H

#include <gmlite/bn.h>
#include <gmlite/common.h>
#include <gmlite/ec.h>
#include <gmlite/pairing.h>
#include <gmlite/sm3.h>

# ifdef __cplusplus
extern "C" {
# endif

GML_EXPORT const EC_GROUP* SM9_get_group();

GML_EXPORT const ATE_CTX* SM9_get_pairing_ctx();

GML_EXPORT int SM9_compute_master_pubkey(uint8_t master_privkey[32], uint8_t master_pubkey[129]);

GML_EXPORT int SM9_master_keygen(uint8_t master_privkey[32], uint8_t master_pubkey[129]);

GML_EXPORT int SM9_usr_keygen(uint8_t usr_privkey[65], const uint8_t *id, int idlen, const uint8_t hid, const uint8_t master_privkey[32]);

GML_EXPORT int SM9_sign(uint8_t h[32], uint8_t S[65], 
                        const uint8_t *msg, int msglen, uint8_t rand[32], 
                        const uint8_t usr_privkey[65], const uint8_t master_pubkey[129]);

GML_EXPORT int SM9_verify(uint8_t h[32], uint8_t S[65], 
                          const uint8_t *msg, int msglen, 
                          const uint8_t *id, int idlen, uint8_t hid,
                          const uint8_t master_pubkey[129]);

# ifdef __cplusplus
}
# endif

#endif
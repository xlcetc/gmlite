#ifndef HEADER_SM2_LCL_H
#define HEADER_SM2_LCL_H

#include "../ec/ec_lcl.h"

extern const EC_GROUP *sm2_group;

// typedef struct sm2_sk_precomp
// {
//     uint8_t d[32];
//     uint8_t dinv[32];
// } SM2_SK_PRE_COMP;

int sm2_group_init();
int sm2_sig_asn1_encode(uint8_t sig[128], int *siglen, uint8_t r[32], uint8_t s[32]);
int sm2_sig_asn1_decode(uint8_t r[32], uint8_t s[32], uint8_t sig[128], int siglen);

#endif
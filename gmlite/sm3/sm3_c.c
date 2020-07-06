/*
 * Copyright 2020 cetcxl. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <gmlite/common.h>
#include <gmlite/crypto.h>
#include <gmlite/sm3.h>
#include "sm3_lcl.h"

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17)) 
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23)) 

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

void sm3_compress_c(uint32_t digest[8], const uint8_t *block, int nb)
{
    int i, j;
    uint32_t W[68], W1[64];

    for (i = 0; i < nb; i++) {
        const uint32_t *pblock = (const uint32_t *)block;
        
        uint32_t A = digest[0];
        uint32_t B = digest[1];
        uint32_t C = digest[2];
        uint32_t D = digest[3];
        uint32_t E = digest[4];
        uint32_t F = digest[5];
        uint32_t G = digest[6];
        uint32_t H = digest[7];
        uint32_t SS1,SS2,TT1,TT2,T[64];

        for (j = 0; j < 16; j++)
            W[j] = to_be32(pblock[j]);

        for (j = 16; j < 68; j++)
            W[j] = P1(W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7) ^ W[j-6];

        for( j = 0; j < 64; j++)
            W1[j] = W[j] ^ W[j+4];

        for(j = 0; j < 16; j++) {
            T[j] = 0x79CC4519;
            SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7); 
            SS2 = SS1 ^ ROTATELEFT(A,12);
            TT1 = FF0(A,B,C) + D + SS2 + W1[j];
            TT2 = GG0(E,F,G) + H + SS1 + W[j];
            D = C;
            C = ROTATELEFT(B,9);
            B = A;
            A = TT1;
            H = G;
            G = ROTATELEFT(F,19);
            F = E;
            E = P0(TT2);
        }

        for(j = 16; j < 64; j++) {
            T[j] = 0x7A879D8A;
            SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7); 
            SS2 = SS1 ^ ROTATELEFT(A,12);
            TT1 = FF1(A,B,C) + D + SS2 + W1[j];
            TT2 = GG1(E,F,G) + H + SS1 + W[j];
            D = C;
            C = ROTATELEFT(B,9);
            B = A;
            A = TT1;
            H = G;
            G = ROTATELEFT(F,19);
            F = E;
            E = P0(TT2);
        }

        digest[0] ^= A;
        digest[1] ^= B;
        digest[2] ^= C;
        digest[3] ^= D;
        digest[4] ^= E;
        digest[5] ^= F;
        digest[6] ^= G;
        digest[7] ^= H;

        block += SM3_BLOCK_SIZE;
    }
}
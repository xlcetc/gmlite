#include <string.h>
#include <gmlite/sm3.h>
#include <gmlite/common.h>
#include <gmlite/ec.h>

/* SM3_DIGEST_LENGTH = 32 
    z = x||y, (x,y) is a point on elliptic curve(sm2p256)
    zlen : 64, 
*/
void kdf(uint8_t *out, int klen, const uint8_t *z, int zlen)
{
    assert(zlen == 64);
    int i, round;
    /* z_copy = z */
    uint8_t z_copy[68];
    /* points to last 4 bytes of z_copy */
    uint8_t *z_copy_ctr;
    /* counter */
    uint32_t ctr[1] = {1};
    uint8_t tmp[32];
    /*  */
    round = (klen - klen % 32) / 32;
    
    memcpy(z_copy, z, zlen);
    z_copy_ctr = z_copy + 64;
    for (i = 0; i < round; i++) {
        u32_to_u8(ctr, 1, z_copy_ctr, ORDER_BIG_ENDIAN);
        SM3_once(z_copy, 68, out);
        ctr[0]++;
        out += SM3_DIGEST_LENGTH;
    }

    if (klen % 32 != 0) {
        u32_to_u8(ctr, 1, z_copy_ctr, ORDER_BIG_ENDIAN);
        SM3_once(z_copy, 68, tmp);
        for (i = 0; i < klen % 32; i++)
            out[i] = tmp[i];
    }
}

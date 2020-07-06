#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmlite/common.h>

/* 0->'0', 1->'1', ... , 15->'F' */
static const uint8_t ascii_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static const uint8_t inv_ascii_table[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0,    1,    2,    3,    4,    5,    6,    7,
       8,    9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff,   10,   11,   12,   13,   14,   15, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

int gml_err(int func, int err)
{
    return func | err;
}

uint32_t to_be32(const uint32_t in)
{
    int ret = in;
    if (ENDIANESS == ORDER_LITTLE_ENDIAN)
        ret = BSWAP4(in);

    return ret;
}

uint32_t to_le32(const uint32_t in)
{
    int ret = in;
    if (ENDIANESS == ORDER_BIG_ENDIAN)
        ret = BSWAP4(in);

    return ret;
}

int u8_to_u32(const uint8_t *in, int in_len, uint32_t *out, int order)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (in_len % 4 != 0)
        return GML_ERROR;
    
    if (order == ENDIANESS) {
        for (int i = 0; i < in_len; i += 4) {
            out[0] = *(uint32_t*)(in + i);
            out++;
        }
    }
    else {
        for (int i = 0; i < in_len; i += 4) {
            out[0] = *(uint32_t*)(in + i);
            out[0] = BSWAP4(out[0]);
            out++;
        }
    }

    return GML_OK;
}

int u32_to_u8(const uint32_t *in, int in_len, uint8_t *out, int order)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (order == ENDIANESS) {
        for (int i = 0; i < in_len; i++) {
            *(uint32_t*)out = in[i];
            out += 4;
        }
    }
    else {
        for (int i = 0; i < in_len; i++) {
            *(uint32_t*)out = BSWAP4(in[i]);
            out += 4;
        }
    }

    return GML_OK;
}

int u8_to_u64(const uint8_t *in, int in_len, uint64_t *out, int order)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (in_len % 8 != 0)
        return GML_ERROR;
    
    if (order == ENDIANESS) {
        for (int i = 0; i < in_len; i += 8) {
            out[0] = *(uint64_t*)(in + i);
            out++;
        }
    }
    else {
        for (int i = 0; i < in_len; i += 8) {
            out[0] = *(uint64_t*)(in + i);
            out[0] = BSWAP8(out[0]);
            out++;
        }
    }

    return GML_OK;
}

int u64_to_u8(const uint64_t *in, int in_len, uint8_t *out, int order)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (order == ENDIANESS) {
        for (int i = 0; i < in_len; i++) {
            *(uint64_t*)out = in[i];
            out += 8;
        }
    }
    else {
        for (int i = 0; i < in_len; i++) {
            *(uint64_t*)out = BSWAP8(in[i]);
            out += 8;
        }
    }

    return GML_OK;
}

int u32_to_hex(const uint32_t *in, int in_len, uint8_t *out, int order)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;
    
    if (order == ORDER_BIG_ENDIAN) {
        for (int i = 0; i < in_len; i++) {
            out[0] = ascii_table[in[i] >> 28];
            out[1] = ascii_table[(in[i] >> 24) & 0xf];
            out[2] = ascii_table[(in[i] >> 20) & 0xf];
            out[3] = ascii_table[(in[i] >> 16) & 0xf];
            out[4] = ascii_table[(in[i] >> 12) & 0xf];
            out[5] = ascii_table[(in[i] >>  8) & 0xf];
            out[6] = ascii_table[(in[i] >>  4) & 0xf];
            out[7] = ascii_table[in[i] & 0xf];
            out += 8;
        }
    }

    if (order == ORDER_LITTLE_ENDIAN) {
        for (int i = 0; i < in_len; i++) {
            out[6] = ascii_table[in[i] >> 28];
            out[7] = ascii_table[(in[i] >> 24) & 0xf];
            out[4] = ascii_table[(in[i] >> 20) & 0xf];
            out[5] = ascii_table[(in[i] >> 16) & 0xf];
            out[2] = ascii_table[(in[i] >> 12) & 0xf];
            out[3] = ascii_table[(in[i] >>  8) & 0xf];
            out[0] = ascii_table[(in[i] >>  4) & 0xf];
            out[1] = ascii_table[in[i] & 0xf];
            out += 8;
        }
    }

    return GML_OK;
}

int u8_to_hex(const uint8_t *in, int in_len, uint8_t *out)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    for (int i = 0; i < in_len; i++) {
        out[0] = ascii_table[in[i] >> 4];
        out[1] = ascii_table[in[i] & 0xf];
        out += 2;
    }
    return GML_OK;
}

int hex_to_u8(const uint8_t *in, int in_len, uint8_t *out)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (in_len % 2 != 0)
        return GML_ERROR;

    for (int i = 0; i < in_len; i += 2) {
        out[0] = (inv_ascii_table[in[i]] << 4) | inv_ascii_table[in[i+1]];
        out++;
    }
    return GML_OK;
}

int hex_to_u64(const uint8_t *in, int in_len, uint64_t *out)
{
    if (in == NULL || out == NULL)
        return GML_ERROR;

    if (in_len % 16 != 0)
        return GML_ERROR;

    for (int i = 0; i < in_len; i += 16) {
        hex_to_u8(in + i, 16, (uint8_t*)out);
        if (ENDIANESS == ORDER_LITTLE_ENDIAN)
            out[0] = BSWAP8(out[0]);
        out++;
    }

    return GML_OK;
}

int u64_to_hex(const uint64_t *in, int in_len, uint8_t *out)
{
    uint8_t tmp[8];

    if (in == NULL || out == NULL)
        return GML_ERROR;

    for (int i = 0; i < in_len; i++) {
        u64_to_u8(in + i, 1, tmp, ORDER_BIG_ENDIAN);
        u8_to_hex(tmp, 8, out);
        out += 16;
    }

    return GML_OK;
}

void print_hex(const char *name, unsigned char *s, int slen)
{
    for(int i = 0; i < strlen(name); i++)
        printf("%c", name[i]);
    unsigned char *hex = (unsigned char*)malloc(2*slen);
    u8_to_hex(s, slen, hex);
    for(int i = 0; i < 2*slen; i++)
        printf("%c", hex[i]);
    printf("\n");
    free(hex);
}

/* constant time PKCS7 padding */
int CRYPTO_pkcs7_pad(unsigned char *buf, unsigned int unpadded_buflen, unsigned int blocksize)
{
    unsigned char           *tail;
    unsigned int            i;
    unsigned int            xpadlen;
    volatile unsigned char  mask;
    unsigned char           pad;

    if (blocksize <= 0U || blocksize >= 256U || unpadded_buflen >= blocksize)
        return GML_ERROR;

    xpadlen = blocksize - unpadded_buflen;
    pad = (unsigned char)xpadlen;
    tail = &buf[blocksize - 1U];

    mask = 0U;
    for (i = 0U; i < blocksize; i++) {
        mask |= (unsigned char) (((i ^ xpadlen) - 1U)
           >> ((sizeof(unsigned int) - 1) * 8));
        *(tail - i) = ((*(tail - i)) & mask) | (pad & (~mask));
    }

    return GML_OK;
}

/* constant time PKCS7 unpadding */
int CRYPTO_pkcs7_unpad(unsigned int *unpadded_buflen_p, unsigned char *buf, unsigned int blocksize)
{
    const unsigned char       *tail;
    unsigned char              mask = 0U;
    unsigned char              c;
    unsigned char              invalid = 0U;
    unsigned int               i;
    unsigned char              pad;

    if (blocksize <= 0U || blocksize >= 256U)
        return GML_ERROR;

    tail = &buf[blocksize - 1U];
    pad = *tail;

    for (i = 0U; i < blocksize; i++) {
        c = *(tail - i);
        mask |= (unsigned char) (((i ^ (unsigned int) pad) - 1U) >> ((sizeof(unsigned int) - 1) * 8));
        invalid |= (c ^ pad) & (~mask);
    }
    *unpadded_buflen_p = blocksize - (unsigned int) pad;

    return (int)(invalid == 0U && pad <= blocksize);
}
#include <string.h>
#include <gmlite/crypto.h>

void* CRYPTO_zalloc(size_t size)
{
    void *ret = malloc(size);
    memset(ret, 0, size);
    return ret;
}

void* CRYPTO_malloc(size_t size)
{
    return malloc(size);
}

void CRYPTO_free(void *ptr)
{
    free(ptr);
}

void CRYPTO_clear_free(void *ptr, size_t size)
{
    memset(ptr, 0, size);
    free(ptr);
}


int CRYPTO_mem_xor(uint8_t *out, const uint8_t *in1, const uint8_t *in2, int len)
{
    if (in1 == NULL || in2 == NULL || len <= 0 || out == NULL)
        return GML_ERROR;

    for (int i = 0; i < len; i++)
        out[i] = in1[i] ^ in2[i];

    return GML_OK;
}

/* 0 : equal, otherwise not equal */
int CRYPTO_memcmp(const uint8_t *a, const uint8_t *b, int n)
{
    uint8_t r = 0;
    if (a == NULL || b == NULL || n < 0)
        return 0;

    for (int i = 0; i < n; i++) 
        r |= (a[i] ^ b[i]);

    return (r != 0);
}

// /*  */
int CRYPTO_mem_is_zero(const uint8_t *in, int n)
{
    uint8_t r = 0;
    if (in == NULL || n <= 0)
        return 1;

    for (int i = 0; i < n; i++)
        r |= in[i];

    return (r == 0);
}
#include "test.h"

/* emmmm */
int main(int argc, char **argv)
{
    int N = 1000;
    void *ptr;

    if (CRYPTO_init() == GML_ERROR)
        return -1;

    for (int i = 0; i < N; i++) {
        ptr = CRYPTO_secure_malloc(256);
        CRYPTO_secure_free(ptr);
    }

    for (int i = 0; i < N; i++) {
        ptr = CRYPTO_secure_zalloc(256);
        CRYPTO_secure_free(ptr);
    }

    CRYPTO_deinit();
    return 0;
}
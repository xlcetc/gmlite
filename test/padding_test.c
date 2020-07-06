#include "test.h"

#define BLOCK_SIZE_MAX 256

static void padding_test(void *p)
{
    int N;
    uint8_t block[BLOCK_SIZE_MAX];
    uint8_t block1[BLOCK_SIZE_MAX];
    unsigned int len;
    unsigned int unpadded_len;
    int blocksize;

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    for (int i = 0; i < N; i++) {
        /* random blocksize */
        do {
            blocksize = random_number() % BLOCK_SIZE_MAX;
        } while (blocksize == 0);
        /* random unpadded length */
        len = random_number() % blocksize;
        /* random unpadded block */
        random_string(block, len);

        /* pad */
        if (CRYPTO_pkcs7_pad(block, len, blocksize) == GML_ERROR) {
            args->ok = GML_ERROR;
            printf("CRYPTO_pkcs7_pad FAIL\n");
            goto end;
        }
        memcpy(block1, block, blocksize);

        /* unpad */
        if (CRYPTO_pkcs7_unpad(&unpadded_len, block1, blocksize) == GML_ERROR) {
            args->ok = GML_ERROR;
            printf("CRYPTO_pkcs7_unpad FAIL\n");
            goto end;
        }

        /* compare */
        if (unpadded_len != len || CRYPTO_memcmp(block, block1, len) != 0) {
            args->ok = GML_ERROR;
            printf("wrong unpadded block\n");
            goto end;
        }
    }

    args->ok = GML_OK;
end:
    return;
}

int main(int argc, char **argv)
{
    if (CRYPTO_init() == GML_ERROR)
        return -1;

    TEST_ARGS args;
    args.ok = 0;
    args.N = 88888;
    args.num_threads = 4;
    get_test_arg(argc, argv, &args);

    printf("-----------PKCS7 PADDING TEST------------ \n");
    padding_test((void*)&args); if(!args.ok) return -1;

    CRYPTO_deinit();
    return 0;
}
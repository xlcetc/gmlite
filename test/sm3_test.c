#include "test.h"

typedef struct
{
    /* input */
    char *in;
    /* hash (hex) */
    char *hash;
}SM3_TEST_VECTOR;

static SM3_TEST_VECTOR sm3_test_vec[] =
{
    /* 1 */
    {
        "abc",
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    },
    /* 2 */
    {
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    },
    /* 3 */
    {
        "Fed launches unlimited QE, but markets keep falling - as it happened",
        "45f5f7e2b7e7cdef2bc0766e193754e1875830b44e067d3bcc71304721875da8",
    },
    /* 4 */
    {
        "A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution",
        "08c7dd4278a47bac588686088f2ea7c68ebdf297ca8a0d1fab08929c37fb68d5",
    },
    /* 5 */
    {
        "1DRHyarV9Zb6i5JHhUfJ9tM4d5Vit72y4d",
        "7b46253a4faba655669b34ed16d28c5241387a9dc378b009f3fcf6d747a2c596",
    },
    /* 6 */
    {
        "gmlite is a secure, simple and multi-platform crypto library",
        "3896af8cacf9315671a1c036712d85ccacc3ce231753e0c0a6345713e8ea5a04",
    },
    /* 7 */
    {
        "Copyright (C) 2019, 2020 CHINA ELECTRONICS TECHNOLOGY CYBER SECURYITY CO.,LTD.",
        "08711d2c9f459f750b9363759d20d4435d2967c101fd753923ad62524cafacdf",
    },
    /* 8 */
    {
        "Bitcoin is a collection of of concepts and technologies that form the basis of a digital money ecosystem",
        "a3fd2167b9c72b3858f5a9441db93947146a7ee8597d042318da1d7fb0e42712",
    }
};

int sm3_test_case()
{
    int ret = GML_ERROR;
    uint8_t h1[32];
    uint8_t h2[32];

    for (int i = 0; i < sizeof(sm3_test_vec) / sizeof(SM3_TEST_VECTOR); i++) {
        SM3_once((uint8_t*)sm3_test_vec[i].in, strlen(sm3_test_vec[i].in), h1);
        hex_to_u8((uint8_t*)sm3_test_vec[i].hash, 64, h2);
        if (memcmp(h1, h2, 32) != 0) {
            printf("sm3 test case %d failed\n", i+1);
            goto end;
        }
    }

    printf("sm3 test case PASS \n");
    ret = GML_OK;
end:
    return ret;
}

int sm3_test()
{
    int N = 100000;
    uint8_t msg[1024];
    int msglen;
    uint8_t d1[SM3_DIGEST_LENGTH], d2[SM3_DIGEST_LENGTH], d3[SM3_DIGEST_LENGTH];
    SM3_CTX sm3_ctx;

    for (int i = 0; i < N; i++) {
        /* random message length */
        msglen = random_number() % 1024;
        /* random message */
        random_string(msg, msglen);
        /*  */
        SM3_once(msg, msglen, d1);
        SM3_once(msg, msglen/2, d3);

        SM3_init(&sm3_ctx);
        SM3_update(&sm3_ctx, msg, msglen/2);
        SM3_final_noclear(&sm3_ctx, d2);
        if (CRYPTO_memcmp(d3, d2, SM3_DIGEST_LENGTH) != 0) {
            printf("SM3_final_noclear fail\n");
            return GML_ERROR;
        }
        SM3_update(&sm3_ctx, msg + msglen/2, msglen - msglen/2);
        SM3_final_noclear(&sm3_ctx, d2);
        
        if (CRYPTO_memcmp(d1, d2, SM3_DIGEST_LENGTH) != 0) {
            printf("SM3_final_noclear fail\n");
            return GML_ERROR;
        }
    }

    printf("sm3 test PASS \n");
    return GML_OK;
}

int main(int argc, char **argv)
{
    if (CRYPTO_init() == GML_ERROR)
        return -1;

    if (sm3_test_case() == GML_ERROR)
        return -1;

    if (sm3_test() == GML_ERROR)
        return -1;

    CRYPTO_deinit();
    return 0;
}

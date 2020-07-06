#include "test.h"

/*  */
static int N = 22222;

int sm4_test1()
{
    SM4_KEY key;
    unsigned char out[16];
    unsigned char plain_text[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char user_key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char *test1result = (unsigned char*)"\x68\x1E\xDF\x34\xD2\x06\x96\x5E\x86\xB3\xE9\x4F\x53\x6E\x42\x46";
    int res;
    
    SM4_set_key((const unsigned char *)user_key, 16, &key);
    SM4_encrypt_block(out, (const unsigned char *)plain_text, &key);
    
    res = memcmp(out, test1result, 16);
    
    if (res != 0) {
        printf("SM4 ENCRYPTION FAIL");
        return -1;
    }
    
    SM4_decrypt_block(out, (const unsigned char *)out, &key);
    
    res = memcmp(out, plain_text, 16);
    
    if (res != 0) {
        print_hex("1:", plain_text, 16);
        print_hex("2:", out, 16);
        print_hex("3:", test1result, 16);
        printf("SM4 DECRYPTION FAIL");
        return -1;
    }
    
    return 0;
}

#define MAXLEN 250

int sm4_test2()
{
    int len;
    int enc_len;
    int dec_len;
    unsigned char rand_plain[MAXLEN];
    unsigned char out[MAXLEN + 16];
    unsigned char recover[MAXLEN + 16];
    unsigned char user_key[16];
    
    for (int i = 0; i < N; i++) {
        /* random key */
        random_string(user_key, 16);
        // SM4_set_key((const unsigned char *)user_key, 16, &key);

        /* random plaintext,  */
        len = rand() % MAXLEN;
        random_string(rand_plain, len);

        /* encrypt */
        if (SM4_ecb(out, &enc_len, rand_plain, len, user_key, 16, SM4_ENC) == GML_ERROR) {
            printf("sm4 ecb encryption FAIL \n");
            return -1;
        }

        /* decrypt */
        if (SM4_ecb(recover, &dec_len, out, enc_len, user_key, 16, SM4_DEC) == GML_ERROR ||
            len != dec_len || memcmp(rand_plain, recover, len) != 0) {
            printf("sm4 ecb decryption FAIL \n");
            return -1;
        }
    }

    printf("sm4 ecb test PASS \n");
    return 0;
}

int main(int argc, char **argv)
{
    TEST_ARGS args;
    args.ok = 0;
    args.N = 250250;
    args.num_threads = 4;

    if (CRYPTO_init() == GML_ERROR)
        return -1;

    get_test_arg(argc, argv, &args);

    if (sm4_test1() == -1)
        return -1;

    if (sm4_test2() == -1)
        return -1;

    CRYPTO_deinit();
    return 0;
}

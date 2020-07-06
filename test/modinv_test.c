#include "test.h"

static const unsigned char gn[32] = 
{   0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};

int main(int argc, char **argv)
{
    unsigned char in[32];
    static BIGNUM *order = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *c = NULL;
    BN_CTX *ctx = NULL;

    if (CRYPTO_init() == GML_ERROR)
        return -1;

    TEST_ARGS args;
    args.ok = 0;
    args.N = 77777;
    args.num_threads = 0;

    if(!order)
    {
        order = BN_new();
        BN_bin2bn(gn, 32, order);
    }
    a = BN_new();
    b = BN_new();
    c = BN_new();
    ctx = BN_CTX_new();

    uint8_t bb[32], bb_hex[64];
    uint8_t cc[32], cc_hex[64];
    for(int i = 0; i < args.N; i++)
    {
        random_string(in, 32);
        BN_bin2bn(in, 32, a);

        BN_mod_inverse(b, a, order, ctx);
        BN_mod_inverse_Lehmer(c, a, order, ctx);

        if(BN_cmp(b, c) != 0)
        {
            /* print b */
            BN_bn2binpad(b, bb, 32);
            u8_to_hex(bb, 32, bb_hex);
            printf("bin exgcd\n");
            for(int i = 0; i < 64; i++)
            {
                printf("%c", bb_hex[i]);
            }
            printf("\n");

            /* print c */
            BN_bn2binpad(c, cc, 32);
            u8_to_hex(cc, 32, cc_hex);
            printf("lehmer exgcd\n");
            for(int i = 0; i < 64; i++)
            {
                printf("%c", cc_hex[i]);
            }
            printf("\n");

            printf("mod_inverse test failed\n");
            return -1;
        }
    }

    printf("mod_inverse test PASS\n");
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_CTX_free(ctx);
    CRYPTO_deinit();
    return 0;
}
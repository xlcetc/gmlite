#include "../test/test.h"
#include "speed_lcl.h"

typedef struct
{
    int do_sm2;
    int do_sm3;
    int do_sm4;
    int do_sm9;
    int do_pairing;
    int do_ct;
    int do_dkmixer;
    int do_mod_inverse;
    int do_wb;
} SPEED_TEST;

static SPEED_TEST speed_test;

/* sig r */
uint8_t r_hex[65] = "cd706bfe896006c0b2edae8b3f47d1875de7fc25db9a790b13d947284b942bf4" ;
uint8_t r[32];

/* sig s */
uint8_t s_hex[65] = "ba7d22d23f838d76493a8c6b35aebf2aed20bec422f33881ef88f3cdda6ee29e";
uint8_t s[32];

/*  */
uint8_t msg[147] = "190815000210001,0400f935d3097d871ae79f679f639a91f769eec2f9eb2433c480d4f48a17e59f5f5a12fffc7eb76f7ec17228b44b0b17cd7aebe0887e860ff519b9f2b70c4e6ae4";

/* e = SM3(ZA || m) */
uint8_t e_hex[65] = "0000000000000000000000000000000000000000000000000000000000000000";
uint8_t e[32];

/* 私钥 r */
uint8_t privkey_hex[65] = "837F26CF4A5A9CC5FDE16602CEFF5CFB22B1E3E53D0ADC40FEF1BF6B9EC8371E";
uint8_t privkey[32];

/* 公钥 (x, y) */
uint8_t pubkey_hex_x[65] = "E3D37935C0EC25A4552CB76E7CDB92F43D5C80EAD30D7D85D8E87BEA3B6F2746";
uint8_t pubkey_hex_y[65] = "EA9089635D0705C4BBC19A354A1950A5887D7CBD2DC2F5B266BC0690663B4E5C";
uint8_t pubkey_x[32];
uint8_t pubkey_y[32];

static unsigned char in[32] = 
{   0x0C, 0x4E, 0x00, 0xDE, 0xAF, 0x45, 0xE0, 0xFC, 0x7F, 0xEF, 0x5F, 0x6F,
    0x50, 0x4F, 0x0F, 0x2C, 0x12, 0xE3, 0xD0, 0x63, 0x01, 0xA6, 0x35, 0x1B,
    0x53, 0xAA, 0xA2, 0xB9, 0x39, 0xE5, 0x11, 0x99};

static const unsigned char gn[32] = 
{   0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
    0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23};

/* TODO : add keygen speed test */

/* -----sm2 hash speed test----- */
static void sm2_hash_sign_speed(void *p)
{
    int N;
    double usec;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));
    uint8_t sig[128];
    int siglen;
    hex_to_u8(e_hex, 64, e);
    hex_to_u8(privkey_hex, 64, privkey);
    hex_to_u8(pubkey_hex_x, 64, pubkey_x);
    hex_to_u8(pubkey_hex_y, 64, pubkey_y);
    SM2_CTX_init(sm2_ctx, NULL, NULL);
    int mode;
    mode = SM2_SIG_RS_ASN1;

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM2_sign(sig, &siglen, e, NULL, privkey, mode, sm2_ctx);
    
    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    // tt = t / 1000000;
    printf("sign : %d  op/s\n\n", (int)((double)N*1000000/usec));
    SM2_CTX_clear_free(sm2_ctx);
}

static void sm2_hash_sign_multithread_speed(TEST_ARGS *args)
{
    if (args->num_threads > 0) {
        printf("--------------SM2 HASH SIGN MULTITHREAD SPEED TEST--------------- \n");
        printf("number of threads : %ld \n\n", args->num_threads);
        test_start_n_thread(sm2_hash_sign_speed, (void*)args);
    }
}

static void sm2_hash_verify_speed(void *p)
{
    int N;
    double usec;
    unsigned char buf[32];
    uint8_t sig[128];
    int siglen;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));
    hex_to_u8(r_hex, 64, r);
    hex_to_u8(s_hex, 64, s);
    hex_to_u8(e_hex, 64, e);
    hex_to_u8(privkey_hex, 64, privkey);
    hex_to_u8(pubkey_hex_x, 64, pubkey_x);
    hex_to_u8(pubkey_hex_y, 64, pubkey_y);
    SM2_CTX_init(sm2_ctx, pubkey_x, pubkey_y);
    int mode;
    mode = SM2_SIG_RS_ASN1;

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;
    SM2_sign(sig, &siglen, e, NULL, privkey, mode, sm2_ctx);

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        SM2_verify(sig, siglen, buf, pubkey_x, pubkey_y, mode, sm2_ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("verify : %d  op/s\n\n", (int)((double)N*1000000/usec));
    SM2_CTX_clear_free(sm2_ctx);
}

static void sm2_hash_verify_multithread_speed(TEST_ARGS *p)
{
    if (p->num_threads > 0) {
        printf("--------------SM2 HASH VERIFY MULTITHREAD SPEED TEST--------------- \n");
        printf("number of threads : %ld \n\n", p->num_threads);
        test_start_n_thread(sm2_hash_verify_speed, (void*)p);
    }
}

/* -----sm2 msg speed test----- */
static void sm2_msg_sign_speed(void *p)
{
    int N;
    double usec;
    unsigned char msg[32];
    unsigned char id[16];
    int idlen = 16;
    int msglen = 32;
    uint8_t sig[128];
    int siglen;
    int mode;
    mode = SM2_SIG_RS_ASN1;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));
    SM2_CTX_init(sm2_ctx, NULL, NULL);
    SM2_keygen(privkey, pubkey_x, pubkey_y);

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM2_sign_ex(sig, &siglen, msg, msglen, id, idlen, NULL, pubkey_x, pubkey_y, privkey, mode, sm2_ctx);
    
    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    // tt = t / 1000000;
    printf("sign : %d  op/s\n\n", (int)((double)N*1000000/usec));
    SM2_CTX_clear_free(sm2_ctx);
}

static void sm2_msg_sign_multithread_speed(TEST_ARGS *args)
{
    if (args->num_threads > 0) {
        printf("--------------SM2 MESSAGE SIGN MULTITHREAD SPEED TEST--------------- \n");
        printf("number of threads : %ld \n\n", args->num_threads);
        test_start_n_thread(sm2_msg_sign_speed, (void*)args);
    }
}

static void sm2_msg_verify_speed(void *p)
{
    int N;
    double usec;
    unsigned char msg[32];
    int msglen = 32;
    unsigned char id[32];
    int idlen = 32;
    uint8_t sig[128];
    int siglen;
    int mode;
    mode = SM2_SIG_RS_ASN1;
    SM2_CTX *sm2_ctx = NULL;
    sm2_ctx = (SM2_CTX*)CRYPTO_zalloc(sizeof(SM2_CTX));
    hex_to_u8(r_hex, 64, r);
    hex_to_u8(s_hex, 64, s);
    hex_to_u8(pubkey_hex_x, 64, pubkey_x);
    hex_to_u8(pubkey_hex_y, 64, pubkey_y);
    // SM2_CTX_init(sm2_ctx, pubkey_x, pubkey_y);
    SM2_CTX_init(sm2_ctx, pubkey_x, pubkey_y);

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;
    SM2_sign_ex(sig, &siglen, msg, msglen, id, idlen, NULL, pubkey_x, pubkey_y, privkey, mode, sm2_ctx);

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM2_verify_ex(sig, siglen, msg, msglen, id, idlen, pubkey_x, pubkey_y, mode, sm2_ctx);
    
    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("verify : %d  op/s\n\n", (int)((double)N*1000000/usec));
    SM2_CTX_clear_free(sm2_ctx);
}

static void sm2_msg_verify_multithread_speed(TEST_ARGS *args)
{
    if (args->num_threads > 0) {
        printf("--------------SM2 MESSAGE VERIFY MULTITHREAD SPEED TEST--------------- \n");
        printf("number of threads : %ld \n\n", args->num_threads);
        test_start_n_thread(sm2_msg_verify_speed, (void*)args);
    }
}

/************** sm3 speed test **************/
static void sm3_speed(void *p)
{
    int64_t N;
    double usec;
    double avg_speed_MB, avg_speed_Gb;
    const int64_t block = 8192;

    uint8_t digest[32];
    unsigned char msg[8192];

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N * 5 > 100000 ? 100000 : args->N * 5;

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        SM3_once(msg, block, digest);

    COUNTER_STOP();
    TIMER_STOP();

    usec = USEC();
    avg_speed_MB = (N * block) / usec;
    avg_speed_Gb = 8 * avg_speed_MB / 1000;

    printf("average cycles per block : %ld \n", (int64_t)(TICKS() / (N * block / 64)));
    printf("block(B) \t  time(ms)  \t  speed(MB/s)  \t speed(Gb/s) \n");
    printf("   %ld     \t  %.4f  \t    %.4f   \t   %.4f \n\n", block, usec/1000, avg_speed_MB, avg_speed_Gb);
}

static void sm3_multithread_speed(TEST_ARGS *args)
{
    if (args->num_threads > 0) {
        printf("--------------SM3 MULTITHREAD SPEED TEST--------------- \n");
        printf("number of threads : %ld \n\n", args->num_threads);
        test_start_n_thread(sm3_speed, (void*)args);
    }
}

/************** sm4 speed test *****************/
static void sm4_speed(void *p)
{
    double usec;
    int N;
    unsigned char in[16], out[16];
    double avg_speed_MB, avg_speed_Gb;

    SM4_KEY *sm4_key = (SM4_KEY*)malloc(sizeof(SM4_KEY));
    SM4_set_key(r, 32, sm4_key);

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = (args->N * 100) > 10000000 ? 10000000 : (args->N * 100);

    BENCH_VARS;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        SM4_encrypt_block(in, out, sm4_key);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    avg_speed_MB = (16 * N) / usec;
    avg_speed_Gb = 8 * avg_speed_MB / 1000;

    printf("----------SM4 ENCRYPTION SPEED TEST-----------\n");
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("data(MB) \t  time(ms)  \t  speed(MB/s)  \t speed(Gb/s) \n");
    printf("   %d    \t  %.4f  \t    %.4f   \t   %.4f \n\n", 16*N/1000000, usec/1000, avg_speed_MB, avg_speed_Gb);
}

/************** sms9 speed test *****************/
static void sm9_speed(void *p)
{
    int N;
    double usec;

    /* message */
    uint8_t msg[32];
    int msglen = 32;
    /* id */
    uint8_t id[8];
    int idlen = 8;
    /* hid */
    uint8_t hid = 1;
    /* h */
    uint8_t h[32];
    /* S */
    uint8_t S[65];
    /*  */
    uint8_t user_privkey[65];
    /*  */
    uint8_t master_privkey[32];
    /*  */
    uint8_t master_pubkey[129];

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    BENCH_VARS;

    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM9_master_keygen(master_privkey, master_pubkey);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("SM9 master keygen : %d  op/s\n\n", (int)((double)N*1000000/usec));

    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM9_usr_keygen(user_privkey, id, idlen, hid, master_privkey);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("SM9 usr keygen : %d  op/s\n\n", (int)((double)N*1000000/usec));

    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM9_sign(h, S, msg, msglen, NULL, user_privkey, master_pubkey);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("SM9 sign : %d  op/s\n\n", (int)((double)N*1000000/usec));

    COUNTER_START();
    TIMER_START();
    
    for (int i = 0; i < N; i++)
        SM9_verify(h, S, msg, msglen, id, idlen, hid, master_pubkey);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("SM9 verify : %d  op/s\n\n", (int)((double)N*1000000/usec));
}

/************** mod inverse speed test *****************/
static void bn_mod_inverse_speed(void *p)
{
    static BIGNUM *order = NULL;
    static BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BN_CTX *ctx = NULL;
    int N;
    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    if(!order)
    {
        order = BN_new();
        BN_bin2bn(gn, 32, order);
    }
    a = BN_new();
    b = BN_new();
    ctx = BN_CTX_new();
    double usec;

    random_string(in, 32);
    BN_bin2bn(in, 32, a);

    /* binary gcd */
    BENCH_VARS;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        BN_mod_inverse(b, a, order, ctx);

    COUNTER_STOP();
    TIMER_STOP();

    usec = USEC();

    printf("--------------MOD INVERSE SPEED TEST--------------- \n");
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("binary exgcd: %d  op/s\n\n", (int)((double)N*1000000/usec));

    /* lehmer gcd */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        BN_mod_inverse_Lehmer(b, a, order, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    
    usec = USEC();

    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("lehmer exgcd: %d  op/s\n\n", (int)((double)N*1000000/usec));
}

/* TODO : need better parser */
int get_speed_test_args(int argc, char **argv, TEST_ARGS *args)
{
    int ret = GML_ERROR;
    memset(args, 0, sizeof(TEST_ARGS));
    memset(&speed_test, 0, sizeof(SPEED_TEST));
    
    if (argc == 1) {
        /* do all speed test */
        memset(&speed_test, 1, sizeof(SPEED_TEST));
    }

    for (int i = 1; i < argc; i++) {
        if (memcmp(argv[i], "THREADS=", 8) == 0 || memcmp(argv[i], "threads=", 8) == 0) {
            args->num_threads = atoi(argv[i] + 8);
            continue;
        }

        if (memcmp(argv[i], "t=", 2) == 0 || memcmp(argv[i], "T=", 2) == 0) {
            args->num_threads = atoi(argv[i] + 2);
            continue;
        }

        if (memcmp(argv[i], "n=", 2) == 0 || memcmp(argv[i], "N=", 2) == 0) {
            args->N = atoi(argv[i] + 2);
            continue;
        }

        if (memcmp(argv[i], "sm2", 3) == 0) {
            speed_test.do_sm2 = 1;
            continue;
        }

        if (memcmp(argv[i], "sm3", 3) == 0) {
            speed_test.do_sm3 = 1;
            continue;
        }

        if (memcmp(argv[i], "sm4", 3) == 0 || memcmp(argv[i], "sm4", 4) == 0) {
            speed_test.do_sm4 = 1;
            continue;
        }

        if (memcmp(argv[i], "sm9", 3) == 0) {
            speed_test.do_sm9 = 1;
            continue;
        }

        if (memcmp(argv[i], "modinv", 6) == 0) {
            speed_test.do_mod_inverse = 1;
            continue;
        }

        if (memcmp(argv[i], "pairing", 7) == 0) {
            speed_test.do_pairing = 1;
            continue;
        }
    }

    args->ok = 0;
    args->num_threads = args->num_threads >= 0 ? args->num_threads : 4;
    args->N = args->N > 0 ? args->N : 12345; 

    if(!speed_test.do_sm2 && 
       !speed_test.do_sm3 &&
       !speed_test.do_sm4 &&
       !speed_test.do_sm9 &&
       !speed_test.do_pairing &&
       !speed_test.do_ct &&
       !speed_test.do_dkmixer &&
       !speed_test.do_mod_inverse &&
       !speed_test.do_wb) {
        /* do all speed test */
        memset(&speed_test, 1, sizeof(SPEED_TEST));
    }
    return ret;
}

int main(int argc, char **argv)
{
    TEST_ARGS args;

    CRYPTO_init();

    get_speed_test_args(argc, argv, &args);

    // printf("N = %d \n\n", N);
    if (speed_test.do_sm2) {
        printf("--------------SM2 HASH SINGLETHREAD SPEED TEST--------------- \n");
        sm2_hash_sign_speed((void*)&args);
        sm2_hash_verify_speed((void*)&args);

        sm2_hash_sign_multithread_speed(&args);
        sm2_hash_verify_multithread_speed(&args);

        printf("--------------SM2 MESSAGE SINGLETHREAD SPEED TEST--------------- \n");
        sm2_msg_sign_speed((void*)&args);
        sm2_msg_verify_speed((void*)&args);

        sm2_msg_sign_multithread_speed(&args);
        sm2_msg_verify_multithread_speed(&args);
    }

    if (speed_test.do_sm3) {
        printf("------------SM3 SPEED TEST---------------\n");
        printf("------------- %s ----------------\n", SM3_get_impl_name());
        sm3_speed((void*)&args);
        sm3_multithread_speed(&args);
    }

    if (speed_test.do_sm4)
        sm4_speed((void*)&args);

    if (speed_test.do_sm9)
        sm9_speed((void*)&args);

    if (speed_test.do_mod_inverse)
        bn_mod_inverse_speed((void*)&args);

    if (speed_test.do_pairing)
        pairing_sm9_speed((void*)&args);

    CRYPTO_deinit();
    return 0;
}
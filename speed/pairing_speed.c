#include "speed_lcl.h"
#include "../gmlite/pairing/pairing_lcl.h"

int pairing_sm9_speed(void *p)
{
    int ret = GML_ERROR;
    int64_t N;
    double usec;;
    BIGNUM *s1 = NULL;
    BIGNUM *s2 = NULL;
    BIGNUM *st = NULL;
    const ATE_CTX *ctx = NULL;

    s1 = BN_new();
    s2 = BN_new();
    st = BN_new();
    G1 *op1 = G1_new();
    G2 *op2 = G2_new();
    GT *opt1 = GT_new();

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    ctx = SM9_get_pairing_ctx();
    if (ctx == NULL) {
        ret = -1;
        goto end;
    }

    G1_set_generator(op1, ctx);
    G2_set_generator(op2, ctx);
    optate(opt1, op1, op2, ctx);

    BENCH_VARS;

    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        optate(opt1, op1, op2, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("sm9 pairing : %d  op/s\n\n", (int)((double)N*1000000/usec));

    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        miller_loop(opt1, op1, op2, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("sm9 miller loop : %d  op/s\n\n", (int)((double)N*1000000/usec));

    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        final_expo(opt1, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("sm9 final expo : %d  op/s\n\n", (int)((double)N*1000000/usec));

    const EC_GROUP *sm9_group = SM9_get_group();
    BIGNUM *P=BN_new();
    BN_CTX *bbb=BN_CTX_new();
    EC_GROUP_get_curve_GFp(sm9_group, P, NULL, NULL,bbb);
    BN_MONT_CTX *mont = BN_MONT_CTX_new();
    BN_MONT_CTX_set(mont, P, bbb);
    BN_rand_range(s1, P);
    BN_rand_range(s2, P);
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        BN_mod_mul_montgomery(st, s1, s2, mont, bbb);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("mul mont : %d  op/s\n\n", (int)((double)N*1000000/usec));

    /* G1_mul */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        G1_mul(op1, op1, s1, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("G1_mul : %d  op/s\n\n", (int)((double)N*1000000/usec));

    /* G2_mul */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        G2_mul(op2, op2, s1, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("G2_mul : %d  op/s\n\n", (int)((double)N*1000000/usec));

    /* GT_pow */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp12_pow(opt1, opt1, s1, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("GT_pow : %d  op/s\n\n", (int)((double)N*1000000/usec));

    /* fp_mul */
    fp_t aa, bb, rr;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp_mul(rr, aa, bb, ctx->p, ctx->n0);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp_mul : %d  op/s\n\n", (int)((double)N*1000000/usec));  

    /* fp2_mul */
    fp2_t a, b, r;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp2_mul(r, a, b, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp2_mul : %d  op/s\n\n", (int)((double)N*1000000/usec));  

    /* fp2_square */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp2_square(r, a, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp2_square : %d  op/s\n\n", (int)((double)N*1000000/usec));  
    
    /* fp2_add */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp2_add(r, a, b, ctx->p);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp2_add : %d  op/s\n\n", (int)((double)N*1000000/usec));  

    /* fp2_set */
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp2_set(r, a);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp2_set : %d  op/s\n\n", (int)((double)N*1000000/usec));  

    /* fp12_square */
    fp12_t p12r, p12a;
    COUNTER_START();
    TIMER_START();

    for (int i = 0; i < N; i++)
        fp12_square(p12r, p12a, ctx);

    COUNTER_STOP();
    TIMER_STOP();
    usec = USEC();
    printf("average cycles per op : %d \n", (int)(TICKS()/N));
    printf("fp12_square : %d  op/s\n\n", (int)((double)N*1000000/usec));  

end:
    return ret;
}
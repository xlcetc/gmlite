#include "test.h"

void pairing_sm9_test(void *p)
{
    int N;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *c = NULL;
    const BIGNUM *order = NULL;
    BN_CTX *bn_ctx = NULL;
    const ATE_CTX *ctx = NULL;

    a = BN_new();
    b = BN_new();
    c = BN_new();
    bn_ctx = BN_CTX_new();
    G1 *P = G1_new();
    G1 *P1 = G1_new();
    G1 *P2 = G1_new();
    G2 *Q = G2_new();
    G2 *Q1 = G2_new();
    G2 *Q2 = G2_new();
    GT *R = GT_new();
    GT *R1 = GT_new();
    GT *R2 = GT_new();

    TEST_ARGS *args = (TEST_ARGS*)p;
    N = args->N;

    ctx = SM9_get_pairing_ctx();
    if (ctx == NULL) {
        args->ok = GML_ERROR;
        goto end;
    }

    order = PAIRING_get0_order(ctx);

    G1_set_generator(P, ctx);
    G2_set_generator(Q, ctx);
    optate(R, P, Q, ctx);

    /* R = e(P, Q)
     * R^(ab) ?= e(aP, bQ) 
     */
    for (int i = 0; i < N; i++) {
        BN_rand_range(a, order);
        G1_mul(P1, P, a, ctx);
        G1_makeaffine(P1, ctx);

        BN_rand_range(b, order);
        G2_mul(Q1, Q, b, ctx);
        G2_makeaffine(Q1, ctx);

        optate(R1, P1, Q1, ctx);
    
        BN_mod_mul(c, a, b, order, bn_ctx);
        fp12_pow(R2, R, c, ctx);

        if (fp12_cmp(R1, R2) != 0) {
            args->ok = GML_ERROR;
            printf("pairing test FAIL\n R = e(P, Q)\n (R^(ab) ?= e(P1, Q1)) \n");
            goto end;
        }
    }

    /* R1 = e(P1, Q), R2 = e(P2, Q)
     * R1 * R2 ?= e(P1 + P2, Q) 
     */
    for (int i = 0; i < N; i++) {
        BN_rand_range(a, order);
        G1_mul(P1, P, a, ctx);
        G1_makeaffine(P1, ctx);
        optate(R1, P1, Q, ctx);

        BN_rand_range(b, order);
        G1_mul(P2, P, b, ctx);
        G1_makeaffine(P2, ctx);
        optate(R2, P2, Q, ctx);

        fp12_mul(R2, R1, R2, ctx);

        G1_add(P1, P1, P2, ctx);
        G1_makeaffine(P1, ctx);
        optate(R1, P1, Q, ctx);

        if (fp12_cmp(R1, R2) != 0) {
            args->ok = GML_ERROR;
            printf("pairing test FAIL\n R1 = e(P1, Q), R2 = e(P2, Q)\n (R1 * R2 ?= e(P1 + P2, Q)) \n");
            goto end;
        }
    }

    /* R1 = e(P, Q1), R2 = e(P, Q2)
     * R1 * R2 ?= e(P, Q1 + Q2) 
     */
    for (int i = 0; i < N; i++) {
        BN_rand_range(a, order);
        G2_mul(Q1, Q, a, ctx);
        G2_makeaffine(Q1, ctx);
        optate(R1, P, Q1, ctx);

        BN_rand_range(b, order);
        G2_mul(Q2, Q, b, ctx);
        G2_makeaffine(Q2, ctx);
        optate(R2, P, Q2, ctx);
    
        fp12_mul(R2, R1, R2, ctx);

        G2_add(Q1, Q1, Q2, ctx);
        G2_makeaffine(Q1, ctx);
        optate(R1, P, Q1, ctx);

        if (fp12_cmp(R1, R2) != 0) {
            args->ok = GML_ERROR;
            printf("pairing test FAIL\n R1 = e(P, Q1), R2 = e(P, Q2)\n (R1 * R2 ?= e(P, Q1 + Q2)) \n");
            goto end;
        }
    }

    printf("pairing test PASS\n");
    args->ok = GML_OK;
end:
    BN_free(a);
    BN_free(b);
    BN_free(c);
    BN_CTX_free(bn_ctx);
    G1_free(P);
    G1_free(P1);
    G1_free(P2);
    G2_free(Q);
    G2_free(Q1);
    G2_free(Q2);
    GT_free(R);
    GT_free(R1);
    GT_free(R2);
}

int main(int argc, char **argv)
{
    if (CRYPTO_init() == GML_ERROR)
        return -1;

    TEST_ARGS args;
    args.ok = 0;
    args.N = 1111;
    args.num_threads = 4;

    get_test_arg(argc, argv, &args);

    /* single thread test */
    printf("-----------PAIRING SM9 TEST------------ \n");
    pairing_sm9_test((void*)&args); if(!args.ok) return -1;

    CRYPTO_deinit();
    return 0;
}
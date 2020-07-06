/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "bn_lcl.h"

static BIGNUM *euclid(BIGNUM *a, BIGNUM *b);

int BN_gcd(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
{
    BIGNUM *a, *b, *t;
    int ret = GML_ERROR;

    bn_check_top(in_a);
    bn_check_top(in_b);

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    if (a == NULL || b == NULL)
        goto err;

    if (BN_copy(a, in_a) == NULL)
        goto err;
    if (BN_copy(b, in_b) == NULL)
        goto err;
    a->neg = 0;
    b->neg = 0;

    if (BN_cmp(a, b) < 0) {
        t = a;
        a = b;
        b = t;
    }
    t = euclid(a, b);
    if (t == NULL)
        goto err;

    if (BN_copy(r, t) == NULL)
        goto err;
    ret = 1;
 err:
    BN_CTX_end(ctx);
    bn_check_top(r);
    return (ret);
}

static BIGNUM *euclid(BIGNUM *a, BIGNUM *b)
{
    BIGNUM *t;
    int shifts = 0;

    bn_check_top(a);
    bn_check_top(b);

    /* 0 <= b <= a */
    while (!BN_is_zero(b)) {
        /* 0 < b <= a */

        if (BN_is_odd(a)) {
            if (BN_is_odd(b)) {
                if (!BN_sub(a, a, b))
                    goto err;
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            } else {            /* a odd - b even */

                if (!BN_rshift1(b, b))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            }
        } else {                /* a is even */

            if (BN_is_odd(b)) {
                if (!BN_rshift1(a, a))
                    goto err;
                if (BN_cmp(a, b) < 0) {
                    t = a;
                    a = b;
                    b = t;
                }
            } else {            /* a even - b even */

                if (!BN_rshift1(a, a))
                    goto err;
                if (!BN_rshift1(b, b))
                    goto err;
                shifts++;
            }
        }
        /* 0 <= b <= a */
    }

    if (shifts) {
        if (!BN_lshift(a, a, shifts))
            goto err;
    }
    bn_check_top(a);
    return (a);
 err:
    return (NULL);
}

/* solves ax == 1 (mod n) */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                                        const BIGNUM *a, const BIGNUM *n,
                                        BN_CTX *ctx);

BIGNUM *BN_mod_inverse(BIGNUM *in,
                       const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *rv;
    int noinv;
    rv = int_bn_mod_inverse(in, a, n, ctx, &noinv);
    if (noinv)
    {
        
    }
        //BNerr(BN_F_BN_MOD_INVERSE, BN_R_NO_INVERSE);
    return rv;
}

BIGNUM *int_bn_mod_inverse(BIGNUM *in,
                           const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx,
                           int *pnoinv)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;

    if (pnoinv)
        *pnoinv = 0;

    if ((BN_get_flags(a, BN_FLG_CONSTTIME) != 0)
        || (BN_get_flags(n, BN_FLG_CONSTTIME) != 0)) {
        return BN_mod_inverse_no_branch(in, a, n, ctx);
    }

    bn_check_top(a);
    bn_check_top(n);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;
    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        if (!BN_nnmod(B, B, A, ctx))
            goto err;
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    if (BN_is_odd(n) && (BN_num_bits(n) <= 2048)) {
        /*
         * Binary inversion algorithm; requires odd modulus. This is faster
         * than the general algorithm if the modulus is sufficiently small
         * (about 400 .. 500 bits on 32-bit systems, but much more on 64-bit
         * systems)
         */
        int shift;

        while (!BN_is_zero(B)) {
            /*-
             *      0 < B < |n|,
             *      0 < A <= |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|)
             */

            /*
             * Now divide B by the maximum possible power of two in the
             * integers, and divide X by the same value mod |n|. When we're
             * done, (1) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(B, shift)) { /* note that 0 < B */
                shift++;

                if (BN_is_odd(X)) {
                    if (!BN_uadd(X, X, n))
                        goto err;
                }
                /*
                 * now X is even, so we can easily divide it by two
                 */
                if (!BN_rshift1(X, X))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(B, B, shift))
                    goto err;
            }

            /*
             * Same for A and Y.  Afterwards, (2) still holds.
             */
            shift = 0;
            while (!BN_is_bit_set(A, shift)) { /* note that 0 < A */
                shift++;

                if (BN_is_odd(Y)) {
                    if (!BN_uadd(Y, Y, n))
                        goto err;
                }
                /* now Y is even */
                if (!BN_rshift1(Y, Y))
                    goto err;
            }
            if (shift > 0) {
                if (!BN_rshift(A, A, shift))
                    goto err;
            }

            /*-
             * We still have (1) and (2).
             * Both  A  and  B  are odd.
             * The following computations ensure that
             *
             *     0 <= B < |n|,
             *      0 < A < |n|,
             * (1) -sign*X*a  ==  B   (mod |n|),
             * (2)  sign*Y*a  ==  A   (mod |n|),
             *
             * and that either  A  or  B  is even in the next iteration.
             */
            if (BN_ucmp(B, A) >= 0) {
                /* -sign*(X + Y)*a == B - A  (mod |n|) */
                if (!BN_uadd(X, X, Y))
                    goto err;
                /*
                 * NB: we could use BN_mod_add_quick(X, X, Y, n), but that
                 * actually makes the algorithm slower
                 */
                if (!BN_usub(B, B, A))
                    goto err;
            } else {
                /*  sign*(X + Y)*a == A - B  (mod |n|) */
                if (!BN_uadd(Y, Y, X))
                    goto err;
                /*
                 * as above, BN_mod_add_quick(Y, Y, X, n) would slow things
                 * down
                 */
                if (!BN_usub(A, A, B))
                    goto err;
            }
        }
    } else {
        /* general inversion algorithm */

        while (!BN_is_zero(B)) {
            BIGNUM *tmp;

            /*-
             *      0 < B < A,
             * (*) -sign*X*a  ==  B   (mod |n|),
             *      sign*Y*a  ==  A   (mod |n|)
             */

            /* (D, M) := (A/B, A%B) ... */
            if (BN_num_bits(A) == BN_num_bits(B)) {
                if (!BN_one(D))
                    goto err;
                if (!BN_sub(M, A, B))
                    goto err;
            } else if (BN_num_bits(A) == BN_num_bits(B) + 1) {
                /* A/B is 1, 2, or 3 */
                if (!BN_lshift1(T, B))
                    goto err;
                if (BN_ucmp(A, T) < 0) {
                    /* A < 2*B, so D=1 */
                    if (!BN_one(D))
                        goto err;
                    if (!BN_sub(M, A, B))
                        goto err;
                } else {
                    /* A >= 2*B, so D=2 or D=3 */
                    if (!BN_sub(M, A, T))
                        goto err;
                    if (!BN_add(D, T, B))
                        goto err; /* use D (:= 3*B) as temp */
                    if (BN_ucmp(A, D) < 0) {
                        /* A < 3*B, so D=2 */
                        if (!BN_set_word(D, 2))
                            goto err;
                        /*
                         * M (= A - 2*B) already has the correct value
                         */
                    } else {
                        /* only D=3 remains */
                        if (!BN_set_word(D, 3))
                            goto err;
                        /*
                         * currently M = A - 2*B, but we need M = A - 3*B
                         */
                        if (!BN_sub(M, M, B))
                            goto err;
                    }
                }
            } else {
                if (!BN_div(D, M, A, B, ctx))
                    goto err;
            }

            /*-
             * Now
             *      A = D*B + M;
             * thus we have
             * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
             */

            tmp = A;            /* keep the BIGNUM object, the value does not
                                 * matter */

            /* (A, B) := (B, A mod B) ... */
            A = B;
            B = M;
            /* ... so we have  0 <= B < A  again */

            /*-
             * Since the former  M  is now  B  and the former  B  is now  A,
             * (**) translates into
             *       sign*Y*a  ==  D*A + B    (mod |n|),
             * i.e.
             *       sign*Y*a - D*A  ==  B    (mod |n|).
             * Similarly, (*) translates into
             *      -sign*X*a  ==  A          (mod |n|).
             *
             * Thus,
             *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
             * i.e.
             *        sign*(Y + D*X)*a  ==  B  (mod |n|).
             *
             * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
             *      -sign*X*a  ==  B   (mod |n|),
             *       sign*Y*a  ==  A   (mod |n|).
             * Note that  X  and  Y  stay non-negative all the time.
             */

            /*
             * most of the time D is very small, so we can optimize tmp :=
             * D*X+Y
             */
            if (BN_is_one(D)) {
                if (!BN_add(tmp, X, Y))
                    goto err;
            } else {
                if (BN_is_word(D, 2)) {
                    if (!BN_lshift1(tmp, X))
                        goto err;
                } else if (BN_is_word(D, 4)) {
                    if (!BN_lshift(tmp, X, 2))
                        goto err;
                } else if (D->top == 1) {
                    if (!BN_copy(tmp, X))
                        goto err;
                    if (!BN_mul_word(tmp, D->d[0]))
                        goto err;
                } else {
                    if (!BN_mul(tmp, D, X, ctx))
                        goto err;
                }
                if (!BN_add(tmp, tmp, Y))
                    goto err;
            }

            M = Y;              /* keep the BIGNUM object, the value does not
                                 * matter */
            Y = X;
            X = tmp;
            sign = -sign;
        }
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        if (pnoinv)
            *pnoinv = 1;
        goto err;
    }
    ret = R;
 err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return (ret);
}

/*
 * BN_mod_inverse_no_branch is a special version of BN_mod_inverse. It does
 * not contain branches that may leak sensitive information.
 */
static BIGNUM *BN_mod_inverse_no_branch(BIGNUM *in,
                                        const BIGNUM *a, const BIGNUM *n,
                                        BN_CTX *ctx)
{
    BIGNUM *A, *B, *X, *Y, *M, *D, *T, *R = NULL;
    BIGNUM *ret = NULL;
    int sign;

    bn_check_top(a);
    bn_check_top(n);

    BN_CTX_start(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    X = BN_CTX_get(ctx);
    D = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    Y = BN_CTX_get(ctx);
    T = BN_CTX_get(ctx);
    if (T == NULL)
        goto err;

    if (in == NULL)
        R = BN_new();
    else
        R = in;
    if (R == NULL)
        goto err;

    BN_one(X);
    BN_zero(Y);
    if (BN_copy(B, a) == NULL)
        goto err;
    if (BN_copy(A, n) == NULL)
        goto err;
    A->neg = 0;

    if (B->neg || (BN_ucmp(B, A) >= 0)) {
        /*
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         */
         {
            BIGNUM local_B;
            bn_init(&local_B);
            BN_with_flags(&local_B, B, BN_FLG_CONSTTIME);
            if (!BN_nnmod(B, &local_B, A, ctx))
                goto err;
            /* Ensure local_B goes out of scope before any further use of B */
        }
    }
    sign = -1;
    /*-
     * From  B = a mod |n|,  A = |n|  it follows that
     *
     *      0 <= B < A,
     *     -sign*X*a  ==  B   (mod |n|),
     *      sign*Y*a  ==  A   (mod |n|).
     */

    while (!BN_is_zero(B)) {
        BIGNUM *tmp;

        /*-
         *      0 < B < A,
         * (*) -sign*X*a  ==  B   (mod |n|),
         *      sign*Y*a  ==  A   (mod |n|)
         */

        /*
         * Turn BN_FLG_CONSTTIME flag on, so that when BN_div is invoked,
         * BN_div_no_branch will be called eventually.
         */
        {
            BIGNUM local_A;
            bn_init(&local_A);
            BN_with_flags(&local_A, A, BN_FLG_CONSTTIME);

            /* (D, M) := (A/B, A%B) ... */
            if (!BN_div(D, M, &local_A, B, ctx))
                goto err;
            /* Ensure local_A goes out of scope before any further use of A */
        }

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        tmp = A;                /* keep the BIGNUM object, the value does not
                                 * matter */

        /* (A, B) := (B, A mod B) ... */
        A = B;
        B = M;
        /* ... so we have  0 <= B < A  again */

        /*-
         * Since the former  M  is now  B  and the former  B  is now  A,
         * (**) translates into
         *       sign*Y*a  ==  D*A + B    (mod |n|),
         * i.e.
         *       sign*Y*a - D*A  ==  B    (mod |n|).
         * Similarly, (*) translates into
         *      -sign*X*a  ==  A          (mod |n|).
         *
         * Thus,
         *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
         * i.e.
         *        sign*(Y + D*X)*a  ==  B  (mod |n|).
         *
         * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
         *      -sign*X*a  ==  B   (mod |n|),
         *       sign*Y*a  ==  A   (mod |n|).
         * Note that  X  and  Y  stay non-negative all the time.
         */

        if (!BN_mul(tmp, D, X, ctx))
            goto err;
        if (!BN_add(tmp, tmp, Y))
            goto err;

        M = Y;                  /* keep the BIGNUM object, the value does not
                                 * matter */
        Y = X;
        X = tmp;
        sign = -sign;
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0) {
        if (!BN_sub(Y, n, Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(A)) {
        /* Y*a == 1  (mod |n|) */
        if (!Y->neg && BN_ucmp(Y, n) < 0) {
            if (!BN_copy(R, Y))
                goto err;
        } else {
            if (!BN_nnmod(R, Y, n, ctx))
                goto err;
        }
    } else {
        //BNerr(BN_F_BN_MOD_INVERSE_NO_BRANCH, BN_R_NO_INVERSE);
        goto err;
    }
    ret = R;
 err:
    if ((ret == NULL) && (in == NULL))
        BN_free(R);
    BN_CTX_end(ctx);
    bn_check_top(ret);
    return (ret);
}

/* TODO : BUG? */
int BN_print(const BIGNUM *a)
{
    uint8_t *b, *hex;

    b = (uint8_t*)malloc(8*(a->top));
    hex = (uint8_t*)malloc(16*(a->top));

    BN_bn2binpad(a, b, 8*(a->top));
    u8_to_hex(b, 8*(a->top), hex);
    if(BN_is_negative(a))
    {
        printf("-");
    }
    for(int i = 0; i < 16*(a->top); i++)
    {
        printf("%c", hex[i]);
    }
    printf("\n");

    free(b);
    free(hex);
    return 1;
}

// lehmerSimulate attempts to simulate several Euclidean update steps
// using the leading digits of A and B.  It returns u0, u1, v0, v1
// such that A and B can be updated as:
//		A = u0*A + v0*B
//		B = u1*A + v1*B
// Requirements: A >= B and len(B.abs) >= 2
// Since we are calculating with full words to avoid overflow,
// we use 'even' to track the sign of the cosequences.
// For even iterations: u0, v1 >= 0 && u1, v0 <= 0
// For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
static int lehmerSimulate(BIGNUM *A, BIGNUM *B, uint64_t *u0, uint64_t *u1, uint64_t *v0, uint64_t *v1)
{
    uint64_t a1, a2, q, r, tmp, c;
    uint64_t uu0, uu1, uu2, vv0, vv1, vv2;
    int even;
    int m = B->top - 1;  // m >= 2
    int n = A->top - 1;  // n >= m >= 2

    // extract the top Word of bits from A and B
    int h = 64 - BN_num_bits_word(A->d[n]);
    // printf("h : %ld", h);
    c = (h == 0) ? 0 : ((A->d[n-1]) >> (64-h));
    a1 = ((A->d[n]) << h) | c;
    // a1 = ((A->d[n]) << h) | ((A->d[n-1]) >> (64-h));
    // uint64_t zzz = ((A->d[n]) >> 64);
    // B may have implicit zero words in the high bits if the lengths differ
    if (n == m) {
        c = (h == 0) ? 0 : ((B->d[n-1]) >> (64-h));
        a2 = (B->d[n] << h) | c;
        // a2 = (B->d[n] << h) | (B->d[n-1] >> (64-h));
    }
    else if (n == (m+1)) {
        a2 = (h == 0) ? 0 : (B->d[n-1] >> (64-h));
        // a2 = (B->d[n-1] >> (64-h));
    }
    else
        a2 = 0;

    // Since we are calculating with full words to avoid overflow,
    // we use 'even' to track the sign of the cosequences.
    // For even iterations: u0, v1 >= 0 && u1, v0 <= 0
    // For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
    // The first iteration starts with k=1 (odd).
    even = 0;
    // variables to track the cosequences
    uu0 = 0, uu1 = 1, uu2 = 0;
    vv0 = 0, vv1 = 0, vv2 = 1;

    // printf("a1 : %ld\n", a1);
    // printf("a2 : %ld\n", a2);
    
    // Calculate the quotient and cosequences using Collins' stopping condition.
    // Note that overflow of a Word is not possible when computing the remainder
    // sequence and cosequences since the cosequence size is bounded by the input size.
    // See section 4.2 of Jebelean for details.
    for (; (a2 >= vv2) && ((a1-a2) >= (vv1+vv2));) {
        q = a1/a2, r = a1%a2;
        a1 = a2, a2 = r;
        tmp = uu1;
        uu0 = uu1, uu1 = uu2, uu2 = tmp+q*uu2;
        tmp = vv1;
        vv0 = vv1, vv1 = vv2, vv2 = tmp+q*vv2;
        even ^= 1;
    }

    *u0 = uu0, *u1 = uu1;
    *v0 = vv0, *v1 = vv1;

    return even;
}

// lehmerUpdate updates the inputs A and B such that:
//		A = u0*A + v0*B
//		B = u1*A + v1*B
// where the signs of u0, u1, v0, v1 are given by even
// For even == 1: u0, v1 >= 0 && u1, v0 <= 0
// For even == 0: u0, v1 <= 0 && u1, v0 >= 0
// q, r, s, t are temporary variables to avoid allocations in the multiplication
void lehmerUpdate(BIGNUM *A, BIGNUM *B, BIGNUM *t, BIGNUM *s, BIGNUM *y, uint64_t u0, uint64_t u1, uint64_t v0, uint64_t v1, int even)
{
    BN_copy(t, A);
    BN_copy(s, B);
    t->neg ^= (even ^ 1);
    s->neg ^= even;
    BN_mul_word(t, u0);
    BN_mul_word(s, v0);

    A->neg ^= even;
    B->neg ^= (even ^ 1);
    BN_mul_word(B, v1);
    BN_mul_word(A, u1);
    BN_add(B, A, B);
    BN_add(A, t, s);
}

// euclidUpdate performs a single step of the Euclidean GCD algorithm
// if extended is true, it also updates the cosequence Ua, Ub
void euclidUpdate(BIGNUM *A, BIGNUM *B, BIGNUM *Ua, BIGNUM *Ub, BIGNUM *q, BIGNUM *r, BN_CTX *ctx)
{
    BN_div(q, r, A, B, ctx);
    BN_copy(A, B);
    BN_copy(B, r);

    // Ua, Ub = Ub, Ua - q*Ub
    BN_copy(r, Ub);
    BN_mul(Ub, Ub, q, ctx);
    BN_sub(Ub, Ua, Ub);
    BN_copy(Ua, r);
}

/* in = a^-1 mod b
 * assume gcd(a, b) = 1 
 */
int BN_mod_inverse_Lehmer(BIGNUM *in, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    BIGNUM *A = NULL;
    BIGNUM *B = NULL;
    BIGNUM *Ua = NULL;
    BIGNUM *Ub = NULL;
    BIGNUM *t = NULL;
    BIGNUM *s = NULL;
    BIGNUM *y = NULL;
    uint64_t u0, u1, v0, v1;
    int even;
    int ret = GML_ERROR;

    A = BN_new();
    B = BN_new();
    Ua = BN_new();
    Ub = BN_new();
    t = BN_new();
    s = BN_new();
    y = BN_new();

    if (!A || !B || !Ua || !Ub || !t || !s || !y)
        goto end;

    if (!ctx) {
        ctx = BN_CTX_new();
        if (!ctx)
            goto end;
    }

    // ensure A >= B
    if (BN_cmp(a, b) < 0) {
        BN_copy(A, b);
        BN_copy(B, a);

        // Ua (Ub) tracks how many times input a has been accumulated into A (B).
        BN_one(Ub);
        BN_zero(Ua);
    }
    else {
        BN_copy(A, a);
        BN_copy(B, b);

        // Ua (Ub) tracks how many times input a has been accumulated into A (B).
        BN_one(Ua);
        BN_zero(Ub);
    }

    // loop invariant A >= B
    while (B->top > 1) {
        // Attempt to calculate in single-precision using leading words of A and B.
        even = lehmerSimulate(A, B, &u0, &u1, &v0, &v1);

        // multiprecision Step
        if (v0 != 0) {
            // Simulate the effect of the single-precision steps using the cosequences.
            // A = u0*A + v0*B
            // B = u1*A + v1*B
            lehmerUpdate(A, B, t, s, y, u0, u1, v0, v1, even);

            // Ua = u0*Ua + v0*Ub
            // Ub = u1*Ua + v1*Ub
            lehmerUpdate(Ua, Ub, t, s, y, u0, u1, v0, v1, even);
        }
        else {
            // Single-digit calculations failed to simulate any quotients.
            // Do a standard Euclidean step.
            euclidUpdate(A, B, Ua, Ub, t, y, ctx);
        }
    }

    if (B->top > 0) {
        // extended Euclidean algorithm base case if B is a single Word
        if (A->top > 1) {
            // A is longer than a single Word, so one update is needed.
            euclidUpdate(A, B, Ua, Ub, t, y, ctx);
        }

        if (B->top > 0) {
            // A and B are both a single Word.
            uint64_t aWord, bWord, ua, ub, va, vb, q, r, tmp;
            aWord = A->d[0];
            bWord = B->d[0];
            ua = 1, ub = 0;
            va = 0, vb = 1;
            even = 1;
            while (bWord != 0) {
                q = aWord/bWord, r = aWord%bWord;
                aWord = bWord, bWord = r;
                tmp = ua;
                ua = ub, ub = tmp+q*ub;
                tmp = va;
                va = vb, vb = tmp+q*vb;
                even ^= 1;
            }

            Ua->neg ^= (even ^ 1);
            Ub->neg ^= even;
            BN_mul_word(Ua, ua);
            BN_mul_word(Ub, va);
            BN_add(Ua, Ua, Ub);
            A->d[0] = aWord;
        }
    }

    if (Ua->neg)
        BN_add(in, Ua, b);
    else
        BN_copy(in, Ua);

    ret = 1;
end:
    BN_free(A);
    BN_free(B);
    BN_free(Ua);
    BN_free(Ub);
    BN_free(t);
    BN_free(s);
    BN_free(y);
    return ret;
}
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bn_lcl.h"
#include <gmlite/rand.h>

int BN_rand(BIGNUM *rnd, int bits)
{
    unsigned char *buf = NULL;
    int ret = 0, bytes;

    bytes = (bits + 7) / 8;
    buf = CRYPTO_malloc(bytes);
    if (buf == NULL) {
        //BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    if(!RAND_buf(buf, bytes))
    {
        goto err;
    }

    if (!BN_bin2bn(buf, bytes, rnd))
    {
        goto err;
    }
    ret = 1;
err:
    CRYPTO_clear_free(buf, bytes);
    bn_check_top(rnd);
    return (ret);
}

/* random number r:  0 <= r < range */
int BN_rand_range(BIGNUM *r, const BIGNUM *range)
{
    int n;
    int count = 100;

    if (range->neg || BN_is_zero(range)) {
        //BNerr(BN_F_BN_RAND_RANGE, BN_R_INVALID_RANGE);
        return 0;
    }

    n = BN_num_bits(range);     /* n > 0 */

    /* BN_is_bit_set(range, n - 1) always holds */

    if (n == 1)
        BN_zero(r);
    else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
        /*
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         */
        do {
            if (!BN_rand(r, n + 1))
                return 0;
            /*
             * If r < 3*range, use r := r MOD range (which is either r, r -
             * range, or r - 2*range). Otherwise, iterate once more. Since
             * 3*range = 11..._2, each iteration succeeds with probability >=
             * .75.
             */
            if (BN_cmp(r, range) >= 0) {
                if (!BN_sub(r, r, range))
                    return 0;
                if (BN_cmp(r, range) >= 0)
                    if (!BN_sub(r, r, range))
                        return 0;
            }

            if (!--count) {
                //BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS);
                return 0;
            }

        }
        while (BN_cmp(r, range) >= 0);
    } else {
        do {
            /* range = 11..._2  or  range = 101..._2 */
            if (!BN_rand(r, n))
                return 0;

            if (!--count) {
                //BNerr(BN_F_BN_RAND_RANGE, BN_R_TOO_MANY_ITERATIONS);
                return 0;
            }
        }
        while (BN_cmp(r, range) >= 0);
    }

    bn_check_top(r);
    return 1;
}
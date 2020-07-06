#ifndef HEADER_TEST_H
#define HEADER_TEST_H

#include <gmlite/common.h>
#include <gmlite/crypto.h>
#include <gmlite/bn.h>
#include <gmlite/ec.h>
#include <gmlite/pairing.h>
#include <gmlite/rand.h>
#include <gmlite/sm2.h>
#include <gmlite/sm3.h>
#include <gmlite/sm4.h>
#include <gmlite/sm9.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "simple_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TEST_ARGS
{
    /* test result, 1 : success, 0 : fail */
    int ok;
    /* test times */
    int64_t N;
    /* number of threads */
    int64_t num_threads;
}TEST_ARGS;

/* start n threads */
int test_start_n_thread(void (*func)(void *), TEST_ARGS *args);

void random_string(unsigned char *s, int len);

int random_number();

int get_test_arg(int argc, char **argv, TEST_ARGS *args);

#ifdef __cplusplus
}
#endif

#endif

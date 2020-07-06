#include <gmlite/rand.h>
#include "rand_lcl.h"

const RAND_IMPL *rand_impl;

void runtime_choose_rand_implementation()
{
    rand_impl = SYS_RAND_IMPL();
}

int RAND_buf(uint8_t *buf, int len)
{
    if (rand_impl == NULL || rand_impl->rand_buf == NULL || buf == NULL || len <= 0)
        return GML_ERROR;

    return rand_impl->rand_buf(buf, len);
}
#ifndef HEADER_RAND_LCL_H
#define HEADER_RAND_LCL_H

#include <stddef.h>
#include <gmlite/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

/* rand implementation */
typedef struct
{
    /* impl name */
    char *impl;
    /* fill buf with random bytes */
    int (*rand_buf) (unsigned char *buf, size_t len);
}RAND_IMPL;

/* chosen when library initialize */
extern const RAND_IMPL *rand_impl;

// const RAND_IMPL *SM3_RAND_IMPL();
const RAND_IMPL *SYS_RAND_IMPL();

/* choose rand implementation */
void runtime_choose_rand_implementation();

#ifdef __cplusplus
}
#endif

#endif
#include <gmlite/cpuid.h>
#include <gmlite/crypto.h>
#include <gmlite/ec.h>
#include <gmlite/sm2.h>
#include <gmlite/sm3.h>
#ifdef _WIN32
# include <windows.h>
#elif defined(HAVE_PTHREAD)
# include <pthread.h>
#endif
#include "ec/ec_lcl.h"
#include "sm2/sm2_lcl.h"
#include "sm3/sm3_lcl.h"
#include "sm9/sm9_lcl.h"
#include "rand/rand_lcl.h"

static volatile int initialized;
static volatile int locked;

#ifdef _WIN32

static CRITICAL_SECTION _lock;
static volatile long    _lock_initialized;

int _crit_init(void)
{
    long status = 0L;

    while ((status = InterlockedCompareExchange(&_lock_initialized,
                                                1L, 0L)) == 1L) {
        Sleep(0);
    }

    switch (status) {
    case 0L:
        InitializeCriticalSection(&_lock);
        return InterlockedExchange(&_lock_initialized, 2L) == 1L ? 0 : -1;
    case 2L:
        return 0;
    default: /* should never be reached */
        return -1;
    }
}

int CRYPTO_crit_enter(void)
{
    if (_crit_init() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    EnterCriticalSection(&_lock);
    assert(locked == 0);
    locked = 1;

    return 0;
}

int CRYPTO_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;
    LeaveCriticalSection(&_lock);

    return 0;
}

#elif defined(HAVE_PTHREAD) && !defined(__EMSCRIPTEN__)

static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;

int CRYPTO_crit_enter(void)
{
    int ret;

    if ((ret = pthread_mutex_lock(&_lock)) == 0) 
    {
        assert(locked == 0);
        locked = 1;
    }
    return ret;
}

int CRYPTO_crit_leave(void)
{
    if (locked == 0) {
# ifdef EPERM
        errno = EPERM;
# endif
        return -1;
    }
    locked = 0;

    return pthread_mutex_unlock(&_lock);
}

#elif defined(HAVE_ATOMIC_OPS) && !defined(__EMSCRIPTEN__)

static volatile int _lock;

int
CRYPTO_crit_enter(void)
{
# ifdef HAVE_NANOSLEEP
    struct timespec q;
    memset(&q, 0, sizeof q);
# endif
    while (__sync_lock_test_and_set(&_lock, 1) != 0) {
# ifdef HAVE_NANOSLEEP
        (void) nanosleep(&q, NULL);
# elif defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__ ("pause");
# endif
    }
    return 0;
}

int
CRYPTO_crit_leave(void)
{
    __sync_lock_release(&_lock);

    return 0;
}

#else

int
CRYPTO_crit_enter(void)
{
    return 0;
}

int
CRYPTO_crit_leave(void)
{
    return 0;
}

#endif

/* choose fastest implementation */
static int runtime_choose_best_implementation()
{
    runtime_choose_sm3_implementation();
    runtime_choose_rand_implementation();
    return GML_OK;
}

static int init_globals()
{
    if (CRYPTO_alloc_init() == GML_ERROR)
        goto end;

    /* init sm2 curve parameters and methods */
    if (sm2_group_init() == GML_ERROR)
        goto end;

    /* init sm9 curve parameters and methods */
    if (sm9_group_init() == GML_ERROR || 
        sm9_pairing_init() == GML_ERROR)
        goto end;

    return GML_OK;
end:
    return GML_ERROR;
}

/* TODO : CRYPTO_deinit() */
static void deinit_globals()
{
    EC_GROUP_free((EC_GROUP*)sm2_group);
    EC_GROUP_free((EC_GROUP*)sm9_group);
    PAIRING_free((ATE_CTX*)sm9_ate_ctx);
}

int CRYPTO_init()
{
    if (CRYPTO_crit_enter() != 0) 
        return GML_ERROR; /* LCOV_EXCL_LINE */

    if (initialized != 0) {
        if (CRYPTO_crit_leave() != 0) 
            return GML_ERROR; /* LCOV_EXCL_LINE */
        return GML_OK;
    }

    if (init_globals() == GML_ERROR) 
        abort();

    _runtime_get_cpu_features();

    runtime_choose_best_implementation();

    initialized = 1;
    if (CRYPTO_crit_leave() != 0)
        return GML_ERROR; /* LCOV_EXCL_LINE */

    return GML_OK;
}

int CRYPTO_deinit()
{
    if (CRYPTO_crit_enter() != 0) 
        return GML_ERROR; /* LCOV_EXCL_LINE */

    if (initialized != 1) {
        if (CRYPTO_crit_leave() != 0) 
            return GML_ERROR; /* LCOV_EXCL_LINE */
        return GML_OK;
    }

    deinit_globals();

    initialized = 0;
    if (CRYPTO_crit_leave() != 0)
        return GML_ERROR; /* LCOV_EXCL_LINE */

    return GML_OK;
}
#ifndef _TIMERS_H
#define _TIMERS_H
/* ------------------------------------------------------------------------- */

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))

#include "sys/time.h"

#define BENCH_VARS                                                            \
  uint32_t start_tick_lo, start_tick_hi;                                                     \
  uint32_t ticks_lo, ticks_hi;                                                  \
  int64_t start_time, end_time

#define COUNTER_START()                                                         \
  __asm__ volatile                                                            \
    ("\n        rdtsc"                                                        \
     : "=a" (start_tick_lo), "=d" (start_tick_hi))

#define COUNTER_STOP()                                                          \
  __asm__ volatile                                                            \
    ("\n        rdtsc"                                                        \
     "\n        subl %2, %%eax"                                               \
     "\n        sbbl %3, %%edx"                                               \
     : "=&a" (ticks_lo), "=&d" (ticks_hi)                                     \
     : "g" (start_tick_lo), "g" (start_tick_hi)) 

static gml_inline int64_t gettime_i64()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000UL + tv.tv_usec;
}

#define TIMER_START()                                                          \
    start_time = gettime_i64()

#define TIMER_STOP()                                                          \
    end_time = gettime_i64()

#define TICKS() (ticks_lo + 4294967296LL * ticks_hi)
#define USEC() (double)(end_time - start_time)

/* ------------------------------------------------------------------------- */

#elif defined(_MSC_VER) && defined(_M_IX86)

#include <windows.h>

typedef unsigned int u32;
#define BENCH_VARS                                                            \
  u32 start_tick_lo, start_tick_hi;                                                     \
  u32 ticks_lo, ticks_hi
  DWORD start_time_lo, start_time_hi;                                           \
  DWORD time_lo, time_hi

#define COUNTER_START()                                                         \
  __asm {                                                                     \
    __asm rdtsc                                                               \
    __asm mov start_tick_lo, eax                                                   \
    __asm mov start_tick_hi, edx                                                   \
  }

#define COUNTER_STOP()                                                          \
  __asm {                                                                     \
    __asm rdtsc                                                               \
    __asm sub eax, start_tick_lo                                                   \
    __asm sbb edx, start_tick_hi                                                   \
    __asm mov ticks_lo, eax                                                   \
    __asm mov ticks_hi, edx                                                   \
  } 

static void gettime_i64(DWORD *lo, DWORD *hi)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    *lo = ft.dwLowDateTime;
    *hi = ft.dwHighDateTime;
}

#define TIMER_START()                                                              \
    gettime_i64(&start_time_lo, &start_time_hi)

#define TIMER_STOP()                                                              \
    gettime_i64(&time_lo, &time_hi)                                                \
    time_lo -= start_time_lo;                                                      \
    time_hi -= start_time_hi

#define TICKS() ((double)ticks_lo + 4294967296.0 * (double)ticks_hi)
#define USEC(ticks) 0.1 * ((double)time_lo) + 0.1 * 4294967296.0 * (double)(time_hi)

/* ------------------------------------------------------------------------- */

#elif defined(_MSC_VER) && (defined(_M_AMD64) || defined(_M_X64))
#include <intrin.h>
#pragma intrinsic(__rdtsc)

#define BENCH_VARS                                                                            \
unsigned __int64 start_ticks, end_ticks;                                                      \
unsigned __int64 start_time, end_time                                                                  

#define COUNTER_START() start_ticks = __rdtsc()                                                   

#define COUNTER_STOP() end_ticks = __rdtsc()                                                     

static unsigned __int64 gettime_i64()
{
    FILETIME ft;
    unsigned __int64 ret;
    GetSystemTimeAsFileTime(&ft);
    ret = (unsigned __int64)ft.dwLowDateTime | ((unsigned __int64)ft.dwHighDateTime) << 32;
    return ret;
}

#define TIMER_START()                                                              \
    start_time = gettime_i64()

#define TIMER_STOP()                                                              \
    end_time = gettime_i64()

//unsigned __int64 __rdtsc(void);
#define TICKS() ((double)end_ticks - (double)start_ticks)
#define USEC() ((double)((end_time - start_time) * 0.1))

#else

#include <time.h>

#define BENCH_VARS                                                            \
  clock_t start_ul;                                                           \
  clock_t ticks_ul

#define COUNTER_START()                                                         \
  start_ul = clock()

#define COUNTER_STOP()                                                          \
  ticks_ul = clock() - start_ul


#define TICKS() ((double)ticks_ul)
#define USEC(ticks) (1000000.0 * (double)ticks / (double)CLOCKS_PER_SEC)

/* ------------------------------------------------------------------------- */

#endif

#endif
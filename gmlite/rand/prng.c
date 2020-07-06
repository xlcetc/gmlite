#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <gmlite/common.h>
#include <gmlite/cpuid.h>
#include <gmlite/crypto.h>
#include <gmlite/sm3.h>
#include "rand_lcl.h"

// #ifdef _WIN32
//   #include <io.h>
//   #include <process.h>
//   typedef int pid_t;
// #else
//   #include <unistd.h>
// #endif

// #ifdef __GNUC__
//   #pragma GCC target("rdrnd")
// #endif

// #if defined(__FreeBSD__) || defined(__OpenBSD__) || 
//     defined(__NetBSD__)  || defined(__linux__)



// #endif

// #ifdef HAVE_GETTIMEOFDAY
// # include <sys/time.h>
// #endif

// /* thread local storage */
// #ifndef TLS
// # ifdef _WIN32
// #  define TLS __declspec(thread)
// # else
// #  define TLS 
// # endif
// #endif

// #define POOL_SIZE 512

// /* pool to collect entropy, its size is POOL_SIZE
//  * rand_pool is allocated using CRYPTO_secure_zalloc()
//  */
// static TLS uint8_t *rand_pool;

// /* ammount of entropy in rand_pool */
// static TLS int entropy;

// /* whether rand_pool is initialized */
// static TLS int initialized;

// /* where entropy is to be added in */
// static TLS size_t offset;

// /* it's ok to be global */
// static size_t nonce;

// /* process id, if pid != getpid(), then we're in child process */
// static pid_t pid;

// /* high resolution timestamp */
// static int hrtime(uint64_t *t)
// {
// #ifdef HAVE_CLOCK_GETTIME
//     struct timespec ts = {0, 0};
//     if(clock_gettime(CLOCK_MONOTONIC, &ts) == 0)  /* success */
//     {
//         *t = ts.tv_sec << 30 + ts.tv_nsec; /* nano seconds */
//         return 1;
//     }
// #elif defined HAVE_GETTIMEOFDAY
//     struct timeval tv;
//     if(gettimeofday(&tv, NULL) == 0) /* success */
//     {
//         *t = tv.tv_usec; /* micro seconds */
//         return 1;
//     }
// #else


// #endif
//     return 0;
// }

// /* rdrand */
// static int rdrand64(uint64_t *r)
// {
// //     if(runtime_has_rdrand())
// //     {
// // #if defined(__x86_64) || defined(__x86_64__)
// //         if(_rdrand64_step(r) == 1) /* success */
// //         {
// //             return 1;
// //         }
// // #else
// //         if(_rdrand32_step((uint32_t*)r) == 1 &&  /* success */
// //            _rdrand32_step(1 + (uint32_t*)r) == 1)  /* success */
// //         {
// //             return 1;
// //         }
// // #endif
// //     }

//     return 0;
// }

// /* rdseed */
// static int rdseed64(uint64_t *r)
// {
// //     if(runtime_has_rdseed())
// //     {
// // #if defined(__x86_64) || defined(__x86_64__)
// //         /* retry loop */
// //         while(_rdseed64_step(r) != 1) /* fail */
// //         {}
// // #else
// //         /* retry loop */
// //         while(_rdseed32_step((uint32_t*)r) != 1) /* fail */
// //         {}
// //         /* retry loop */
// //         while(_rdseed32_step(1 + (uint32_t*)r) != 1) /* fail */
// //         {}
// // #endif
// //         return 1;
// //     }

//     return 0;
// }

// // static int random_bytes_from_dev_random(uint8_t *buf, int buflen)
// // {
// // // 	int randFD, noBytes = 0;

// // // #if defined(__linux__) && defined(GRND_NONBLOCK)
// // //   #ifdef SYS_getrandom
// // // 	#include <sys/syscall.h>
// // // 	noBytes = syscall( SYS_getrandom, buffer, DEVRANDOM_BYTES, 
// // // 					   GRND_NONBLOCK );
// // //   #else
// // // 	/* noBytes = getrandom( buffer, DEVRANDOM_BYTES, GRND_NONBLOCK ); */
// // //   #endif /* No guarantee of getrandom() support */
// // // #elif defined(__OpenBSD__) && OpenBSD > 201412
// // // 	/* See the comment at the start for why we use 'OpenBSD' for the version 
// // // 	   number */
// // // 	noBytes = getentropy( buffer, DEVRANDOM_BYTES );
// // // 	if( noBytes == 0 )
// // //     {
// // //     /* OpenBSD's semantics for the call differ from the read()-alike
// // //         functionality of the Linux version and simply return 0 or -1
// // //         for success or failure, so we convert the former into a byte
// // //         count */
// // //     noBytes = DEVRANDOM_BYTES;
// // //     }

// // // #elif (defined(__FreeBSD__) || defined(__NetBSD__) || 
// // // 	   defined(__OpenBSD__) || defined(__APPLE__) )
// // // 	{
// // // 	static const int mib[] = { CTL_KERN, KERN_ARND };
// // // 	size_t size = DEVRANDOM_BYTES;
// // // 	int status;

// // // 	/* Alternative to getentropy() if it's not present, supported by some 
// // // 	   BSDs */
// // // 	if( sysctl( mib, 2, buffer, &size, NULL, 0 ) == 0 )
// // // 		noBytes = size;
// // // 	}
// // // #else
// // // 	/* Check whether there's a /dev/random present.  We don't use O_NOFOLLOW 
// // // 	   because on some Unixen special files can be symlinks and in any case 
// // // 	   a system that allows attackers to mess with privileged filesystems 
// // // 	   like this is presumably a goner anyway */
// // // 	if((randFD = open( "/dev/urandom", O_RDONLY)) < 0)
// // // 		return( 0 );
// // // 	if(randFD <= 2)
// // //     {
// // //         /* We've been given a standard I/O handle, something's wrong */
// // //         close(randFD);
// // //         return( 0 );
// // //     }

// // // 	/* Read data from /dev/urandom, which won't block (although the quality
// // // 	 * of the noise is arguably slighly less) 
// // //      */
// // // 	noBytes = read(randFD, buf, DEVRANDOM_BYTES);
// // // 	close(randFD);
// // // #endif /* OSes without API support for the randomness device */
// // // 	if(noBytes < 1)
// // // 	{
// // // 		return -1;
// // // 	}

// // // 	return( quality );
// // }

// /* fast */
// static int gather_low_entropy(uint8_t *buf, size_t len)
// {
//     return 1;
// }

// /* slow */
// static int gather_high_entropy(uint8_t *buf, size_t len)
// {
//     return 1;
// }

// /*
//  *
//  * 
//  * 
//  */
// static int pool_init()
// {
//     if(initialized)
//     {
//         return 1;
//     }

//     rand_pool = CRYPTO_secure_zalloc(POOL_SIZE);
//     if(rand_pool == NULL)
//     {
//         initialized = 0;
//         return 0;
//     }

//     entropy = 0;
//     initialized = 1;
//     return 1;
// }

// /* add entropy into rand_pool */
// static void pool_add(uint8_t *buf, size_t len)
// {
//     while(len)
//     {
//         len--;
//         rand_pool[offset++] ^= buf[len];
//         if(offset >= POOL_SIZE)
//         {
//             offset = 0;
//         }
//     }
// }

// /*   */
// static void pool_rdrand_xor()
// {

// }

// static int pool_need_stir()
// {
//     pid_t cur_pid;
//     if(!initialized)
//     {
//         if(pool_init())
//         {
//             return 1;
//         }
//         else
//         {
//             /* abort ? */
//             return 0;
//         }
//     }

//     cur_pid = getpid();
//     /* fork */
//     if(cur_pid != pid || entropy <= 0)
//     {
//         return 1;
//     }

//     return 0;
// }

// /* use some random source to stir rand_pool */ 
// static int pool_stir()
// {
//     pid_t cur_pid;
//     size_t z1, z2;
//     uint8_t r[SM3_DIGEST_LENGTH];
//     uint8_t h[SM3_DIGEST_LENGTH];

//     if(pool_need_stir())
//     {
//         z1 = 0;
//         for(int i = 0; i < POOL_SIZE / SM3_DIGEST_LENGTH; i++)
//         {
//             /* r = random */
//             gather_high_entropy(r, SM3_DIGEST_LENGTH);

//             /* h = hash(block) */
//             SM3_once(&rand_pool[z1], SM3_DIGEST_LENGTH, h);

//             z2 = z1 + SM3_DIGEST_LENGTH;
//             if(z2 >= POOL_SIZE)
//             {
//                 z2 -= POOL_SIZE;
//             }

//             /* next block = r xor h */
//             for(int k = 0; k < SM3_DIGEST_LENGTH; k++)
//             {
//                 rand_pool[z2++] = r[k] ^ h[k];
//             }
//             z1 += SM3_DIGEST_LENGTH;
//         }

//         /* random nonce */


//         CRYPTO_memzero(r, SM3_DIGEST_LENGTH);
//     }
// }

// /* generate random from rand_pool */
// static int rand_buf(uint8_t *buf, size_t len)
// {
//     pid_t cur_pid;
//     uint8_t r[SM3_BLOCK_SIZE];
//     SM3_CTX sm3_ctx;

//     pool_stir();

//     for(size_t i = 0; i < len; i += SM3_DIGEST_LENGTH)
//     {
//         SM3_init(&sm3_ctx);

//         /* r = [rand_pool[32], rand_source[32]] */
//         memcpy(r, &rand_pool[offset], SM3_BLOCK_SIZE / 2);
//         gather_low_entropy(r + SM3_BLOCK_SIZE / 2, SM3_BLOCK_SIZE / 2);
//         /* rand = sm3_compress(r) */
//         // sm3_impl->compress(buf, r, 1);

//         entropy -= SM3_DIGEST_LENGTH;
//         /* add some entropy into rand_pool */
//         cur_pid = getpid();
//         pool_add((uint8_t*)&cur_pid, sizeof cur_pid);


//         pool_stir();
//     }




// end:
//     CRYPTO_memzero(&sm3_ctx, sizeof(SM3_CTX));
//     CRYPTO_memzero(r, SM3_BLOCK_SIZE);
// }

// /* IMPLEMENTAION */
// static const RAND_IMPL _SM3_RAND_IMPL = {
//     "sm3 prng",
//     rand_buf,
// };

// const RAND_IMPL *SM3_RAND_IMPL()
// {
//     return &_SM3_RAND_IMPL;
// }
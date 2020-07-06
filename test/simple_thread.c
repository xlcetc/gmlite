/* only for test */

#include <stdlib.h>
#include "test.h"

/* TODO : thread runs too slow in cygwin */
#ifdef HAVE_PTHREAD

int test_start_n_thread(void (*func)(void *), TEST_ARGS *args)
{
    int i;
    int ret = GML_OK;
    int num_threads = args->num_threads;
    pthread_t *t;

    t = (pthread_t*)malloc(sizeof(pthread_t) * args->num_threads);
    TEST_ARGS *test_args = calloc(1, num_threads*sizeof(TEST_ARGS));

    /* copy arguments */
    for (int i = 0; i < num_threads; i++)
        test_args[i].N = args->N;

    /* start threads */
    for (i = 0; i < num_threads; i++)
        if (pthread_create(&t[i], NULL, (void*)func, (void*)&test_args[i]))
            return GML_ERROR;

    // sleep(5);

    // pthread_mutex_lock(&mut);
    // for(i = 0; i < n; i++)
    // {
    //     pthread_cond_signal(&cond[i]);
    // }
    // pthread_mutex_unlock(&mut);

    for (int i = 0; i < num_threads; i++) {
        pthread_join(t[i], NULL);
        if (test_args[i].ok == GML_ERROR)
            ret = GML_ERROR;
    }

    free(t);
    CRYPTO_free(test_args);
    return ret;
}

#elif defined HAVE_WIN32_THREAD

/* start n threads 
   same func, same arg
*/
int test_start_n_thread(void(*func)(void *), TEST_ARGS *args)
{
    int i;
    int ret = 1;
    int num_threads = args->num_threads;
    HANDLE *thread_handle = (HANDLE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, num_threads * sizeof(HANDLE));
    TEST_ARGS *test_args = calloc(1, num_threads * sizeof(TEST_ARGS));

    for (i = 0; i < num_threads; i++) {
        test_args[i].N = args->N;
        thread_handle[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, (LPVOID)&test_args[i], 0, NULL);
    }

    for (i = 0; i < num_threads; i++) {
        WaitForSingleObject(thread_handle[i], INFINITE);
        CloseHandle(thread_handle[i]);
        if (test_args[i].ok == GML_ERROR)
            ret = GML_ERROR;
    }
    HeapFree(GetProcessHeap(), 0, thread_handle);
    CRYPTO_free(test_args);
    return ret;
}

#else

int test_start_n_thread(void (*func)(void *), void *arg, int n)
{
    printf("multithread not supported \n");
    return GML_ERROR;
}

#endif
#include "test.h"

void random_string(unsigned char *s, int len)
{
    static int en = 0;
    srand((unsigned)time(NULL) + en);
    while (len--)
        s[len] = rand() % 256;
    en++;
}

int random_number()
{
    static int en = 0;
    srand((unsigned)time(NULL) + en);
    en++;
    return rand();
}

/* TODO : need better parser */
int get_test_arg(int argc, char **argv, TEST_ARGS *args)
{
    int ret = GML_ERROR;

    for (int i = 1; i < argc; i++) {
        if (memcmp(argv[i], "THREADS=", 8) == 0 || memcmp(argv[i], "threads=", 8) == 0) {
            args->num_threads = atoi(argv[i] + 8);
            continue;
        }

        if (memcmp(argv[i], "t=", 2) == 0 || memcmp(argv[i], "T=", 2) == 0) {
            args->num_threads = atoi(argv[i] + 2);
            continue;
        }

        if (memcmp(argv[i], "n=", 2) == 0 || memcmp(argv[i], "N=", 2) == 0) {
            args->N = atoi(argv[i] + 2);
            continue;
        }
    }

    args->ok = 0;
    args->num_threads = args->num_threads > 0 ? args->num_threads : 4;
    args->N = args->N > 0 ? args->N : 12345; 

    return ret;
}


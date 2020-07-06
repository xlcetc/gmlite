#ifndef SIMPLE_THREADS_H
# define SIMPLE_THREADS_H

#include "config.h"

# ifdef HAVE_PTHREAD
#  include <pthread.h>
# elif defined HAVE_WIN32_THREAD
#  include <windows.h>
# else

# endif

#endif
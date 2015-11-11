/*
 *  See license file
 */

#ifndef STUN_OS_H
#define STUN_OS_H


#ifndef  WIN32
#include <pthread.h>
#else
#undef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#endif


#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

#if defined(WIN32)
typedef CRITICAL_SECTION STUN_MUTEX;
#else
/* linux, .. */
typedef pthread_mutex_t STUN_MUTEX;
#endif

bool
Stun_MutexCreate(STUN_MUTEX* m,
                 char*       name);
bool
Stun_MutexLock  (STUN_MUTEX* m);
bool
Stun_MutexUnlock(STUN_MUTEX* m);
bool
Stun_MutexDestroy(STUN_MUTEX* m);


#ifdef __cplusplus
}
#endif


#endif /* STUN_OS_H */

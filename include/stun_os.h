/*
Copyright 2014 Cisco. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are 
permitted provided that the following conditions are met: 

   1. Redistributions of source code must retain the above copyright notice, this list of 
      conditions and the following disclaimer. 

   2. Redistributions in binary form must reproduce the above copyright notice, this list 
      of conditions and the following disclaimer in the documentation and/or other materials 
      provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY CISCO ''AS IS'' AND ANY EXPRESS OR IMPLIED 
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND 
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH 
DAMAGE. 

The views and conclusions contained in the software and documentation are those of the 
authors and should not be interpreted as representing official policies, either expressed 
or implied, of Cisco.
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

bool Stun_MutexCreate(STUN_MUTEX *m, char *name);
bool Stun_MutexLock  (STUN_MUTEX *m);
bool Stun_MutexUnlock(STUN_MUTEX *m);
bool Stun_MutexDestroy(STUN_MUTEX *m);


#ifdef __cplusplus
}
#endif


#endif /* STUN_OS_H */

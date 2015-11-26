#ifndef HIUT_LIB_H
#define HIUT_LIB_H

#define MAX_TTL 64

#include <stunlib.h>

struct hiutTTLinfo {
  /* int ttl; */
  /* int messageSize; */
  StunMsgId stunMsgId;

};

struct hiutPathElement {
  bool                    gotAnswer;
  bool                    inactive;
  struct sockaddr_storage addr;
};

struct hiutResult {
  /* STUN Setup */
  void*                   stunCtx;
  int32_t                 sockfd;
  char          username[STUN_MSG_MAX_USERNAME_LENGTH];
  char          password[STUN_MSG_MAX_PASSWORD_LENGTH];
  
  STUN_SENDFUNC           sendFunc;


  int32_t                 currentTTL;
  int32_t                 user_start_ttl;
  int32_t                 user_max_ttl;
  int32_t                 user_paralell_traces;
  int32_t                 path_max_ttl; /*got port unreachable or STUN response
                                         **/
  uint32_t                wait_ms;
  struct sockaddr_storage localAddr;
  struct sockaddr_storage remoteAddr;


  /* Initial Length of first STUN packet (TTL=1) */
  uint32_t               stunLen;
  struct hiutPathElement pathElement[MAX_TTL];
  struct hiutTTLinfo     ttlInfo[MAX_TTL];
  //struct npa_trace       trace;

  /* Recurring traces*/
  int32_t max_recuring;
  int32_t num_traces;

};


#endif

#pragma once

#define MAX_TTL 40
#define MAX_CONCECUTIVE_INACTIVE 4

#define STUNTRACE_MAX_RETRANSMITS          3
#define STUNTRACE_RETRANSMIT_TIMEOUT_LIST      2000, 2000, 2000

typedef struct
{

  struct sockaddr* nodeAddr;

  uint32_t hop;
  uint32_t rtt;                           /* Rtt in microseconds */
  uint32_t retransmits;
  uint32_t trace_num;
  bool     traceEnd;
  bool     done;

} StunTraceCallBackData_T;

typedef void (* STUN_TRACECB)(void*                    userCtx,
                              StunTraceCallBackData_T* stunCbData);

#if 0
struct hiutTTLinfo {
  /* int ttl; */
  /* int messageSize; */
  StunMsgId stunMsgId;

};
#endif

struct hiutPathElement {
  bool                    gotAnswer;
  bool                    inactive;
  struct sockaddr_storage addr;
};

struct hiutResult {
  /* STUN Setup */
  void*   stunCtx;
  void*   userCtx;
  int32_t sockfd;
  char    username[STUN_MSG_MAX_USERNAME_LENGTH];
  char    password[STUN_MSG_MAX_PASSWORD_LENGTH];

  STUN_SENDFUNC sendFunc;


  int32_t   currentTTL;
  StunMsgId currStunMsgId;
  int32_t   user_start_ttl;
  int32_t   user_max_ttl;
  int32_t   user_paralell_traces;
  int32_t   path_max_ttl;               /*got port unreachable or STUN response
                                        **/
  uint32_t                wait_ms;
  struct sockaddr_storage localAddr;
  struct sockaddr_storage remoteAddr;


  /* Initial Length of first STUN packet (TTL=1) */
  /* uint32_t               stunLen; */
  struct hiutPathElement pathElement[MAX_TTL + 1];
  bool                   remoteAlive;
  /* struct hiutTTLinfo     ttlInfo[MAX_TTL]; */
  /* struct npa_trace       trace; */

  /* Recurring traces*/
  int32_t max_recuring;
  int32_t num_traces;

  /* Callback */
  STUN_TRACECB traceCb;
};

bool
isDstUnreachable(const int32_t   ICMPtype,
                 const u_int16_t addrFamily);

bool
isTimeExceeded(const int32_t   ICMPtype,
               const u_int16_t addrFamily);

int
StunTrace_startTrace(STUN_CLIENT_DATA*      clientData,
                     void*                  userCtx,
                     const struct sockaddr* toAddr,
                     const struct sockaddr* fromAddr,
                     uint32_t               sockhandle,
                     const char*            ufrag,
                     const char*            password,
                     uint32_t               numTraces,
                     STUN_TRACECB           traceCbFunc,
                     STUN_SENDFUNC          sendFunc);

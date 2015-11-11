/*
 *  See license file
 */

#ifndef TURN_INTERN_H
#define TURN_INTERN_H

#ifdef __cplusplus
extern "C" {
#endif

#define Dflt_TimerResMsec      50
#define NoStunErrorCode  0xffffffff

/* make sure both the following timers are < 5 minutes */
#define TURN_REFRESH_CHANNEL_TIMER_SEC     (3 * 60)  /* 3 min (spec. is 10 min)
                                                      **/
#define TURN_REFRESH_PERMISSION_TIMER_SEC  (4 * 60)  /* 4 min (spec. is 5 min)
                                                      * */

#define TURN_RETRANS_TIMEOUT_RELEASE_MSEC 150
#define TURN_RETRIES_RELEASE                2


/* Internal TURN signals, inputs to turn client. */
typedef enum {
  TURN_SIGNAL_AllocateReq,
  TURN_SIGNAL_AllocateResp,
  TURN_SIGNAL_AllocateRespError,
  TURN_SIGNAL_CreatePermissionReq,
  TURN_SIGNAL_CreatePermissionResp,
  TURN_SIGNAL_CreatePermissionRespError,
  TURN_SIGNAL_ChannelBindReq,
  TURN_SIGNAL_ChannelBindResp,
  TURN_SIGNAL_ChannelBindRespError,
  TURN_SIGNAL_RefreshResp,
  TURN_SIGNAL_RefreshRespError,
  TURN_SIGNAL_TimerTick,
  TURN_SIGNAL_TimerRetransmit,
  TURN_SIGNAL_TimerRefreshAlloc,
  TURN_SIGNAL_TimerRefreshChannel,
  TURN_SIGNAL_TimerRefreshPermission,
  TURN_SIGNAL_TimerStunKeepAlive,
  TURN_SIGNAL_DeAllocate,

  TURN_SIGNAL_Illegal = -1
} TURN_SIGNAL;

/* Internal message formats */
typedef struct {
  struct sockaddr_storage serverAddr;
  char                    username[STUN_MSG_MAX_USERNAME_LENGTH];
  char                    password[STUN_MSG_MAX_PASSWORD_LENGTH];
  int                     ai_family;    /* AF_INET/AF_INET6 */
  TURN_SEND_FUNC          sendFunc;
  void*                   userCtx;
  TURN_CB_FUNC            turnCbFunc;
  uint32_t                threadCtx;
  bool                    evenPortAndReserve;
  uint64_t                reservationToken;
} TurnAllocateReqStuct;


/* Internal TURN states */
typedef enum {
  TURN_STATE_Idle = 0,
  TURN_STATE_WaitAllocRespNotAuth,
  TURN_STATE_WaitAllocResp,
  TURN_STATE_Allocated,
  TURN_STATE_WaitAllocRefreshResp,
  TURN_STATE_WaitChanBindResp,
  TURN_STATE_WaitCreatePermResp,
  TURN_STATE_WaitReleaseResp,
  TURN_STATE_End    /* must be last */
} TURN_STATE;



/********************************************/
/******  instance data ********  (internal) */
/********************************************/


typedef struct
{
  uint16_t                channelNumber;
  struct sockaddr_storage peerTrnspAddr;
  bool                    createPermission;
}
TurnChannelBindInfo_T;

typedef struct
{
  uint32_t                numberOfPeers;
  struct sockaddr_storage peerTrnspAddr[TURN_MAX_PERMISSION_PEERS];
}
TurnCreatePermissionInfo_T;


struct TURN_INSTANCE_DATA
{
  char           softwareVersionStr[100];
  unsigned long  id;
  TURN_INFO_FUNC infoFunc;

  TURN_STATE            state;
  bool                  inUse;
  TurnAllocateReqStuct  turnAllocateReq;
  StunMsgId             StunReqTransId;                          /* transaction
                                                                  *id of request
                                                                  **/
  StunMsgId             PrevRespTransId;                         /* transaction
                                                                  *id of last
                                                                  *received */
  uint8_t               stunReqMsgBuf[STUN_MAX_PACKET_SIZE];     /* encoded STUN
                                                                  *request    */
  int                   stunReqMsgBufLen;                        /* of encoded
                                                                  *STUN request
                                                                  **/
  bool                  pendingChannelBind;
  STUN_USER_CREDENTIALS userCredentials;
  bool                  authenticated;
  bool                  permissionsInstalled;
  bool                  channelBound;
  bool                  createPermissionCallbackCalled;
  bool                  channelBindCallbackCalled;
  /* returned in allocate resp */

  struct sockaddr_storage srflxAddr;
  struct sockaddr_storage relAddr_IPv4;
  struct sockaddr_storage relAddr_IPv6;

  uint32_t                   lifetime; /* Seconds */
  TurnChannelBindInfo_T      channelBindInfo;
  TurnCreatePermissionInfo_T createPermInfo;
  /* timers */
  uint32_t timerResMsec;
  int32_t  TimerRetransmit;
  int32_t  TimerRefreshAlloc;
  int32_t  TimerRefreshChannel;
  int32_t  TimerRefreshPermission;
  int32_t  TimerStunKeepAlive;
  int      retransmits;
  int      failures;
  uint64_t token;

  bool doStunKeepAlive;

  TurnCallBackData_T turnCbData;

  void* userData;
};


/* state function */
typedef void (* TURN_STATE_FUNC)(TURN_INSTANCE_DATA* pInst,
                                 TURN_SIGNAL         sig,
                                 uint8_t*            payload,
                                 uint8_t*            origMsgBuf);

/* entry in state table */
typedef struct
{
  TURN_STATE_FUNC Statefunc;
  const char*     StateStr;
}
TURN_STATE_TABLE;


void
TurnClientSimulateSig(void*       instance,
                      TURN_SIGNAL sig);


#ifdef __cplusplus
}
#endif


#endif  /* TURN_INTERN_H */

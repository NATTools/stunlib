/*
 *  See license file
 */



/*******************************************************************************
 * Description   :
 * implemented as an OS independent state machine.
 * Initialisaiton:
 *      Application calls StunClientBind_init().
 *
 * Entrypoints:
 *      1. Application calls StunClientBind_startxxxxx() to initiate the
 * stun/ice protocol sequence.
 *      2. StunClientBind_HandleTick() must be called by appl. every N msec such
 * that it can carry out timing/retransmissions.
 *      3. Application calls StunClientBind_HandleIncResp() when it detects
 * incoming stun responses in the media RTP/RTCP stream.
 *
 * Outputs:
 *      1. Application provides function pointer and  data ptr to receive the
 * result of the  stun/ice protocol.
 *
 ******************************************************************************/


#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "stunclient.h"
#include "stun_intern.h"


#include "sockaddr_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>

static const uint32_t stunTimeoutList[STUNCLIENT_MAX_RETRANSMITS] =
{ STUNCLIENT_RETRANSMIT_TIMEOUT_LIST};

static const uint32_t stuntraceTimeoutList[STUNTRACE_MAX_RETRANSMITS] =
{ STUNTRACE_RETRANSMIT_TIMEOUT_LIST};

/* forward declarations of statics */
static void
StunClientMain(STUN_CLIENT_DATA* clientData,
               int               ctx,
               STUN_SIGNAL       sig,
               uint8_t*          payload);

static void
StunClientFsm(STUN_TRANSACTION_DATA* trans,
              STUN_SIGNAL            sig,
              uint8_t*               payload);
static void
SetNextState(STUN_TRANSACTION_DATA* trans,
             STUN_STATE             NextState);

/* forward declarations of state functions */
static void
StunState_Idle(STUN_TRANSACTION_DATA* trans,
               STUN_SIGNAL            sig,
               uint8_t*               payload);
static void
StunState_WaitBindResp(STUN_TRANSACTION_DATA* trans,
                       STUN_SIGNAL            sig,
                       uint8_t*               payload);
static void
StunState_Cancelled(STUN_TRANSACTION_DATA* trans,
                    STUN_SIGNAL            sig,
                    uint8_t*               payload);
static bool
TimerHasExpired(STUN_TRANSACTION_DATA* trans,
                uint32_t               TimerResMsec);



/*************************************************************************/
/************************ UTILS*******************************************/
/*************************************************************************/


/*
 * Called when an internal STUNCLIENT wants to output managemnt info.
 * Prints the string to a buffer.
 * If the application has defined a callback function to handle the output
 * then this is called with the string and the severity.
 */
void
StunPrint(void*              userData,
          STUN_INFO_FUNC_PTR Log_cb,
          StunInfoCategory_T category,
          const char*        fmt,
          ...)
{
  if (Log_cb)
  {
    char    s[STUN_MAX_ERR_STRLEN];
    va_list ap;
    va_start(ap,fmt);

    /* print string to buffer  */
    vsprintf(s, fmt, ap);
    /* Call the application defined "error callback function" */
    va_end(ap);

    (Log_cb)(userData, category, s);
  }
}


/* debug,trace */
static STUN_SIGNAL
StunMsgToInternalStunSig(const StunMessage* msg)
{
  switch (msg->msgHdr.msgType)
  {
  case STUN_MSG_BindRequestMsg:         return STUN_SIGNAL_BindReq;
  case STUN_MSG_BindResponseMsg:        return STUN_SIGNAL_BindResp;
  case STUN_MSG_BindErrorResponseMsg:   return STUN_SIGNAL_BindRespError;
  default:
    /* Some other message */
    return STUN_SIGNAL_Illegal;
  }
}


/* transaction id compare */
static bool
TransIdIsEqual(const StunMsgId* a,
               const StunMsgId* b)
{
  return (memcmp(a, b, STUN_MSG_ID_SIZE) == 0);
}



static void
StoreStunBindReq(STUN_TRANSACTION_DATA* trans,
                 StunBindReqStruct*     pMsgIn)
{
  /* copy whole msg */
  memcpy( &trans->stunBindReq, pMsgIn, sizeof(StunBindReqStruct) );
}


static void
BuildStunBindReq(STUN_TRANSACTION_DATA* trans,
                 StunMessage*           stunReqMsg)
{
  memset(stunReqMsg, 0, sizeof *stunReqMsg);
  stunReqMsg->msgHdr.msgType = STUN_MSG_BindRequestMsg;

  /* transaction id */
  memcpy( &stunReqMsg->msgHdr.id, &trans->stunBindReq.transactionId,
          sizeof(StunMsgId) );
  /* Username */
  if (strlen(trans->stunBindReq.ufrag) > 0)
  {
    stunReqMsg->hasUsername = true;
    strncpy(stunReqMsg->username.value,
            trans->stunBindReq.ufrag,
            STUN_MAX_STRING - 1);
    stunReqMsg->username.sizeValue =
      min( STUN_MAX_STRING, strlen(trans->stunBindReq.ufrag) );
  }
  /* Priority */
  if (trans->stunBindReq.peerPriority > 0)
  {
    stunReqMsg->hasPriority    = true;
    stunReqMsg->priority.value = trans->stunBindReq.peerPriority;
  }
  /* useCandidate */
  stunReqMsg->hasUseCandidate = trans->stunBindReq.useCandidate;

  /* controlling */
  if (trans->stunBindReq.tieBreaker > 0)
  {
    stunReqMsg->hasControlling    = trans->stunBindReq.iceControlling;
    stunReqMsg->controlling.value = trans->stunBindReq.tieBreaker;
    if (!trans->stunBindReq.iceControlling)
    {
      stunReqMsg->hasControlled    = true;
      stunReqMsg->controlled.value = trans->stunBindReq.tieBreaker;
    }
  }
  /* ttl */
  if (trans->stunBindReq.ttl > 0)
  {
    char ttlString[200];
    char iTTL[5] = "0000\0";
    stunReqMsg->hasTTL  = true;
    stunReqMsg->ttl.ttl = trans->stunBindReq.ttl;

    sprintf(iTTL, "%.4i", trans->stunBindReq.ttl);
    ttlString[0] = '\0';
    for (int i = 0; i < trans->stunBindReq.ttl; i++)
    {
      strncat(ttlString,iTTL, 4);
    }

    stunlib_addTTLString(stunReqMsg, ttlString, 'a');
  }


  /*Adding DISCUSS attributes if present*/
  if (trans->stunBindReq.discussData != NULL)
  {
    stunReqMsg->hasStreamType   = true;
    stunReqMsg->streamType.type =
      trans->stunBindReq.discussData->streamType;
    stunReqMsg->streamType.interactivity =
      trans->stunBindReq.discussData->interactivity;

    stunReqMsg->hasNetworkStatus    = true;
    stunReqMsg->networkStatus.flags =
      trans->stunBindReq.discussData->networkStatus_flags;
    stunReqMsg->networkStatus.nodeCnt =
      trans->stunBindReq.discussData->networkStatus_nodeCnt;
    stunReqMsg->networkStatus.upMaxBandwidth =
      trans->stunBindReq.discussData->networkStatus_upMaxBandwidth;
    stunReqMsg->networkStatus.downMaxBandwidth =
      trans->stunBindReq.discussData->networkStatus_downMaxBandwidth;
  }

  if (trans->stunBindReq.addSoftware)
  {
    stunlib_addSoftware(stunReqMsg, SoftwareVersionStr, STUN_DFLT_PAD);
  }
}


/*************************************************************************/
/************************ API ********************************************/
/*************************************************************************/


bool
StunClient_Alloc(STUN_CLIENT_DATA** clientDataPtr)
{
  STUN_CLIENT_DATA* clientData;

  if (!clientDataPtr)
  {
    return false;
  }

  clientData = malloc(sizeof *clientData);
  if (!clientData)
  {
    return false;
  }

  memset(clientData, 0, sizeof *clientData);

  clientData->Log_cb      = NULL;
  clientData->logUserData = NULL;

  StunClient_clearStats(clientData);

  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    STUN_TRANSACTION_DATA* trans = &clientData->data[i];
    trans->inst   = i;
    trans->state  = STUN_STATE_Idle;
    trans->inUse  = false;
    trans->client = clientData;
  }

  clientData->traceResult.num_traces = 1;

  *clientDataPtr = clientData;
  return true;
}


void
StunClient_free(STUN_CLIENT_DATA* clientData)
{
  if (clientData)
  {
    free(clientData);
  }
}


void
StunClient_RegisterLogger(STUN_CLIENT_DATA*  clientData,
                          STUN_INFO_FUNC_PTR logPtr,
                          void*              userData)
{
  clientData->Log_cb      = logPtr;
  clientData->logUserData = userData;
}


void
StunClient_HandleTick(STUN_CLIENT_DATA* clientData,
                      uint32_t          TimerResMsec)
{
  if (clientData == NULL)
  {
    return;
  }

  /* call fsm for each timer that has expired */
  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    STUN_TRANSACTION_DATA* trans = &clientData->data[i];
    if ( trans->inUse && TimerHasExpired(trans, TimerResMsec) )
    {
      StunClientFsm(trans, STUN_SIGNAL_TimerRetransmit, NULL);
    }
  }
}


int32_t
StunClient_startBindTransaction(STUN_CLIENT_DATA*      clientData,
                                void*                  userCtx,
                                const struct sockaddr* serverAddr,
                                const struct sockaddr* baseAddr,
                                int                    proto,
                                bool                   useRelay,
                                const char*            ufrag,
                                const char*            password,
                                uint32_t               peerPriority,
                                bool                   useCandidate,
                                bool                   iceControlling,
                                uint64_t               tieBreaker,
                                StunMsgId              transactionId,
                                uint32_t               sockhandle,
                                STUN_SENDFUNC          sendFunc,
                                STUNCB                 stunCbFunc,
                                DiscussData*           discussData)
{
  StunBindReqStruct m;

  if (clientData == NULL)
  {
    return STUNCLIENT_CTX_UNKNOWN;
  }

  memset( &m, 0, sizeof(m) );
  m.userCtx = userCtx;
  sockaddr_copy( (struct sockaddr*)&m.serverAddr, serverAddr );
  sockaddr_copy( (struct sockaddr*)&m.baseAddr,   baseAddr );
  strncpy(m.ufrag,    ufrag,    sizeof(m.ufrag) - 1);
  strncpy(m.password, password, sizeof(m.password) - 1);
  m.proto          = proto;
  m.useRelay       = useRelay;
  m.peerPriority   = peerPriority;
  m.useCandidate   = useCandidate;
  m.iceControlling = iceControlling;
  m.tieBreaker     = tieBreaker;
  m.transactionId  = transactionId;
  m.sockhandle     = sockhandle;
  m.sendFunc       = sendFunc;

  m.discussData = discussData;
  m.addSoftware = true;

  /* callback and data (owned by caller) */
  m.stunCbFunc = stunCbFunc;
  StunClientMain(clientData, STUNCLIENT_CTX_UNKNOWN, STUN_SIGNAL_BindReq,
                 (uint8_t*)&m);

  return 0;
}

uint32_t
StunClient_startSTUNTrace(STUN_CLIENT_DATA*      clientData,
                          void*                  userCtx,
                          const struct sockaddr* serverAddr,
                          const struct sockaddr* baseAddr,
                          bool                   useRelay,
                          const char*            ufrag,
                          const char*            password,
                          uint8_t                ttl,
                          StunMsgId              transactionId,
                          uint32_t               sockhandle,
                          STUN_SENDFUNC          sendFunc,
                          STUNCB                 stunCbFunc,
                          DiscussData*           discussData)          /*NULL if
                                                                        * none*/

{
  StunBindReqStruct     m;
  STUN_TRANSACTION_DATA trans;
  StunMessage           stunMsg;
  uint8_t               stunBuff[STUN_MAX_PACKET_SIZE];
  uint32_t              len;

  memset( &m, 0, sizeof(m) );
  m.userCtx = userCtx;
  sockaddr_copy( (struct sockaddr*)&m.serverAddr, serverAddr );
  sockaddr_copy( (struct sockaddr*)&m.baseAddr,   baseAddr );
  m.useRelay = useRelay;
  strncpy(m.ufrag,    ufrag,    sizeof(m.ufrag) - 1);
  strncpy(m.password, password, sizeof(m.password) - 1);

  m.ttl           = ttl;
  m.transactionId = transactionId;
  m.sockhandle    = sockhandle;
  m.sendFunc      = sendFunc;
  m.discussData   = discussData;
  m.addSoftware   = false;
  /* callback and data (owned by caller) */
  m.stunCbFunc = stunCbFunc;
  m.stuntrace  = true;

  StoreStunBindReq(&trans, &m);
  BuildStunBindReq(&trans, &stunMsg);
  StunClientMain(clientData, STUNCLIENT_CTX_UNKNOWN, STUN_SIGNAL_BindReq,
                 (uint8_t*)&m);
  len = stunlib_encodeMessage(&stunMsg,
                              (uint8_t*)stunBuff,
                              STUN_MAX_PACKET_SIZE,
                              (unsigned char*)password,           /* md5key */
                              password ? strlen(password) : 0,    /* keyLen */
                              NULL);
  return len;
}


void
StunClient_HandleIncResp(STUN_CLIENT_DATA*      clientData,
                         const StunMessage*     msg,
                         const struct sockaddr* srcAddr)
{
  if (clientData == NULL)
  {
    return;
  }

  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    STUN_TRANSACTION_DATA* trans = &clientData->data[i];
    if ( trans->inUse &&
         TransIdIsEqual(&msg->msgHdr.id, &trans->stunBindReq.transactionId) )
    {
      StunRespStruct m;
      gettimeofday(&trans->stop[trans->retransmits], NULL);
      memcpy( &m.stunRespMessage, msg, sizeof(m.stunRespMessage) );
      sockaddr_copy( (struct sockaddr*)&m.srcAddr, srcAddr );
      StunClientMain(clientData, i, StunMsgToInternalStunSig(msg), (void*)&m);
      return;
    }
  }
  StunPrint(clientData->logUserData,
            clientData->Log_cb,
            StunInfoCategory_Trace,
            "<STUNCLIENT> no instance with transId, discarding, msgType %d\n ",
            msg->msgHdr.msgType);
}

void
StunClient_HandleICMP(STUN_CLIENT_DATA*      clientData,
                      const struct sockaddr* srcAddr,
                      uint32_t               ICMPtype)
{
  if (clientData == NULL)
  {
    return;
  }
  /* Todo: Test if this is for me.. */
  StunPrint(clientData->logUserData,
            clientData->Log_cb,
            StunInfoCategory_Trace,
            "<STUNTRACE> StunClient_HandleICMP: Got ICMP type: %i\n ",
            ICMPtype);

  if ( isTimeExceeded(ICMPtype, srcAddr->sa_family) ||
       isDstUnreachable(ICMPtype,srcAddr->sa_family) )
  {
    for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
    {
      STUN_TRANSACTION_DATA* trans = &clientData->data[i];
      if ( trans->inUse &&
           TransIdIsEqual(&clientData->traceResult.currStunMsgId,
                          &trans->stunBindReq.transactionId) )
      {
        StunRespStruct m;
        gettimeofday(&trans->stop[trans->retransmits], NULL);
        /* memcpy(&m.stunRespMessage, msg, sizeof(m.stunRespMessage)); */
        sockaddr_copy( (struct sockaddr*)&m.srcAddr, srcAddr );
        m.ICMPtype = ICMPtype;
        m.ttl      = clientData->traceResult.currentTTL;
        StunClientMain(clientData, i, STUN_SIGNAL_ICMPResp, (void*)&m);
        return;

      }
    }
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Trace,
              "<STUNTRACE> StunClient_HandleICMP: Ignoring ICMP Type, nothing to do\n ",
              ICMPtype);
  }
}

/*
 * Cancel a transaction with  matching  transaction id
 *      transactionId  - Transaction id.
 * return -  if  transaction found returns ctx/instance
 *        -  if  no instance found with transactionid, returns
 * STUNCLIENT_CTX_UNKNOWN
 */
int
StunClient_cancelBindingTransaction(STUN_CLIENT_DATA* clientData,
                                    StunMsgId         transactionId)
{
  if (clientData == NULL)
  {
    return STUNCLIENT_CTX_UNKNOWN;
  }

  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    STUN_TRANSACTION_DATA* trans = &clientData->data[i];
    if ( trans->inUse &&
         TransIdIsEqual(&transactionId, &trans->stunBindReq.transactionId) )
    {
      StunClientMain(clientData, i, STUN_SIGNAL_Cancel, NULL);
      return i;
    }
  }

  return STUNCLIENT_CTX_UNKNOWN;
}


static bool
CreateConnectivityBindingResp(StunMessage*           stunMsg,
                              StunMsgId              transactionId,
                              const struct sockaddr* mappedSockAddr,
                              uint16_t               response,
                              uint32_t               responseCode,
                              DiscussData*           discussData)
{
  StunIPAddress mappedAddr;

  if ( !sockaddr_isSet(mappedSockAddr) )
  {
    return false;
  }

  memset(stunMsg, 0, sizeof *stunMsg);
  stunMsg->msgHdr.msgType = response;

  if (mappedSockAddr->sa_family == AF_INET)
  {
    mappedAddr.familyType   =  STUN_ADDR_IPv4Family;
    mappedAddr.addr.v4.port = ntohs(
      ( (struct sockaddr_in*)mappedSockAddr )->sin_port);
    mappedAddr.addr.v4.addr = ntohl(
      ( (struct sockaddr_in*)mappedSockAddr )->sin_addr.s_addr);

  }
  else if (mappedSockAddr->sa_family == AF_INET6)
  {
    mappedAddr.familyType   =  STUN_ADDR_IPv6Family;
    mappedAddr.addr.v6.port = ntohs(
      ( (struct sockaddr_in6*)mappedSockAddr )->sin6_port);

    /*TODO: will this be correct ? */
    memcpy( mappedAddr.addr.v6.addr,
            ( (struct sockaddr_in6*)mappedSockAddr )->sin6_addr.s6_addr,
            sizeof(mappedAddr.addr.v6.addr) );
  }
  else
  {
    return false;
  }

  /*id*/
  stunMsg->msgHdr.id = transactionId;

  /* The XOR address MUST be added according to the RFC */
  stunMsg->hasXorMappedAddress = true;
  stunMsg->xorMappedAddress    = mappedAddr;

  if (discussData != NULL)
  {
    stunMsg->hasStreamType            = true;
    stunMsg->streamType.type          = discussData->streamType;
    stunMsg->streamType.interactivity = discussData->interactivity;

    stunMsg->hasNetworkStatus               = true;
    stunMsg->networkStatus.flags            = 0;
    stunMsg->networkStatus.nodeCnt          = 0;
    stunMsg->networkStatus.upMaxBandwidth   = 0;
    stunMsg->networkStatus.downMaxBandwidth = 0;

    stunMsg->hasNetworkStatusResp    = true;
    stunMsg->networkStatusResp.flags =
      discussData->networkStatusResp_flags;
    stunMsg->networkStatusResp.nodeCnt =
      discussData->networkStatusResp_nodeCnt;
    stunMsg->networkStatusResp.upMaxBandwidth =
      discussData->networkStatusResp_upMaxBandwidth;
    stunMsg->networkStatusResp.downMaxBandwidth =
      discussData->networkStatusResp_downMaxBandwidth;
  }
  if (responseCode != 200)
  {
    stunMsg->hasErrorCode         = true;
    stunMsg->errorCode.errorClass = responseCode / 100;
    stunMsg->errorCode.number     = (uint8_t) (responseCode % 100);
    if (responseCode == 487)
    {
      strncpy( stunMsg->errorCode.reason, "Role Conflict",
               sizeof (stunMsg->errorCode.reason) );
      stunMsg->errorCode.sizeReason = strlen(stunMsg->errorCode.reason);
    }
    else if (responseCode == 400)
    {
      strncpy( stunMsg->errorCode.reason, "Bad Request",
               sizeof (stunMsg->errorCode.reason) );
      stunMsg->errorCode.sizeReason = strlen(stunMsg->errorCode.reason);
    }
  }

  return true;
}


static bool
SendConnectivityBindResponse(STUN_CLIENT_DATA*      clientData,
                             int32_t                globalSocketId,
                             StunMessage*           stunRespMsg,
                             const char*            password,
                             const struct sockaddr* dstAddr,
                             void*                  userData,
                             STUN_SENDFUNC          sendFunc,
                             int                    proto,
                             bool                   useRelay)
{
  uint8_t stunBuff[STUN_MAX_PACKET_SIZE];
  int     stunLen;

  (void) userData;
  /* encode bind Response */
  stunLen = stunlib_encodeMessage(stunRespMsg,
                                  (uint8_t*)stunBuff,
                                  STUN_MAX_PACKET_SIZE,
                                  (unsigned char*)password,           /* md5key
                                                                      **/
                                  password ? strlen(password) : 0,    /* keyLen
                                                                      **/
                                  NULL);
  if (!stunLen)
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT>  Failed to encode Binding request response\n");
    return false;
  }

  /* send */
  /* sendFunc(globalSocketId, stunBuff, stunLen, dstAddr, useRelay, 0); */
  sendFunc(clientData->userCtx,
           globalSocketId,
           stunBuff,
           stunLen,
           dstAddr,
           proto,
           useRelay,
           0);
  clientData->stats.BindRespSent++;
  return true;
}


/********* Server handling of STUN BIND RESP *************/
bool
StunServer_SendConnectivityBindingResp(STUN_CLIENT_DATA*      clientData,
                                       int32_t                globalSocketId,
                                       StunMsgId              transactionId,
                                       const char*            password,
                                       const struct sockaddr* mappedAddr,
                                       const struct sockaddr* dstAddr,
                                       void*                  userData,
                                       STUN_SENDFUNC          sendFunc,
                                       int                    proto,
                                       bool                   useRelay,
                                       uint32_t               responseCode,
                                       DiscussData*           discussData)
{
  StunMessage stunRespMsg;

  /* format */
  if ( CreateConnectivityBindingResp(&stunRespMsg,
                                     transactionId,
                                     mappedAddr,
                                     (responseCode ==
                                      200) ? STUN_MSG_BindResponseMsg :
                                     STUN_MSG_BindErrorResponseMsg,
                                     responseCode,
                                     discussData) )
  {
    /* encode and send */
    if ( SendConnectivityBindResponse(clientData,
                                      globalSocketId,
                                      &stunRespMsg,
                                      password,
                                      dstAddr,
                                      userData,
                                      sendFunc,
                                      proto,
                                      useRelay) )
    {
      return true;
    }
  }
  return false;
}


/********** Server handling of incoming STUN BIND REQ **********/
bool
StunServer_HandleStunIncomingBindReqMsg(STUN_CLIENT_DATA*       clientData,
                                        STUN_INCOMING_REQ_DATA* pReq,
                                        const StunMessage*      stunMsg,
                                        bool                    fromRelay)
{
  if (!clientData)
  {
    return false;
  }

  memcpy( &pReq->transactionId, &stunMsg->msgHdr.id, sizeof(StunMsgId) );

  pReq->fromRelay = fromRelay;

  if (stunMsg->hasUsername)
  {
    strncpy( pReq->ufrag, stunMsg->username.value,
             min(stunMsg->username.sizeValue, STUN_MAX_STRING) );
    if (stunMsg->username.sizeValue < STUN_MAX_STRING)
    {
      pReq->ufrag[stunMsg->username.sizeValue] = '\0';
    }
    else
    {
      pReq->ufrag[STUN_MAX_STRING - 1] = '\0';
    }
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT> Missing Username in Binding Request\n");
    return false;
  }

  if (stunMsg->hasPriority)
  {
    pReq->peerPriority = stunMsg->priority.value;
  }
  else
  {
    StunPrint(clientData->logUserData,
              clientData->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT> Missing Priority in Binding Request\n");
    return false;
  }

  pReq->useCandidate = stunMsg->hasUseCandidate;

  if (stunMsg->hasControlling)
  {
    pReq->iceControlling = true;
    pReq->tieBreaker     = stunMsg->controlling.value;
  }
  else
  {
    pReq->iceControlling = false;
  }

  if (stunMsg->hasControlled)
  {
    pReq->iceControlled = true;
    pReq->tieBreaker    = stunMsg->controlled.value;
  }
  else
  {
    pReq->iceControlled = false;
  }

  if (fromRelay)
  {
    clientData->stats.BindReqReceived_ViaRelay++;
  }
  clientData->stats.BindReqReceived++;

  return true;
}


/*************************************************************************/
/************************ FSM Framework **********************************/
/*************************************************************************/


static const STUN_STATE_TABLE StateTable[STUN_STATE_End] =
{
  /* function ptr */                      /* str */
  { StunState_Idle,                       "Idle"                          },
  { StunState_WaitBindResp,               "WaitBindResp"                  },
  { StunState_Cancelled,                  "Cancelled"                     },
};

static const uint32_t NoOfStates = sizeof(StateTable) / sizeof(StateTable[0]);


static const char*
StunsigToStr(STUN_SIGNAL sig)
{
  switch (sig)
  {
  case STUN_SIGNAL_BindReq:            return "BindReq";
  case STUN_SIGNAL_BindResp:           return "BindResp";
  case STUN_SIGNAL_BindRespError:      return "BindRespError";
  case STUN_SIGNAL_TimerTick:          return "TimerTick";
  case STUN_SIGNAL_TimerRetransmit:    return "TimerRetransmit";
  case STUN_SIGNAL_ICMPResp:           return "ICMPResp";
  case STUN_SIGNAL_DeAllocate:         return "DeAllocate";
  case STUN_SIGNAL_Cancel:             return "Cancel";
  default:                             return "???";
  }
}


/* */
static int
AllocFreeInst(STUN_CLIENT_DATA* clientData,
              STUN_SIGNAL*      sig,
              uint8_t*          payload)
{
  (void) sig;
  (void) payload;
  int i;

  for (i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    STUN_TRANSACTION_DATA* trans = &clientData->data[i];
    if (!trans->inUse)
    {
      trans->inUse = true;
      return i;
    }
  }

  return STUNCLIENT_CTX_UNKNOWN;
}


static void
SetNextState(STUN_TRANSACTION_DATA* trans,
             STUN_STATE             NextState)
{
  STUN_CLIENT_DATA* client = trans->client;

  if  (NextState >= NoOfStates)
  {
    StunPrint(client->logUserData,
              client->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT:%02d> SetNextState, Illegal State %d",
              trans->inst,
              NextState);
    return;
  }

  if (trans->state != NextState)
  {
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Trace,
              "<STUNCLIENT:%02d> State (%s -> %s)", trans->inst,
              StateTable[trans->state].StateStr,
              StateTable[NextState].StateStr);
    trans->state = NextState;
  }

  /* always free instance on return to idle */
  if (NextState == STUN_STATE_Idle)
  {
    trans->inUse = false;
  }
}


/* check if timer has expired and return the timer signal */
static bool
TimerHasExpired(STUN_TRANSACTION_DATA* trans,
                uint32_t               TimerResMsec)
{
  if (trans)
  {
    int* timer = &trans->TimerRetransmit;
    if (*timer)     /* check timer is running */
    {
      *timer -= TimerResMsec;
      if (*timer <= 0)
      {
        *timer = 0;
        return true;
      }
    }
  }

  return false;
}


/* check if timer has expired and return the timer signal */
static void
StartTimer(STUN_TRANSACTION_DATA* trans,
           STUN_SIGNAL            sig,
           uint32_t               durationMsec)
{
  STUN_CLIENT_DATA* client = trans->client;

    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Trace,
            "<STUNCLIENT:%02d> StartTimer(%s, %dms)",
            trans->inst, StunsigToStr(sig), durationMsec);

  switch (sig)
  {
  case STUN_SIGNAL_TimerRetransmit:
    trans->TimerRetransmit = durationMsec;
    break;

  default:
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Error,
              "<STUNCLIENT:%02d> illegal StartTimer %d, duration %d",
              trans->inst,  sig, durationMsec);
    break;
  }
}

/* check if timer has expired and return the timer signal */
static void
StopTimer(STUN_TRANSACTION_DATA* trans,
          STUN_SIGNAL            sig)
{
  STUN_CLIENT_DATA* client = trans->client;

    StunPrint( client->logUserData, client->Log_cb, StunInfoCategory_Trace,
             "<STUNCLIENT:%02d> StopTimer(%s)", trans->inst,
             StunsigToStr(sig) );

  switch (sig)
  {
  case STUN_SIGNAL_TimerRetransmit:
    trans->TimerRetransmit = 0;
    break;

  default:
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Error,
              "<STUNCLIENT:%02d> illegal StopTimer %d", trans->inst,  sig);
    break;
  }
}


static void
StunClientMain(STUN_CLIENT_DATA* clientData,
               int               ctx,
               STUN_SIGNAL       sig,
               uint8_t*          payload)
{
  /* if  context is already known, just call the  fsm */
  if (ctx != STUNCLIENT_CTX_UNKNOWN)
  {
    if (ctx < MAX_STUN_TRANSACTIONS)
    {
      StunClientFsm(&clientData->data[ctx], sig, payload);
    }
    else
    {
      StunPrint(clientData->logUserData,
                clientData->Log_cb,
                StunInfoCategory_Error,
                "<STUNCLIENT> sig: %s illegal context %d exceeds %d\n ",
                StunsigToStr(sig),
                ctx,
                MAX_STUN_TRANSACTIONS);
    }
  }
  else if (sig == STUN_SIGNAL_BindReq)
  {
    ctx = AllocFreeInst(clientData,&sig, payload);
    if (ctx >= 0)
    {
      StunClientFsm(&clientData->data[ctx], sig, payload);
    }
    else
    {
      StunPrint( clientData->logUserData, clientData->Log_cb,
                 StunInfoCategory_Error,
                 "<STUNCLIENT> No free instances, sig: %s", StunsigToStr(sig) );
    }
  }
}


/*************************************************************************/
/************************ FSM functions  *********************************/
/*************************************************************************/


/* clear everything except  instance, state and log info*/
static void
InitInstData(STUN_TRANSACTION_DATA* trans)
{
  STUN_TRANSACTION_DATA orig = *trans;

  memset(trans, 0, sizeof *trans);

  trans->state  = orig.state;
  trans->inst   = orig.inst;
  trans->inUse  = orig.inUse;
  trans->stats  = orig.stats;
  trans->client = orig.client;
}

/* encode and send */
static bool
SendStunReq(STUN_TRANSACTION_DATA* trans,
            StunMessage*           stunReqMsg)
{
  STUN_CLIENT_DATA* client = trans->client;
  /* encode the BindReq */
  if (strlen(trans->stunBindReq.password) > 0)
  {
    trans->stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                                    (unsigned char*) (trans->
                                                                      stunReqMsgBuf),
                                                    STUN_MAX_PACKET_SIZE,
                                                    (unsigned char*)&trans->stunBindReq.password,
                                                    /* key */
                                                    strlen(trans->stunBindReq.
                                                           password),
                                                    /* keyLen
                                                     * */
                                                    NULL);
  }
  else
  {
    trans->stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                                    (unsigned char*) (trans->
                                                                      stunReqMsgBuf),
                                                    STUN_MAX_PACKET_SIZE,
                                                    NULL,
                                                    /* key */
                                                    0,
                                                    /* keyLen  */
                                                    NULL);

  }

  if (!trans->stunReqMsgBufLen)
  {
    StunPrint(client->logUserData,
              client->Log_cb,
              StunInfoCategory_Error,
              "<STUNCLIENT:%02d>  SendStunReq(BindReq), failed encode",
              trans->inst);
    return false;
  }

  /*Store Time so we can messure RTT */
  gettimeofday(&trans->start[trans->retransmits], NULL);
  if (trans->stunBindReq.sendFunc != NULL)
  {
    trans->stunBindReq.sendFunc(trans->client->userCtx,
                                trans->stunBindReq.sockhandle,
                                trans->stunReqMsgBuf,
                                trans->stunReqMsgBufLen,
                                (struct sockaddr*)&trans->stunBindReq.serverAddr,
                                trans->stunBindReq.proto,
                                trans->stunBindReq.useRelay,
                                trans->stunBindReq.ttl);
  }
  trans->stats.BindReqSent++;

  return true;
}


static void
StunClientFsm(STUN_TRANSACTION_DATA* trans,
              STUN_SIGNAL            sig,
              uint8_t*               payload)
{
  STUN_CLIENT_DATA* client = trans->client;

  if (trans->state < STUN_STATE_End)
  {
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Trace,
              "<STUNCLIENT:%02d> IN <-- %s (state %s)",
              trans->inst, StunsigToStr(sig),
              StateTable[trans->state].StateStr);
    (StateTable[trans->state].Statefunc)(trans, sig, payload);
  }
  else
  {
    StunPrint( client->logUserData, client->Log_cb, StunInfoCategory_Error,
               "<STUNCLIENT:%02d> undefned state %d, sig %s",
               trans->inst, trans->state, StunsigToStr(sig) );
  }
}


static void
RetransmitLastReq(STUN_TRANSACTION_DATA*   trans,
                  struct sockaddr_storage* destAddr)
{
  gettimeofday(&trans->start[trans->retransmits + 1], NULL);
  trans->stunBindReq.sendFunc(trans->client->userCtx,
                              trans->stunBindReq.sockhandle,
                              trans->stunReqMsgBuf,
                              trans->stunReqMsgBufLen,
                              (struct sockaddr*)destAddr,
                              trans->stunBindReq.proto,
                              trans->stunBindReq.useRelay,
                              trans->stunBindReq.ttl);
}


static void
StartFirstRetransmitTimer(STUN_TRANSACTION_DATA* trans)
{
  trans->retransmits = 0;
  if (trans->stunBindReq.stuntrace)
  {
    StartTimer(trans, STUN_SIGNAL_TimerRetransmit,
               stuntraceTimeoutList[trans->retransmits]);
  }
  else
  {
    StartTimer(trans, STUN_SIGNAL_TimerRetransmit,
               stunTimeoutList[trans->retransmits]);
  }
}


static void
StartNextRetransmitTimer(STUN_TRANSACTION_DATA* trans)
{
  if (trans->stunBindReq.stuntrace)
  {
    StartTimer(trans, STUN_SIGNAL_TimerRetransmit,
               stuntraceTimeoutList[trans->retransmits]);
  }
  else
  {
    StartTimer(trans, STUN_SIGNAL_TimerRetransmit,
               stunTimeoutList[trans->retransmits]);
  }
}


static void
CallBack(STUN_TRANSACTION_DATA* trans,
         StunResult_T           stunResult)
{
  StunCallBackData_T res;
  memset( &res, 0, sizeof (StunCallBackData_T) );

  memcpy( &res.msgId, &trans->stunBindReq.transactionId, sizeof(StunMsgId) );
  res.stunResult = stunResult;
  res.ttl        = trans->stunBindReq.ttl;

  if (trans->stunBindReq.stunCbFunc)
  {
    (trans->stunBindReq.stunCbFunc)(trans->stunBindReq.userCtx, &res);
  }
}


static void
CommonRetryTimeoutHandler(STUN_TRANSACTION_DATA* trans,
                          StunResult_T           stunResult,
                          const char*            errStr,
                          STUN_STATE             FailedState)
{
  STUN_CLIENT_DATA* client = trans->client;

  uint32_t max;

  if (trans->stunBindReq.stuntrace)
  {
    max = STUNTRACE_MAX_RETRANSMITS;
  }
  else
  {
    max = STUNCLIENT_MAX_RETRANSMITS;
  }

  if ( (trans->retransmits < max)
       && (stunTimeoutList[trans->retransmits] != 0) ) /* can be 0 terminated if
                                                        * using fewer
                                                        * retransmits
                                                        **/
  {
    char peer [SOCKADDR_MAX_STRLEN] = {0,};
    sockaddr_toString( (struct sockaddr*) &trans->stunBindReq.serverAddr, peer,
                       sizeof (peer), true );

    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Trace,
              "<STUNCLIENT:%02d> Retrans %s Retry: %d to %s",
              trans->inst, errStr, trans->retransmits + 1, peer);
    RetransmitLastReq(trans, &trans->stunBindReq.serverAddr);
    StartNextRetransmitTimer(trans);
    trans->retransmits++;
    trans->stats.Retransmits++;
  }
  else
  {
    CallBack(trans, stunResult);
    SetNextState(trans, FailedState);
    trans->stats.Failures++;
  }
}


static void
CancelRetryTimeoutHandler(STUN_TRANSACTION_DATA* trans)
{
  STUN_CLIENT_DATA* client = trans->client;

  if ( (trans->retransmits < STUNCLIENT_MAX_RETRANSMITS)
       && (stunTimeoutList[trans->retransmits] != 0) ) /* can be 0 terminated if
                                                        * using fewer
                                                        * retransmits
                                                        **/
  {
    StartNextRetransmitTimer(trans);
    trans->retransmits++;
  }
  else
  {
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Trace,
              "<STUNCLIENT:%02d> Cancel complete", trans->inst);
    CallBack(trans, StunResult_CancelComplete);
    SetNextState(trans, STUN_STATE_Idle);
  }
}


static void
InitRetryCounters(STUN_TRANSACTION_DATA* trans)
{
  trans->retransmits = 0;
}


static bool
StoreBindResp(STUN_TRANSACTION_DATA* trans,
              StunMessage*           resp)
{
  STUN_CLIENT_DATA* client = trans->client;

  if (resp->hasXorMappedAddress)
  {
    if (resp->xorMappedAddress.familyType == STUN_ADDR_IPv4Family)
    {
      sockaddr_initFromIPv4Int( (struct sockaddr_in*)&trans->rflxAddr,
                                htonl(resp->xorMappedAddress.addr.v4.addr),
                                htons(resp->xorMappedAddress.addr.v4.port) );
    }
    else if (resp->xorMappedAddress.familyType == STUN_ADDR_IPv6Family)
    {
      sockaddr_initFromIPv6Int( (struct sockaddr_in6*)&trans->rflxAddr,
                                resp->xorMappedAddress.addr.v6.addr,
                                htons(resp->xorMappedAddress.addr.v6.port) );
    }

    return true;
  }
  else
  {
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Error,
              "<STUNCLIENT:%02d> Missing XorMappedAddress BindResp",
              trans->inst);
    return false;
  }
}

static int
getRTTvalue(STUN_TRANSACTION_DATA* trans)
{
  int32_t stop = (trans->stop[trans->retransmits].tv_sec * 1000000 +
                  trans->stop[trans->retransmits].tv_usec);
  /* Always use the first stored value for start. */
  int32_t start = (trans->start[0].tv_sec * 1000000 +
                   trans->start[0].tv_usec);

  return stop - start;


}
static void
BindRespCallback(STUN_TRANSACTION_DATA* trans,
                 const struct sockaddr* srcAddr)
{
  STUN_CLIENT_DATA*  client = trans->client;
  char               ip_str [SOCKADDR_MAX_STRLEN];
  StunCallBackData_T res;

  memset( &res, 0, sizeof (StunCallBackData_T) );

  memcpy( &res.msgId, &trans->stunBindReq.transactionId, sizeof(StunMsgId) );

  res.stunResult = StunResult_BindOk;

  sockaddr_copy( (struct sockaddr*)&res.rflxAddr,
                 (struct sockaddr*)&trans->rflxAddr );

  sockaddr_copy( (struct sockaddr*)&res.srcAddr,
                 srcAddr );

  sockaddr_copy( (struct sockaddr*)&res.dstBaseAddr,
                 (struct sockaddr*)&trans->stunBindReq.baseAddr );

  /* So did we loose a packet, or got an answer to the first response?*/

  res.rtt = getRTTvalue(trans);
  res.ttl = trans->stunBindReq.ttl;

  StunPrint( client->logUserData, client->Log_cb, StunInfoCategory_Info,
             "<STUNCLIENT:%02d> BindResp from src: %s",
             trans->inst,
             sockaddr_toString( (struct sockaddr*) &res.srcAddr, ip_str,
                                SOCKADDR_MAX_STRLEN,
                                true ) );

  if (trans->stunBindReq.stunCbFunc)
  {
    (trans->stunBindReq.stunCbFunc)(trans->stunBindReq.userCtx, &res);
  }
}


static void
ICMPRespCallback(STUN_TRANSACTION_DATA* trans,
                 const struct sockaddr* srcAddr)
{
  STUN_CLIENT_DATA*  client = trans->client;
  char               ip_str [SOCKADDR_MAX_STRLEN];
  StunCallBackData_T res;

  memset( &res, 0, sizeof (StunCallBackData_T) );

  memcpy( &res.msgId, &trans->stunBindReq.transactionId, sizeof(StunMsgId) );

  res.stunResult = StunResult_ICMPResp;
  res.ICMPtype   = trans->ICMPtype;
  res.ttl        = trans->ttl;

  res.rtt         = getRTTvalue(trans);
  res.retransmits = trans->retransmits;
  sockaddr_copy( (struct sockaddr*)&res.srcAddr,
                 srcAddr );

  StunPrint( client->logUserData, client->Log_cb, StunInfoCategory_Info,
             "<STUNCLIENT:%02d> ICMPResp from src: %s",
             trans->inst,
             sockaddr_toString( (struct sockaddr*) &res.srcAddr, ip_str,
                                SOCKADDR_MAX_STRLEN,
                                true ) );


  if (trans->stunBindReq.stunCbFunc)
  {
    (trans->stunBindReq.stunCbFunc)(trans->stunBindReq.userCtx, &res);
  }
}


/* Common signal handling for all states */
static void
StunAllState(STUN_TRANSACTION_DATA* trans,
             STUN_SIGNAL            sig)
{
  STUN_CLIENT_DATA* client = trans->client;

  StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Error,
            "<STUNCLIENT:%02d> undefined signal %s in state %d",
            trans->inst, StunsigToStr(sig), trans->state);
}


static void
StunState_Idle(STUN_TRANSACTION_DATA* trans,
               STUN_SIGNAL            sig,
               uint8_t*               payload)
{
  switch (sig)
  {
  case STUN_SIGNAL_BindReq:
  {
    StunBindReqStruct* pMsgIn = (StunBindReqStruct*)payload;
    StunMessage        stunReqMsg;   /* decoded */
    /* clear instance data */
    InitInstData(trans);
    /* store msg */
    StoreStunBindReq(trans, pMsgIn);
    /* build and send stun bind req */
    BuildStunBindReq(trans, &stunReqMsg);
    SendStunReq(trans, &stunReqMsg);
    InitRetryCounters(trans);
    StartFirstRetransmitTimer(trans);
    SetNextState(trans, STUN_STATE_WaitBindResp);
    break;
  }

  case STUN_SIGNAL_DeAllocate:       /* ignore extra clears */
  case STUN_SIGNAL_Cancel:
    break;

  case STUN_SIGNAL_BindResp:
    trans->stats.BindRespReceived_InIdle++;
    break;

  default:
    StunAllState(trans, sig);
    break;
  }

} /* StunState_Idle() */


/*
 * Bind request has been sent, waiting for response.
 */
static void
StunState_WaitBindResp(STUN_TRANSACTION_DATA* trans,
                       STUN_SIGNAL            sig,
                       uint8_t*               payload)
{
  switch (sig)
  {
  case STUN_SIGNAL_BindResp:
  {
    StunRespStruct* pMsgIn = (StunRespStruct*)payload;
    StunMessage*    pResp  = &pMsgIn->stunRespMessage;

    StopTimer(trans, STUN_SIGNAL_TimerRetransmit);
    trans->ttl = pMsgIn->ttl;
    if ( StoreBindResp(trans, pResp) )
    {
      BindRespCallback(trans, (struct sockaddr*)&pMsgIn->srcAddr);
    }
    else
    {
      CallBack(trans, StunResult_MalformedResp);
    }
    trans->stats.BindRespReceived++;
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_ICMPResp:
  {
    StunRespStruct* pMsgIn = (StunRespStruct*)payload;
    trans->ICMPtype = pMsgIn->ICMPtype;
    trans->ttl      = pMsgIn->ttl;
    ICMPRespCallback(trans, (struct sockaddr*)&pMsgIn->srcAddr);
    trans->stats.ICMPReceived++;
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_BindRespError:
  {
    CallBack(trans, StunResult_BindFail);
    trans->stats.BindRespErrReceived++;
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_Cancel:
  {
    SetNextState(trans, STUN_STATE_Cancelled);
    break;
  }

  case STUN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(trans,
                              StunResult_BindFailNoAnswer,
                              "BindReq",
                              STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_DeAllocate:
  {
    StopTimer(trans, STUN_SIGNAL_TimerRetransmit);
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  default:
    StunAllState(trans, sig);
    break;
  }

} /* StunState_WaitBindResp() */



/*
 * Cancel hes been received, still waiting for response.
 * Do not fail if timeout
 */
static void
StunState_Cancelled(STUN_TRANSACTION_DATA* trans,
                    STUN_SIGNAL            sig,
                    uint8_t*               payload)
{
  switch (sig)
  {
  case STUN_SIGNAL_BindResp:
  {
    StunRespStruct* pMsgIn = (StunRespStruct*)payload;
    StunMessage*    pResp  = &pMsgIn->stunRespMessage;

    StopTimer(trans, STUN_SIGNAL_TimerRetransmit);
    trans->ttl = pMsgIn->ttl;
    if ( StoreBindResp(trans, pResp) )
    {
      BindRespCallback(trans, (struct sockaddr*)&pMsgIn->srcAddr);
    }
    else
    {
      CallBack(trans, StunResult_MalformedResp);
    }
    trans->stats.BindRespReceived_AfterCancel++;
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_BindRespError:
  {
    CallBack(trans, StunResult_BindFail);
    trans->stats.BindRespErrReceived++;
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }

  case STUN_SIGNAL_TimerRetransmit:
  {
    CancelRetryTimeoutHandler(trans);
    break;
  }

  case STUN_SIGNAL_DeAllocate:
  {
    StopTimer(trans, STUN_SIGNAL_TimerRetransmit);
    SetNextState(trans, STUN_STATE_Idle);
    break;
  }
  case STUN_SIGNAL_Cancel:
    /* Ignore */
    break;

  default:
    StunAllState(trans, sig);
    break;
  }

} /* StunState_Cancelled() */


void
StunClient_clearStats(STUN_CLIENT_DATA* clientData)
{
  if (!clientData)
  {
    return;
  }

    memset(&clientData->stats, 0, sizeof clientData->stats);

  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    memset( &clientData->data[i].stats, 0, sizeof (struct StunClientStats) );
  }
}


void
StunClient_dumpStats (STUN_CLIENT_DATA*  clientData,
                      STUN_INFO_FUNC_PTR logPtr,
                      void*              userData)
{
  struct StunClientStats  stats;
  struct StunClientStats* ptr     = &clientData->stats;
  int                     usedCnt = 0;

    memset(&stats, 0, sizeof stats);

  stats.InProgress                   += ptr->InProgress;
  stats.BindReqSent                  += ptr->BindReqSent;
  stats.BindReqSent_ViaRelay         += ptr->BindReqSent_ViaRelay;
  stats.BindRespReceived             += ptr->BindRespReceived;
  stats.BindRespReceived_AfterCancel += ptr->BindRespReceived_AfterCancel;
  stats.BindRespReceived_InIdle      += ptr->BindRespReceived_InIdle;
  stats.BindRespReceived_ViaRelay    += ptr->BindRespReceived_ViaRelay;
  stats.BindRespErrReceived          += ptr->BindRespErrReceived;
  stats.BindReqReceived              += ptr->BindReqReceived;
  stats.BindReqReceived_ViaRelay     += ptr->BindReqReceived_ViaRelay;
  stats.BindRespSent                 += ptr->BindRespSent;
  stats.BindRespSent_ViaRelay        += ptr->BindRespSent_ViaRelay;
  stats.Retransmits                  += ptr->Retransmits;
  stats.Failures                     += ptr->Failures;

  for (int i = 0; i < MAX_STUN_TRANSACTIONS; i++)
  {
    ptr = &clientData->data[i].stats;

    stats.InProgress                   += ptr->InProgress;
    stats.BindReqSent                  += ptr->BindReqSent;
    stats.BindReqSent_ViaRelay         += ptr->BindReqSent_ViaRelay;
    stats.BindRespReceived             += ptr->BindRespReceived;
    stats.BindRespReceived_AfterCancel += ptr->BindRespReceived_AfterCancel;
    stats.BindRespReceived_InIdle      += ptr->BindRespReceived_InIdle;
    stats.BindRespReceived_ViaRelay    += ptr->BindRespReceived_ViaRelay;
    stats.BindRespErrReceived          += ptr->BindRespErrReceived;
    stats.BindReqReceived              += ptr->BindReqReceived;
    stats.BindReqReceived_ViaRelay     += ptr->BindReqReceived_ViaRelay;
    stats.BindRespSent                 += ptr->BindRespSent;
    stats.BindRespSent_ViaRelay        += ptr->BindRespSent_ViaRelay;
    stats.Retransmits                  += ptr->Retransmits;
    stats.Failures                     += ptr->Failures;

    if (ptr->BindReqSent > 0)
    {
      usedCnt++;
    }
  }

  StunPrint(userData, logPtr, StunInfoCategory_Info,
            "<STUNCLIENTS used:%02d> Stats:"
            "\n\t InProgress %d,"
            "\n\t BindReqSent %d,"
            "\n\t BindRespReceived %d,"
            "\n\t BindRespErrReceived %d,"
            "\n\t BindReqReceived %d,"
            "\n\t BindRespSent %d,"
            "\n\t Retransmits %d,"
            "\n\t Failures %d",
            usedCnt,
            stats.InProgress,
            stats.BindReqSent,
            stats.BindRespReceived,
            stats.BindRespErrReceived,
            stats.BindReqReceived,
            stats.BindRespSent,
            stats.Retransmits,
            stats.Failures);
}

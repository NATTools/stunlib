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
    stunReqMsg->hasTTL  = true;
    stunReqMsg->ttl.ttl = trans->stunBindReq.ttl;
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

  if (trans->stunBindReq.addTransCnt)
  {
    stunReqMsg->hasTransCount       = true;
    stunReqMsg->transCount.reserved = (uint16_t)0;
    stunReqMsg->transCount.reqCnt   = (uint8_t)trans->retransmits + 1;
    stunReqMsg->transCount.respCnt  = (uint8_t)0;
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
  /*TODO: Let app overide this */
  m.addTransCnt = true;

  /* callback and data (owned by caller) */
  m.stunCbFunc = stunCbFunc;
  StunClientMain(clientData, STUNCLIENT_CTX_UNKNOWN, STUN_SIGNAL_BindReq,
                 (uint8_t*)&m);

  return 0;
}

void
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
  m.stunCbFunc  = stunCbFunc;
  m.stuntrace   = true;
  m.addTransCnt = false;


  StoreStunBindReq(&trans, &m);
  BuildStunBindReq(&trans, &stunMsg);
  StunClientMain(clientData, STUNCLIENT_CTX_UNKNOWN, STUN_SIGNAL_BindReq,
                 (uint8_t*)&m);
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
  uint8_t           stunReqMsgBuf[STUN_MAX_PACKET_SIZE]; /* encoded STUN request
                                                          *   */
  int stunReqMsgBufLen;                                /* of encoded STUN
                                                        * request */

  /* encode the BindReq */
  if (strlen(trans->stunBindReq.password) > 0)
  {
    stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                             (unsigned char*) (stunReqMsgBuf),
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
    stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                             (unsigned char*) (stunReqMsgBuf),
                                             STUN_MAX_PACKET_SIZE,
                                             NULL,
                                             /* key */
                                             0,
                                             /* keyLen  */
                                             NULL);

  }

  if (!stunReqMsgBufLen)
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
                                stunReqMsgBuf,
                                stunReqMsgBufLen,
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
                  StunMessage*             stunReqMsg,
                  struct sockaddr_storage* destAddr)
{

  /* We need to recalculate Integrity Attribute due to the change in reqCnt*/
  /* encode the BindReq */
  uint8_t stunReqMsgBuf[STUN_MAX_PACKET_SIZE];         /* encoded STUN request
                                                        *   */
  int stunReqMsgBufLen;                                /* of encoded STUN
                                                        * request */

  if (strlen(trans->stunBindReq.password) > 0)
  {
    stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                             (unsigned char*) (stunReqMsgBuf),
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
    stunReqMsgBufLen = stunlib_encodeMessage(stunReqMsg,
                                             (unsigned char*) (stunReqMsgBuf),
                                             STUN_MAX_PACKET_SIZE,
                                             NULL,
                                             /* key */
                                             0,
                                             /* keyLen  */
                                             NULL);

  }

  gettimeofday(&trans->start[trans->retransmits + 1], NULL);
  trans->stunBindReq.sendFunc(trans->client->userCtx,
                              trans->stunBindReq.sockhandle,
                              stunReqMsgBuf,
                              stunReqMsgBufLen,
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

static int
getRTTvalue(STUN_TRANSACTION_DATA* trans)
{
  int32_t start, stop = 0;


  if ( trans->reqTransCnt > 0 && trans->reqTransCnt < STUNCLIENT_MAX_RETRANSMITS )
  {
    stop = (trans->stop[trans->reqTransCnt].tv_sec * 1000000 +
            trans->stop[trans->reqTransCnt].tv_usec);
    /* Always use the first stored value for start. */
    start = (trans->start[trans->reqTransCnt].tv_sec * 1000000 +
             trans->start[trans->reqTransCnt].tv_usec);
  }
  else
  {
    stop = (trans->stop[trans->retransmits].tv_sec * 1000000 +
            trans->stop[trans->retransmits].tv_usec);
    /* Always use the first stored value for start. */
    start = (trans->start[0].tv_sec * 1000000 +
             trans->start[0].tv_usec);

  }
  return stop - start;


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
  res.rtt         = getRTTvalue(trans);
  res.retransmits = trans->retransmits;

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
              trans->inst, errStr, trans->retransmits, peer);
    StunMessage stunReqMsg;
    BuildStunBindReq(trans, &stunReqMsg);
    RetransmitLastReq(trans, &stunReqMsg, &trans->stunBindReq.serverAddr);
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
  uint32_t          max;

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
  }
  else
  {
    StunPrint(client->logUserData, client->Log_cb, StunInfoCategory_Error,
              "<STUNCLIENT:%02d> Missing XorMappedAddress BindResp",
              trans->inst);
    return false;
  }

  if (resp->hasTransCount)
  {
    trans->reqTransCnt  = resp->transCount.reqCnt;
    trans->respTransCnt = resp->transCount.respCnt;
  }
  return true;
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

  res.respTransCnt = trans->respTransCnt;
  res.reqTransCnt  = trans->reqTransCnt;

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
  res.ttl        = trans->stunBindReq.ttl;

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
    trans->stunBindReq.ttl = pMsgIn->ttl;
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
    trans->ICMPtype        = pMsgIn->ICMPtype;
    trans->stunBindReq.ttl = pMsgIn->ttl;
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
    trans->stunBindReq.ttl = pMsgIn->ttl;
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

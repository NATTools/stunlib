/*
 *  See license file
 */


/********************************************************************************
 *
 * Description   :
 * Turn client implemented as an OS independent state machine.
 *
 * Entrypoints:
 *   1. Appl. calls TurnClient_startAllocateTransaction() to initiate the turn
 *      protocol sequence.
 *   2. Appl. calls TurnClient_HandleTick() every N msec such that it can carry
 *      out timing/retransmissions.
 *   3. Appl. calls TurnClient_HandleIncResp() when it detects incoming turn
 *      responses in the media RTP/RTCP stream.
 *   3. Appl. calls TurnClient_StartCreatePermissionReq() so that  stun probes
 *      can go thru the TURN server
 *   4. Appl. optionally calls TurnClient_StartChannelBindReq() to optimise
 *      relay traffic
 *   6. Application calls TurnClient_Deallocate() to release the allocation
 *
 * Outputs:
 *      1. Application provides function pointer and  data ptr to receive the
 * result of the  turn protocol.
 *
 *
 *
 *
 *           ------------
 *   ------>|    IDLE    |<----------------------------
 *           ------------                             |
 *                |                                   |
 *                |                                   |
 *                |                                   |
 *   (Error)  ----------                              |
 *           |   WAIT   |<--                          |
 *  |--------|   ALLOC  |   | (T (Retries))           |
 *  |        |   RESP   |   |                         |
 *  |        |  NOT_AUT |---                          |
 *  |         ----------                              |
 *  |             |                                   |
 *  |             | (Auth_Failure (401))              |
 *  |             |                                   |
 *  |        -----------                              |
 *  |        |   WAIT   |<--                          |
 *  |(Error) |   ALLOC  |   | (T (Retries))           |
 *   --------|   RESP   |---                          |
 *            ----------                              |
 *                |                                   |
 *                | (Allocate_Response)               |
 *                |                                   |
 *        |-------------                           -----------
 *        |             |                         | WAIT      |
 *        |  ALLOCATED  |------------------------>| RELEASE   |
 *        |             |                         | RESP      |
 *        | -------------                           -----------
 *                ^
 *                |
 *                |-------------------------
 *                |            |           |
 *                |            |           |
 *                v            v           v
 *         |------------   ----------   -----------
 *         |    WAIT   |  | WAIT     | | WAIT      |
 *         |PERMISSION |  | CHANBIND | | REFRESH   |
 *         |    RESP   |  | RESP     | | RESP      |
 *         |------------   ----------   -----------
 *
 ******************************************************************************/


#include <stdio.h>
#include <stdliB.h>
#include <stdarg.h>
#include <string.h>



#include "turnclient.h"
#include "turn_intern.h"
#include "sockaddr_util.h"


#define TURN_MAX_ERR_STRLEN    256  /* max size of string in TURN_INFO_FUNC */
#define TURN_TRANSID_BUFFER_SIZE 36


static const uint32_t stunTimeoutList[STUNCLIENT_MAX_RETRANSMITS] =
{ STUNCLIENT_RETRANSMIT_TIMEOUT_LIST};

/* forward declarations */
static void
CallBack(TURN_INSTANCE_DATA* pInst,
         TurnResult_T        turnResult);
static void
TurnClientFsm(TURN_INSTANCE_DATA* pInst,
              TURN_SIGNAL         sig,
              uint8_t*            payload,
              uint8_t*            origMsgBuf);

static void
SetNextState(TURN_INSTANCE_DATA* pInst,
             TURN_STATE          NextState);
static void
TurnPrint(TURN_INSTANCE_DATA* pInst,
          TurnInfoCategory_T  category,
          const char*         fmt,
          ...);
static bool
TimerHasExpired(TURN_INSTANCE_DATA* pInst,
                TURN_SIGNAL         sig);
static void
StartFirstRetransmitTimer(TURN_INSTANCE_DATA* pInst);


/* forward declarations of state functions */
static void
TurnState_Idle(TURN_INSTANCE_DATA* pInst,
               TURN_SIGNAL         sig,
               uint8_t*            payload,
               uint8_t*            origMsgBuf);

static void
TurnState_WaitAllocRespNotAut(TURN_INSTANCE_DATA* pInst,
                              TURN_SIGNAL         sig,
                              uint8_t*            payload,
                              uint8_t*            origMsgBuf);

static void
TurnState_WaitAllocResp(TURN_INSTANCE_DATA* pInst,
                        TURN_SIGNAL         sig,
                        uint8_t*            payload,
                        uint8_t*            origMsgBuf);

static void
TurnState_Allocated(TURN_INSTANCE_DATA* pInst,
                    TURN_SIGNAL         sig,
                    uint8_t*            payload,
                    uint8_t*            origMsgBuf);

static void
TurnState_WaitChanBindResp(TURN_INSTANCE_DATA* pInst,
                           TURN_SIGNAL         sig,
                           uint8_t*            payload,
                           uint8_t*            origMsgBuf);

static void
TurnState_WaitCreatePermResp(TURN_INSTANCE_DATA* pInst,
                             TURN_SIGNAL         sig,
                             uint8_t*            payload,
                             uint8_t*            origMsgBuf);

static void
TurnState_WaitAllocRefreshResp(TURN_INSTANCE_DATA* pInst,
                               TURN_SIGNAL         sig,
                               uint8_t*            payload,
                               uint8_t*            origMsgBuf);

static void
TurnState_WaitReleaseResp(TURN_INSTANCE_DATA* pInst,
                          TURN_SIGNAL         sig,
                          uint8_t*            payload,
                          uint8_t*            origMsgBuf);


/*************************************************************************/
/************************ UTILS*******************************************/
/*************************************************************************/

/*
 * Called when an internal TURNCLIENT wants to output managemnt info.
 * Prints the string to a buffer.
 * If the application has defined a callback function to handle the output
 * then this is called with the string and the severity.
 */
static void
TurnPrint(TURN_INSTANCE_DATA* pInst,
          TurnInfoCategory_T  category,
          const char*         fmt,
          ...)
{
  char s[TURN_MAX_ERR_STRLEN];

  va_list ap;
  va_start(ap,fmt);

  /* print string to buffer  */
  vsprintf(s, fmt, ap);

  if (true)
  {
    return;         /* TODO: fix logging */

  }
  if (pInst->infoFunc)
  {
    /* Call the application defined "error callback function" */
    pInst->infoFunc(pInst->userData, category, s);
  }

  va_end(ap);

}

static void
TurnTransactionIdString(char*    dst,
                        uint32_t buffersize,
                        uint8_t* src)
{
  if (buffersize >= TURN_TRANSID_BUFFER_SIZE)     /* (2 * 12) + 11 + 1*/
  {
    sprintf(dst,
            "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            src[0], src[1], src[2], src[3],
            src[4], src[5], src[6], src[7],
            src[8], src[9], src[10], src[11]);
  }
}

static int
TurnRand(void)
{
  return rand();
}


static int
getAddrFamily(const TURN_INSTANCE_DATA* pInst)
{
  return pInst->turnAllocateReq.ai_family;
}


static TURN_SIGNAL
StunMsgToInternalTurnSig(TURN_INSTANCE_DATA* pInst,
                         StunMessage*        msg)
{
  switch (msg->msgHdr.msgType)
  {
  case STUN_MSG_AllocateResponseMsg:               return
      TURN_SIGNAL_AllocateResp;
  case STUN_MSG_AllocateErrorResponseMsg:          return
      TURN_SIGNAL_AllocateRespError;
  case STUN_MSG_CreatePermissionResponseMsg:       return
      TURN_SIGNAL_CreatePermissionResp;
  case STUN_MSG_CreatePermissionErrorResponseMsg:  return
      TURN_SIGNAL_CreatePermissionRespError;
  case STUN_MSG_RefreshResponseMsg:                return
      TURN_SIGNAL_RefreshResp;
  case STUN_MSG_RefreshErrorResponseMsg:           return
      TURN_SIGNAL_RefreshRespError;
  case STUN_MSG_ChannelBindResponseMsg:            return
      TURN_SIGNAL_ChannelBindResp;
  case STUN_MSG_ChannelBindErrorResponseMsg:       return
      TURN_SIGNAL_ChannelBindRespError;

  default:
    /* Some other message */
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> unknown STUN message type (0x%02x)",
              pInst->id,
              msg->msgHdr.msgType);
    return TURN_SIGNAL_Illegal;
    break;
  }
}


/* transaction id compare */
static bool
TransIdIsEqual(const StunMsgId* a,
               const StunMsgId* b)
{
  return (memcmp( a, b, sizeof(StunMsgId) ) == 0);
}

/* Store transaction id of a request  */
static void
StoreReqTransId(TURN_INSTANCE_DATA* pInst,
                StunMessage*        stunReqMsg)
{
  memcpy( &pInst->StunReqTransId, &stunReqMsg->msgHdr.id,
          sizeof(pInst->StunReqTransId) );
}

/* Store transaction id of  resp  */
static void
StorePrevRespTransId(TURN_INSTANCE_DATA* pInst,
                     StunMessage*        stunRespMsg)
{
  memcpy( &pInst->PrevRespTransId, &stunRespMsg->msgHdr.id,
          sizeof(pInst->PrevRespTransId) );
}



/*************************************************************************/
/************************ API ********************************************/
/*************************************************************************/


static unsigned long id_counter = 0;


bool
TurnClient_StartAllocateTransaction(TURN_INSTANCE_DATA**   instp,
                                    uint32_t               tickMsec,
                                    TURN_INFO_FUNC         infoFunc,
                                    const char*            SwVerStr,
                                    void*                  userCtx,
                                    const struct sockaddr* serverAddr,
                                    const char*            userName,
                                    const char*            password,
                                    int                    ai_family,
                                    TURN_SEND_FUNC         sendFunc,
                                    TURN_CB_FUNC           turnCbFunc,
                                    bool                   evenPortAndReserve,
                                    uint64_t               reservationToken)
{
  TURN_INSTANCE_DATA*  pInst;
  TurnAllocateReqStuct m;

  if (!instp)
  {
    return false;
  }

  pInst = malloc(sizeof *pInst);
  if (!pInst)
  {
    return false;
  }

  memset(pInst, 0, sizeof *pInst);

  *instp = pInst;

  pInst->id = ++id_counter;

  if (SwVerStr)
  {
    strncpy(pInst->softwareVersionStr, SwVerStr,
            sizeof(pInst->softwareVersionStr) - 1);
  }

  pInst->infoFunc     = infoFunc;
  pInst->userData     = userCtx;
  pInst->timerResMsec = tickMsec;

  pInst->state = TURN_STATE_Idle;
  pInst->inUse = true;

  TurnPrint(pInst,
            TurnInfoCategory_Trace,
            "<TURNCLIENT:%d> Create Turn instance",
            pInst->id);

  /* as default always send stun KeepAlives */

  pInst->doStunKeepAlive = true;

  memset( &m, 0, sizeof(m) );

  sockaddr_copy( (struct sockaddr*)&m.serverAddr, serverAddr );
  strncpy(m.username, userName, sizeof(m.username) - 1);
  strncpy(m.password, password, sizeof(m.password) - 1);
  m.ai_family          = ai_family;
  m.sendFunc           = sendFunc;
  m.userCtx            = userCtx;
  m.evenPortAndReserve = evenPortAndReserve;
  m.reservationToken   = reservationToken;

  /* callback and  data (owned by caller) */
  m.turnCbFunc = turnCbFunc;

  TurnClientFsm(pInst, TURN_SIGNAL_AllocateReq, (uint8_t*)&m, NULL);

  return true;
}


/* range 0x4000 - 0xFFFF, with channel number 0xFFFF reserved */
static __inline bool
IsValidBindChannelNumber(uint16_t chanNum)
{
  return (chanNum >= 0x4000 && chanNum != 0xFFFF);
}


static bool
ChannelBindReqParamsOk(TURN_INSTANCE_DATA*    pInst,
                       uint16_t               channelNumber,
                       const struct sockaddr* peerTrnspAddr)

{
  if ( !IsValidBindChannelNumber(channelNumber) )  /* channel number ignored if
                                                    * creating a permission */
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> ChannelBindReq - illegal channel number %0X ",
              pInst->id,
              channelNumber);
    return false;
  }

  if ( !sockaddr_isSet(peerTrnspAddr) )
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> ChannelBindReq - illegal peerTRansport Address ",
              pInst->id);
    return false;
  }

  return true;
}

static bool
CreatePermReqParamsOk(TURN_INSTANCE_DATA*    pInst,
                      uint32_t               numberOfPeers,
                      const struct sockaddr* peerTrnspAddr[])

{
  uint32_t i;
  bool     ret = true;

  for (i = 0; i < numberOfPeers; i++)
  {
    if ( !sockaddr_isSet(peerTrnspAddr[i]) )
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> CreatePerm - illegal peerTRansport Address ",
                pInst->id);
      ret = false;
    }
  }
  return ret;
}


bool
TurnClient_StartChannelBindReq(TURN_INSTANCE_DATA*    pInst,
                               uint16_t               channelNumber,
                               const struct sockaddr* peerTrnspAddr)
{


  if ( (pInst->channelBindInfo.channelNumber > 0) &&
       sockaddr_isSet( (struct sockaddr*)&pInst->channelBindInfo.peerTrnspAddr )
       &&
       peerTrnspAddr &&
       ( sockaddr_sameAddr( (struct sockaddr*)&pInst->channelBindInfo.
                            peerTrnspAddr,
                            (struct sockaddr*)peerTrnspAddr ) ) )
  {
    TurnPrint(pInst,
              TurnInfoCategory_Trace,
              "<TURNCLIENT:%lu>  ChannelBindReq ignored, same peer as before",
              pInst->id);
    return false;
  }

  if ( ChannelBindReqParamsOk(pInst, channelNumber, peerTrnspAddr) )
  {
    TurnChannelBindInfo_T msg;
    memset( &msg, 0, sizeof(msg) );

    msg.channelNumber = channelNumber;
    sockaddr_copy( (struct sockaddr*)&msg.peerTrnspAddr,
                   peerTrnspAddr );
    TurnClientFsm(pInst, TURN_SIGNAL_ChannelBindReq, (uint8_t*)&msg, NULL);
    return true;
  }
  return false;
}

bool
TurnClient_hasBeenRedirected(TURN_INSTANCE_DATA* pInst)
{
  if (pInst)
  {
    return pInst->redirected;
  }

  return false;
}

const struct sockaddr*
TurnClient_getRedirectedServerAddr(TURN_INSTANCE_DATA* pInst)
{
  if (pInst && pInst->redirected)
  {
    return (const struct sockaddr*) &pInst->turnAllocateReq.serverAddr;
  }

  return NULL;
}

bool
TurnClient_StartCreatePermissionReq(TURN_INSTANCE_DATA*    pInst,
                                    uint32_t               noOfPeers,
                                    const struct sockaddr* peerTrnspAddr[])
{
  if ( CreatePermReqParamsOk(pInst, noOfPeers, peerTrnspAddr) )
  {
    uint32_t                   i;
    TurnCreatePermissionInfo_T msg;
    memset( &msg, 0, sizeof(msg) );

    for (i = 0; i < noOfPeers; i++)
    {
      sockaddr_copy( (struct sockaddr*)&msg.peerTrnspAddr[i],
                     peerTrnspAddr[i] );
      msg.numberOfPeers++;
    }

    TurnClientFsm(pInst, TURN_SIGNAL_CreatePermissionReq, (uint8_t*)&msg, NULL);
    return true;
  }
  return false;
}


void
TurnClient_HandleTick(TURN_INSTANCE_DATA* pInst)
{
  if ( TimerHasExpired(pInst, TURN_SIGNAL_TimerRetransmit) )
  {
    TurnClientFsm(pInst, TURN_SIGNAL_TimerRetransmit, NULL, NULL);
  }
  if ( TimerHasExpired(pInst, TURN_SIGNAL_TimerRefreshAlloc) )
  {
    TurnClientFsm(pInst, TURN_SIGNAL_TimerRefreshAlloc, NULL, NULL);
  }
  if ( TimerHasExpired(pInst, TURN_SIGNAL_TimerRefreshChannel) )
  {
    TurnClientFsm(pInst, TURN_SIGNAL_TimerRefreshChannel, NULL, NULL);
  }
  if ( TimerHasExpired(pInst, TURN_SIGNAL_TimerRefreshPermission) )
  {
    TurnClientFsm(pInst, TURN_SIGNAL_TimerRefreshPermission, NULL, NULL);
  }
  if ( TimerHasExpired(pInst, TURN_SIGNAL_TimerStunKeepAlive) )
  {
    TurnClientFsm(pInst, TURN_SIGNAL_TimerStunKeepAlive, NULL, NULL);
  }
}


bool
TurnClient_HandleIncResp(TURN_INSTANCE_DATA* pInst,
                         StunMessage*        msg,
                         uint8_t*            buf)
{
  if ( TransIdIsEqual(&msg->msgHdr.id, &pInst->PrevRespTransId) )
  {
    /* silent discard duplicate msg */
    char tmp[TURN_TRANSID_BUFFER_SIZE];
    TurnTransactionIdString(tmp,
                            TURN_TRANSID_BUFFER_SIZE,
                            &msg->msgHdr.id.octet[0]);
    TurnPrint( pInst,
               TurnInfoCategory_Trace,
               "<TURNCLIENT:%d> %s %s silent discard duplicate",
               pInst->id,
               tmp,
               stunlib_getMessageName(msg->msgHdr.msgType) );
    return true;
  }

  /* context known, just check transId matches last sent request on this
   * instance */
  if ( TransIdIsEqual(&msg->msgHdr.id, &pInst->StunReqTransId) )
  {
    char tmp[TURN_TRANSID_BUFFER_SIZE];
    TurnTransactionIdString(tmp,
                            TURN_TRANSID_BUFFER_SIZE,
                            &msg->msgHdr.id.octet[0]);
    TurnPrint( pInst,
               TurnInfoCategory_Trace,
               "<TURNCLIENT:%d> %s %s",
               pInst->id,
               tmp,
               stunlib_getMessageName(msg->msgHdr.msgType) );

    StorePrevRespTransId(pInst, msg);
    TurnClientFsm(pInst, StunMsgToInternalTurnSig(pInst,msg), (void*)msg, buf);
    return true;
  }
  else
  {
    char tmp1[TURN_TRANSID_BUFFER_SIZE];
    char tmp2[TURN_TRANSID_BUFFER_SIZE];
    TurnTransactionIdString(tmp1,
                            TURN_TRANSID_BUFFER_SIZE,
                            &msg->msgHdr.id.octet[0]);
    TurnTransactionIdString(tmp2,
                            TURN_TRANSID_BUFFER_SIZE,
                            &pInst->StunReqTransId.octet[0]);
    TurnPrint( pInst,
               TurnInfoCategory_Error,
               "<TURNCLIENT:%d> mismatched transId rec: %s, exp: %s discarding, msgType %s", pInst->id,
               tmp1,
               tmp2,
               stunlib_getMessageName(msg->msgHdr.msgType) );

    return false;
  }
}


void
TurnClient_Deallocate(TURN_INSTANCE_DATA* inst)
{
  if (!inst)
  {
    return;
  }

  TurnClientFsm(inst, TURN_SIGNAL_DeAllocate, NULL, NULL);
}


void
TurnClient_free(TURN_INSTANCE_DATA* inst)
{
  if (inst)
  {
    free(inst);
  }
}


/* managemnet/statistics */
void
TurnClientGetStats(const TURN_INSTANCE_DATA* pInst,
                   TurnStats_T*              Stats)
{
  if (pInst->state >= TURN_STATE_Allocated)
  {
          sockaddr_copy( (struct sockaddr*)&Stats->AllocResp.srflxAddr,
                   (struct sockaddr*)&pInst->srflxAddr );

          sockaddr_copy( (struct sockaddr*)&Stats->AllocResp.relAddrIPv4,
                   (struct sockaddr*)&pInst->relAddr_IPv4 );

          sockaddr_copy( (struct sockaddr*)&Stats->AllocResp.relAddrIPv6,
                   (struct sockaddr*)&pInst->relAddr_IPv6 );

    Stats->channelBound = pInst->channelBound;
    if (pInst->channelBound)
    {
      Stats->channelNumber = pInst->channelBindInfo.channelNumber;
          sockaddr_copy( (struct sockaddr*)&Stats->BoundPeerTrnspAddr,
                     (struct sockaddr*)&pInst->channelBindInfo.peerTrnspAddr );
      /* a bound channel also creates a permission, so show this  */
      Stats->permissionsInstalled = 1;
      Stats->numberOfPeers        = 1;
          sockaddr_copy( (struct sockaddr*)&Stats->PermPeerTrnspAddr[0],
                     (struct sockaddr*)&pInst->channelBindInfo.peerTrnspAddr );
    }
    else
    {
      Stats->permissionsInstalled = pInst->permissionsInstalled;
      if (Stats->permissionsInstalled)
      {
        uint32_t k;
        Stats->numberOfPeers = pInst->createPermInfo.numberOfPeers;
        for (k = 0; k <  Stats->numberOfPeers; k++)
        {
          sockaddr_copy( (struct sockaddr*)&Stats->PermPeerTrnspAddr[k],
                         (struct sockaddr*)&pInst->createPermInfo.peerTrnspAddr[
                           k] );
        }
      }
    }
    Stats->Retransmits = pInst->retransmits;
    Stats->Failures    = pInst->failures;
  }
}

/*************************************************************************/
/************************ FSM Framework **********************************/
/*************************************************************************/


/* NOTE: index is TURN_STATE */
static const TURN_STATE_TABLE StateTable[TURN_STATE_End] =
{
  /* function ptr */                      /* str */
  { TurnState_Idle,                       "Idle"                          },
  { TurnState_WaitAllocRespNotAut,        "WaitAllocRespNotAut"           },
  { TurnState_WaitAllocResp,              "WaitAllocResp"                 },
  { TurnState_Allocated,                  "Allocated"                     },
  { TurnState_WaitAllocRefreshResp,       "WaitAllocRefreshResp"          },
  { TurnState_WaitChanBindResp,           "WaitChanBindResp"              },
  { TurnState_WaitCreatePermResp,         "WaitCreatePermResp"            },
  { TurnState_WaitReleaseResp,            "WaitReleaseResp"               },


};

static const uint32_t NoOfStates = sizeof(StateTable) / sizeof(StateTable[0]);


static const char*
TurnsigToStr(TURN_SIGNAL sig)
{
  switch (sig)
  {
  case TURN_SIGNAL_AllocateReq:               return "AllocateReq";
  case TURN_SIGNAL_AllocateResp:              return "AllocateResp";
  case TURN_SIGNAL_AllocateRespError:         return "AllocateRespError";
  case TURN_SIGNAL_ChannelBindReq:            return "ChannelBindReq";
  case TURN_SIGNAL_ChannelBindResp:           return "ChannelBindResp";
  case TURN_SIGNAL_ChannelBindRespError:      return "ChannelBindRespError";
  case TURN_SIGNAL_CreatePermissionReq:       return "CreatePermissionReq";
  case TURN_SIGNAL_CreatePermissionResp:      return "CreatePermissionResp";
  case TURN_SIGNAL_CreatePermissionRespError: return "CreatePermissionRespError";
  case TURN_SIGNAL_RefreshResp:               return "RefreshResp";
  case TURN_SIGNAL_RefreshRespError:          return "RefreshRespError";
  case TURN_SIGNAL_TimerTick:                 return "TimerTick";
  case TURN_SIGNAL_TimerRetransmit:           return "TimerRetransmit";
  case TURN_SIGNAL_TimerRefreshAlloc:         return "TimerRefreshAlloc";
  case TURN_SIGNAL_TimerRefreshChannel:       return "TimerRefreshChannel";
  case TURN_SIGNAL_TimerRefreshPermission:    return "TimerRefreshPermission";
  case TURN_SIGNAL_TimerStunKeepAlive:        return "TimerStunKeepAlive";
  case TURN_SIGNAL_DeAllocate:                return "DeAllocate";
  default:                                    return "???";
  }
}

const char*
TurnResultToStr(TurnResult_T res)
{
  switch (res)
  {
  case TurnResult_AllocOk:                     return "TurnResult_AllocOk";
  case TurnResult_AllocFail:                   return "TurnResult_AllocFail";
  case TurnResult_AllocFailNoAnswer:           return
      "TurnResult_AllocFailNoAnswer";
  case TurnResult_AllocUnauthorised:           return
      "TurnResult_AllocUnauthorised";
  case TurnResult_CreatePermissionOk:          return
      "TurnResult_CreatePermissionOk";
  case TurnResult_CreatePermissionFail:        return
      "TurnResult_CreatePermissionFail";
  case TurnResult_CreatePermissionNoAnswer:    return
      "TurnResult_CreatePermissionNoAnswer";
  case TurnResult_CreatePermissionQuotaReached: return
      "TurnResult_CreatePermissionQuotaReached";
  case TurnResult_PermissionRefreshFail:       return
      "TurnResult_PermissionRefreshFail";
  case TurnResult_ChanBindOk:                  return "TurnResult_ChanBindOk";
  case TurnResult_ChanBindFail:                return "TurnResult_ChanBindFail";
  case TurnResult_ChanBindFailNoanswer:        return
      "TurnResult_ChanBindFailNoanswer";
  case TurnResult_RefreshFail:                 return "TurnResult_RefreshFail";
  case TurnResult_RefreshFailNoAnswer:         return
      "TurnResult_RefreshFailNoAnswer";
  case TurnResult_RelayReleaseComplete:        return
      "TurnResult_RelayReleaseComplete";
  case TurnResult_RelayReleaseFailed:          return
      "TurnResult_RelayReleaseFailed";
  case TurnResult_InternalError:               return "TurnResult_InternalError";
  case TurnResult_MalformedRespWaitAlloc:      return
      "TurnResult_MalformedRespWaitAlloc";
  default: return "unknown turnresult ??";
  }
}


/* stop specific timer signal */
static void
StopAllTimers(TURN_INSTANCE_DATA* pInst)
{
    TurnPrint(pInst,
            TurnInfoCategory_Trace,
            "<TURNCLIENT:%d> StopAllTimers",
            pInst->id);
  pInst->TimerRetransmit        = 0;
  pInst->TimerRefreshAlloc      = 0;
  pInst->TimerRefreshChannel    = 0;
  pInst->TimerRefreshPermission = 0;
  pInst->TimerStunKeepAlive     = 0;
}


static void
SetNextState(TURN_INSTANCE_DATA* pInst,
             TURN_STATE          NextState)
{
  if  (NextState >= NoOfStates)
  {
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> SetNextState, Illegal State %d",
              pInst->id,
              NextState);
    return;
  }

  if (pInst->state != NextState)
  {
    TurnPrint(pInst,
              TurnInfoCategory_Trace,
              "<TURNCLIENT:%d> State (%s -> %s)",
              pInst->id,
              StateTable[pInst->state].StateStr,
              StateTable[NextState].StateStr);
    pInst->state = NextState;
  }

  /* always free instance and stop all timers on return to idle */
  if (NextState == TURN_STATE_Idle)
  {
    StopAllTimers(pInst);
    pInst->inUse = false;
  }
}


/* check if timer has expired and return the timer signal */
static bool
TimerHasExpired(TURN_INSTANCE_DATA* pInst,
                TURN_SIGNAL         sig)
{
  int* timer;

  switch (sig)
  {
  case TURN_SIGNAL_TimerRefreshAlloc:
    timer =  &pInst->TimerRefreshAlloc;
    break;
  case TURN_SIGNAL_TimerRefreshChannel:
    timer = &pInst->TimerRefreshChannel;
    break;
  case TURN_SIGNAL_TimerRefreshPermission:
    timer = &pInst->TimerRefreshPermission;
    break;
  case TURN_SIGNAL_TimerRetransmit:
    timer = &pInst->TimerRetransmit;
    break;
  case TURN_SIGNAL_TimerStunKeepAlive:
    timer = &pInst->TimerStunKeepAlive;
    break;
  default:
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> illegal timer expiry %d ",
              pInst->id,
              sig);
    return false;
    break;
  }

  if (*timer)   /* check timer is running */
  {
    *timer -= pInst->timerResMsec;
    if (*timer <= 0)
    {
      *timer = 0;
      return true;
    }
  }
  return false;
}

/* check if timer has expired and return the timer signal */
static void
StartTimer(TURN_INSTANCE_DATA* pInst,
           TURN_SIGNAL         sig,
           uint32_t            durationMsec)
{
    TurnPrint(pInst,
            TurnInfoCategory_Trace,
            "<TURNCLIENT:%d> StartTimer(%s, %dms)",
            pInst->id,
            TurnsigToStr(sig),
            durationMsec);

  switch (sig)
  {
  case TURN_SIGNAL_TimerRetransmit:
    pInst->TimerRetransmit = durationMsec;
    break;
  case TURN_SIGNAL_TimerRefreshAlloc:
    pInst->TimerRefreshAlloc = durationMsec;
    break;
  case TURN_SIGNAL_TimerRefreshChannel:
    pInst->TimerRefreshChannel = durationMsec;
    break;
  case TURN_SIGNAL_TimerRefreshPermission:
    pInst->TimerRefreshPermission = durationMsec;
    break;
  case TURN_SIGNAL_TimerStunKeepAlive:
    pInst->TimerStunKeepAlive = durationMsec;
    break;
  default:
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> illegal StartTimer %d, duration %d",
              pInst->id,
              sig,
              durationMsec);
    break;
  }
}

/* stop specific timer signal */
static void
StopTimer(TURN_INSTANCE_DATA* pInst,
          TURN_SIGNAL         sig)
{
    TurnPrint( pInst, TurnInfoCategory_Trace, "<TURNCLIENT:%d> StopTimer(%s)",
             pInst->id, TurnsigToStr(sig) );

  switch (sig)
  {
  case TURN_SIGNAL_TimerRetransmit:
    pInst->TimerRetransmit = 0;
    break;
  case TURN_SIGNAL_TimerRefreshAlloc:
    pInst->TimerRefreshAlloc = 0;
    break;
  case TURN_SIGNAL_TimerRefreshChannel:
    pInst->TimerRefreshChannel = 0;
    break;
  case TURN_SIGNAL_TimerRefreshPermission:
    pInst->TimerRefreshPermission = 0;
    break;
  case TURN_SIGNAL_TimerStunKeepAlive:
    pInst->TimerStunKeepAlive = 0;
    break;
  default:
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> illegal StopTimer %d",
              pInst->id,
              sig);
    break;
  }
}




void
TurnClientSimulateSig(void*       instance,
                      TURN_SIGNAL sig)
{
  TURN_INSTANCE_DATA* pInst = (TURN_INSTANCE_DATA*)instance;
  TurnClientFsm(pInst, sig, NULL, NULL);
}

/*************************************************************************/
/************************ FSM functions  *********************************/
/*************************************************************************/


static void
StoreAllocateReq(TURN_INSTANCE_DATA*   pInst,
                 TurnAllocateReqStuct* pMsgIn)
{
  /* copy whole msg */
    memcpy( &pInst->turnAllocateReq, pMsgIn,
          sizeof(TurnAllocateReqStuct) );

  /* copy crendentials to seperate area */
    memcpy( pInst->userCredentials.stunUserName, pMsgIn->username,
          sizeof(pInst->userCredentials.stunUserName) );
    memcpy( pInst->userCredentials.stunPassword, pMsgIn->password,
          sizeof(pInst->userCredentials.stunPassword) );
}

static void
StoreChannelBindReq(TURN_INSTANCE_DATA*    pInst,
                    TurnChannelBindInfo_T* pMsgIn)
{
    memcpy( &pInst->channelBindInfo, pMsgIn, sizeof(pInst->channelBindInfo) );
}

static bool
PendingChannelBindReq(TURN_INSTANCE_DATA* pInst)
{
  return pInst->pendingChannelBind;
}

static void
StoreCreatePermReq(TURN_INSTANCE_DATA*         pInst,
                   TurnCreatePermissionInfo_T* pMsgIn)
{
    memcpy( &pInst->createPermInfo, pMsgIn, sizeof(pInst->createPermInfo) );
}

static bool
StoreRealm(TURN_INSTANCE_DATA* pInst,
           StunMessage*        pResp)
{
  if (pResp->hasRealm)
  {
    memcpy(pInst->userCredentials.realm,
           pResp->realm.value,
           pResp->realm.sizeValue);
    return true;
  }
  else
  {
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> No REALM in message!",
              pInst->id);
    return false;
  }
}

static bool
StoreNonce(TURN_INSTANCE_DATA* pInst,
           StunMessage*        pResp)
{
  if (pResp->hasNonce)
  {
    memcpy(pInst->userCredentials.nonce,
           pResp->nonce.value,
           pResp->nonce.sizeValue);
    return true;
  }
  else
  {
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> No NONCE in message!",
              pInst->id);
    return false;
  }
}

static bool
StoreRealmAndNonce(TURN_INSTANCE_DATA* pInst,
                   StunMessage*        pResp)
{
  return StoreRealm(pInst, pResp) && StoreNonce(pInst, pResp);
}


static bool
StoreServerReflexiveAddress(TURN_INSTANCE_DATA* pInst,
                            StunMessage*        stunRespMsg)
{
  struct sockaddr_storage addr;

  memset(&addr, 0, sizeof addr);

  if (stunRespMsg->hasXorMappedAddress)
  {

    if (stunRespMsg->xorMappedAddress.familyType == STUN_ADDR_IPv4Family)
    {
      sockaddr_initFromIPv4Int( (struct sockaddr_in*)&addr,
                                htonl(
                                  stunRespMsg->xorMappedAddress.addr.v4.addr),
                                htons(
                                  stunRespMsg->xorMappedAddress.addr.v4.port) );
    }
    else if (stunRespMsg->xorMappedAddress.familyType == STUN_ADDR_IPv6Family)
    {
      sockaddr_initFromIPv6Int( (struct sockaddr_in6*)&addr,
                                stunRespMsg->xorMappedAddress.addr.v6.addr,
                                htons(
                                  stunRespMsg->xorMappedAddress.addr.v6.port) );
    }

    sockaddr_copy( (struct sockaddr*)&pInst->srflxAddr,
                   (struct sockaddr*)&addr );

    return true;
  }
  else
  {
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> Missing XorMappedAddress AllocResp",
              pInst->id);
    return false;
  }
}


static bool
StoreToken (TURN_INSTANCE_DATA* pInst,
            StunMessage*        stunRespMsg)
{
  if (stunRespMsg->hasReservationToken)
  {
    pInst->token = stunRespMsg->reservationToken.value;
  }
  else
  {
    pInst->token = 0;
  }

  return true;
}

static bool
StoreRelayAddressStd(TURN_INSTANCE_DATA* pInst,
                     StunMessage*        stunRespMsg)
{
  int                     requested_ai_family;
  struct sockaddr_storage addr_v4;
  struct sockaddr_storage addr_v6;
  memset(&addr_v4, 0, sizeof addr_v4);
  memset(&addr_v6, 0, sizeof addr_v6);


  requested_ai_family = getAddrFamily(pInst);

  if (stunRespMsg->hasXorRelayAddressSSODA)
  {
    if (stunRespMsg->xorRelayAddressIPv4.familyType == STUN_ADDR_IPv4Family)
    {
      sockaddr_initFromIPv4Int( (struct sockaddr_in*)&addr_v4,
                                htonl(stunRespMsg->xorRelayAddressIPv4.addr.v4.
                                      addr),
                                htons(stunRespMsg->xorRelayAddressIPv4.addr.v4.
                                      port) );
    }

    if (stunRespMsg->xorRelayAddressIPv6.familyType == STUN_ADDR_IPv6Family)
    {
      sockaddr_initFromIPv6Int( (struct sockaddr_in6*)&addr_v6,
                                stunRespMsg->xorRelayAddressIPv6.addr.v6.addr,
                                htons(stunRespMsg->xorRelayAddressIPv6.addr.v6.
                                      port) );
    }

    sockaddr_copy( (struct sockaddr*)&pInst->relAddr_IPv4,
                   (struct sockaddr*)&addr_v4 );

    sockaddr_copy( (struct sockaddr*)&pInst->relAddr_IPv6,
                   (struct sockaddr*)&addr_v6 );

    return true;
  }
  else if (stunRespMsg->hasXorRelayAddressIPv4)
  {
    if (stunRespMsg->xorRelayAddressIPv4.familyType == STUN_ADDR_IPv4Family)
    {
      sockaddr_initFromIPv4Int( (struct sockaddr_in*)&addr_v4,
                                htonl(stunRespMsg->xorRelayAddressIPv4.addr.v4.
                                      addr),
                                htons(stunRespMsg->xorRelayAddressIPv4.addr.v4.
                                      port) );


      sockaddr_copy( (struct sockaddr*)&pInst->relAddr_IPv4,
                     (struct sockaddr*)&addr_v4 );
      return true;
    }
    else
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> Alocated relay has incorrect address family %s (%d:%d)",
                pInst->id,
                requested_ai_family == AF_INET ? "Requested: IPv4, Received IPv6" : "Requested: IPv6, Received IPv4",
                requested_ai_family,
                stunRespMsg->xorRelayAddressIPv4.familyType);
      return false;
    }

  }
  else if (stunRespMsg->hasXorRelayAddressIPv6)
  {
    if (stunRespMsg->xorRelayAddressIPv6.familyType == STUN_ADDR_IPv6Family)
    {

      sockaddr_initFromIPv6Int( (struct sockaddr_in6*)&addr_v6,
                                stunRespMsg->xorRelayAddressIPv6.addr.v6.addr,
                                htons(stunRespMsg->xorRelayAddressIPv6.addr.v6.
                                      port) );

      sockaddr_copy( (struct sockaddr*)&pInst->relAddr_IPv6,
                     (struct sockaddr*)&addr_v6 );

      return true;
    }
    else
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> Alocated relay has incorrect address family %s (%d:%d)",
                pInst->id,
                requested_ai_family == AF_INET ? "Requested: IPv4, Received IPv6" : "Requested: IPv6, Received IPv4",
                requested_ai_family,
                stunRespMsg->xorRelayAddressIPv6.familyType);
      return false;
    }

  }
  else
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> Missing Xor RelayAddress AllocResp",
              pInst->id);
    return false;
  }
}


static bool
StoreRelayAddress(TURN_INSTANCE_DATA* pInst,
                  StunMessage*        stunRespMsg)
{
  return StoreRelayAddressStd(pInst, stunRespMsg);
}


static bool
StoreLifetime(TURN_INSTANCE_DATA* pInst,
              StunMessage*        stunRespMsg)
{
  if (stunRespMsg->hasLifetime)
  {
    pInst->lifetime = stunRespMsg->lifetime.value;
    return true;
  }
  else
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> Missing Lifetime in AllocResp",
              pInst->id);
    return false;
  }
}


static uint32_t
GetErrCode(StunMessage* pResp)
{
  if (pResp->hasErrorCode)
  {
    return pResp->errorCode.errorClass * 100 + pResp->errorCode.number;
  }
  else
  {
    return 0xffffffff;
  }
}


/*
 * The initial allocate request has no authentication info.
 * TURN server will usually reply with  Error(401-notAuth, Realm, Nonce)
 */
static void
BuildInitialAllocateReq(TURN_INSTANCE_DATA* pInst,
                        StunMessage*        pReq)
{
  unsigned long rndval = TurnRand();

  memset( pReq, 0, sizeof(StunMessage) );
  pReq->msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
  stunlib_createId(&pReq->msgHdr.id, rndval, 0);

  stunlib_addSoftware(pReq, pInst->softwareVersionStr, STUN_DFLT_PAD);
  stunlib_addRequestedTransport(pReq, STUN_REQ_TRANSPORT_UDP);

  if (pInst->turnAllocateReq.evenPortAndReserve)
  {
    pReq->hasEvenPort       = true;
    pReq->evenPort.evenPort = 0x80;  /* Set the R bit to reserve the next
                                      * port;*/
  }
  else if (pInst->turnAllocateReq.reservationToken > 0)
  {
    pReq->hasReservationToken    = true;
    pReq->reservationToken.value = pInst->turnAllocateReq.reservationToken;
  }

  if ( !pReq->hasReservationToken && (getAddrFamily(pInst) != AF_UNSPEC) )
  {
    if ( !stunlib_addRequestedAddrFamily( pReq, getAddrFamily(pInst) ) )
    {
      TurnPrint( pInst,
                 TurnInfoCategory_Error,
                 "<TURNCLIENT:%d> Requested Address Family  %i not supported in AllocateReq",
                 pInst->id,
                 getAddrFamily(pInst) );
    }
  }
}


/*
 * Initial request has been sent. TURN server has replies with
 * Error(401=NotAuth, Realm, Nonce).
 * Rebuild the AllocateReq as above but add Realm,Nonce,UserName. Calculate
 * MD5Key and add it.
 */
static void
BuildNewAllocateReq(TURN_INSTANCE_DATA* pInst,
                    StunMessage*        pReq)
{
  unsigned long rndval = TurnRand();

  memset( pReq, 0, sizeof(StunMessage) );
  pReq->msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
  stunlib_createId(&pReq->msgHdr.id, rndval, 1);
  stunlib_addRealm(pReq, pInst->userCredentials.realm, STUN_DFLT_PAD);
  stunlib_addUserName(pReq, pInst->userCredentials.stunUserName, STUN_DFLT_PAD);
  stunlib_addNonce(pReq, pInst->userCredentials.nonce, STUN_DFLT_PAD);

  stunlib_addRequestedTransport(pReq, STUN_REQ_TRANSPORT_UDP);
  stunlib_addSoftware(pReq, pInst->softwareVersionStr, STUN_DFLT_PAD);

  if (pInst->turnAllocateReq.evenPortAndReserve)
  {
    pReq->hasEvenPort       = true;
    pReq->evenPort.evenPort = 0x80;  /* Set the R bit to reserve the next
                                      * port;*/
  }
  else if (pInst->turnAllocateReq.reservationToken > 0)
  {
    pReq->hasReservationToken    = true;
    pReq->reservationToken.value = pInst->turnAllocateReq.reservationToken;
  }

  if ( !pReq->hasReservationToken && (getAddrFamily(pInst) != AF_UNSPEC) )
  {
    if ( !stunlib_addRequestedAddrFamily( pReq, getAddrFamily(pInst) ) )
    {
      TurnPrint( pInst,
                 TurnInfoCategory_Error,
                 "<TURNCLIENT:%d> Requested Address Family  %i not supported in AllocateReq",
                 pInst->id,
                 getAddrFamily(pInst) );
    }
  }

  stunlib_createMD5Key(pInst->userCredentials.key,
                       pInst->userCredentials.stunUserName,
                       pInst->userCredentials.realm,
                       pInst->userCredentials.stunPassword);
}

static void
BuildRefreshAllocateReq(TURN_INSTANCE_DATA* pInst,
                        StunMessage*        pReq,
                        uint32_t            lifetimeSec)
{
  unsigned long rndval = TurnRand();

  memset( pReq, 0, sizeof(StunMessage) );
  stunlib_createId(&pReq->msgHdr.id, rndval, 1);
  pReq->hasLifetime    = true;
  pReq->lifetime.value = lifetimeSec;

  stunlib_addRealm(pReq, pInst->userCredentials.realm, STUN_DFLT_PAD);
  stunlib_addUserName(pReq, pInst->userCredentials.stunUserName, STUN_DFLT_PAD);
  stunlib_addNonce(pReq, pInst->userCredentials.nonce, STUN_DFLT_PAD);

  pReq->msgHdr.msgType = STUN_MSG_RefreshRequestMsg;
  stunlib_addSoftware(pReq, pInst->softwareVersionStr, STUN_DFLT_PAD);

  stunlib_createMD5Key(pInst->userCredentials.key,
                       pInst->userCredentials.stunUserName,
                       pInst->userCredentials.realm,
                       pInst->userCredentials.stunPassword);
}



static void
BuildChannelBindReq(TURN_INSTANCE_DATA* pInst,
                    StunMessage*        pReq)
{
  StunIPAddress    peerTrnspAddr;
  struct sockaddr* peerAddr =
    (struct sockaddr*)&pInst->channelBindInfo.peerTrnspAddr;
  memset( &peerTrnspAddr, 0, sizeof (StunIPAddress) );

  memset( pReq,           0, sizeof(StunMessage) );
  pReq->msgHdr.msgType = STUN_MSG_ChannelBindRequestMsg;
  stunlib_createId(&pReq->msgHdr.id, TurnRand(), 0);

  if (peerAddr->sa_family == AF_INET)
  {

    peerTrnspAddr.familyType   =  STUN_ADDR_IPv4Family;
    peerTrnspAddr.addr.v4.port = ntohs(
      ( (struct sockaddr_in*)peerAddr )->sin_port);
    peerTrnspAddr.addr.v4.addr = ntohl(
      ( (struct sockaddr_in*)peerAddr )->sin_addr.s_addr);

  }
  else if (peerAddr->sa_family == AF_INET6)
  {
    peerTrnspAddr.familyType   =  STUN_ADDR_IPv6Family;
    peerTrnspAddr.addr.v6.port = ntohs(
      ( (struct sockaddr_in6*)peerAddr )->sin6_port);
    memcpy( peerTrnspAddr.addr.v6.addr,
            ( (struct sockaddr_in6*)peerAddr )->sin6_addr.s6_addr,
            sizeof(peerTrnspAddr.addr.v6.addr) );

  }

    memcpy( &pReq->xorPeerAddress[0], &peerTrnspAddr, sizeof(StunIPAddress) );
  pReq->xorPeerAddrEntries = 1;

  /* Channel No */
  stunlib_addChannelNumber(pReq, pInst->channelBindInfo.channelNumber);
  stunlib_addRealm(pReq, pInst->userCredentials.realm, STUN_DFLT_PAD);
  stunlib_addUserName(pReq, pInst->userCredentials.stunUserName, STUN_DFLT_PAD);
  stunlib_addNonce(pReq, pInst->userCredentials.nonce, STUN_DFLT_PAD);
  stunlib_createMD5Key(pInst->userCredentials.key,
                       pInst->userCredentials.stunUserName,
                       pInst->userCredentials.realm,
                       pInst->userCredentials.stunPassword);
}

static void
BuildCreatePermReq(TURN_INSTANCE_DATA* pInst,
                   StunMessage*        pReq)
{
  StunIPAddress peerTrnspAddr;
  uint32_t      i;

  struct sockaddr* peerAddr;

  memset( pReq, 0, sizeof(StunMessage) );
  pReq->msgHdr.msgType = STUN_MSG_CreatePermissionRequestMsg;
  stunlib_createId(&pReq->msgHdr.id, TurnRand(), 0);

  /* peer address(es) */
  for (i = 0; i < pInst->createPermInfo.numberOfPeers; i++)
  {
    peerAddr = (struct sockaddr*)&pInst->createPermInfo.peerTrnspAddr[i];

    if (peerAddr->sa_family == AF_INET)
    {

      peerTrnspAddr.familyType   =  STUN_ADDR_IPv4Family;
      peerTrnspAddr.addr.v4.port = ntohs(
        ( (struct sockaddr_in*)peerAddr )->sin_port);
      peerTrnspAddr.addr.v4.addr = ntohl(
        ( (struct sockaddr_in*)peerAddr )->sin_addr.s_addr);

    }
    else if (peerAddr->sa_family == AF_INET6)
    {
      peerTrnspAddr.familyType   =  STUN_ADDR_IPv6Family;
      peerTrnspAddr.addr.v6.port = ntohs(
        ( (struct sockaddr_in6*)peerAddr )->sin6_port);
      memcpy( peerTrnspAddr.addr.v6.addr,
              ( (struct sockaddr_in6*)peerAddr )->sin6_addr.s6_addr,
              sizeof(peerTrnspAddr.addr.v6.addr) );

    }

      memcpy( &pReq->xorPeerAddress[i], &peerTrnspAddr, sizeof(StunIPAddress) );
    pReq->xorPeerAddrEntries++;
  }

  stunlib_addRealm(pReq, pInst->userCredentials.realm, STUN_DFLT_PAD);
  stunlib_addUserName(pReq, pInst->userCredentials.stunUserName, STUN_DFLT_PAD);
  stunlib_addNonce(pReq, pInst->userCredentials.nonce, STUN_DFLT_PAD);
  stunlib_createMD5Key(pInst->userCredentials.key,
                       pInst->userCredentials.stunUserName,
                       pInst->userCredentials.realm,
                       pInst->userCredentials.stunPassword);
}


/* send stun keepalive (BindingInd) to keep NAT binding open (fire and forget)
**/
static void
SendStunKeepAlive(TURN_INSTANCE_DATA* pInst)
{
  uint32_t  encLen;
  StunMsgId transId;
  uint8_t   buf[STUN_MIN_PACKET_SIZE];
  encLen = stunlib_encodeStunKeepAliveReq( StunKeepAliveUsage_Ice, &transId,
                                           buf, sizeof(buf) );

  TurnPrint(pInst,
            TurnInfoCategory_Trace,
            "<TURNCLIENT:%d>  OUT-->STUNKEEPALIVE: Len=%i to %s",
            pInst->id,
            encLen,
            pInst->turnAllocateReq.serverAddr);

  pInst->turnAllocateReq.sendFunc(buf,
                                  encLen,
                                  (struct sockaddr*)&pInst->turnAllocateReq.serverAddr,
                                  pInst->turnAllocateReq.userCtx);
}


static bool
GetServerAddrFromAltServer(TURN_INSTANCE_DATA* pInst,
                           StunMessage*        pResp)
{
  if (pResp->hasAlternateServer)
  {
    if (pResp->alternateServer.familyType == STUN_ADDR_IPv4Family)
    {

      sockaddr_initFromIPv4Int(
        (struct sockaddr_in*)&pInst->turnAllocateReq.serverAddr,
        htonl(pResp->alternateServer.addr.v4.addr),
        htons(pResp->alternateServer.addr.v4.port) );


      return true;
    }
    else if (pResp->alternateServer.familyType == STUN_ADDR_IPv6Family)
    {
      sockaddr_initFromIPv6Int(
        (struct sockaddr_in6*)&pInst->turnAllocateReq.serverAddr,
        pResp->alternateServer.addr.v6.addr,
        htons(pResp->alternateServer.addr.v6.port) );
      return true;
    }

    else
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> Alternative Server %d not supported in AllocRespErr",
                pInst->id,
                pResp->alternateServer.familyType);
      return false;
    }
  }
  else
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> Missing Alternative Server in AllocRespErr",
              pInst->id);
    return false;
  }
  return false;
}


/* Refresh response with error code  STALE_NONCE must have  NONCE and  REALM.
 * */
static bool
CheckRefreshRespError(TURN_INSTANCE_DATA* pInst,
                      StunMessage*        pResp)
{
  if (pResp->hasErrorCode)
  {
    if (GetErrCode(pResp) != STUN_ERROR_STALE_NONCE)
    {
      return false;
    }
    if (!pResp->hasRealm)
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> No REALM in RefreshRespError",
                pInst->id);
      return false;
    }
    if (!pResp->hasNonce)
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> No NONCE in RefreshRespError",
                pInst->id);
      return false;
    }
    return true;
  }
  else
  {
      TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> No error code in RefreshRespError",
              pInst->id);
    return false;
  }
}


static bool
HandleStunAllocateResponseMsg(TURN_INSTANCE_DATA* pInst,
                              StunMessage*        pResp,
                              uint8_t*            origMsgBuf)

{
  if (origMsgBuf != NULL)
  {
    if ( !stunlib_checkIntegrity(origMsgBuf,
                                 pResp->msgHdr.msgLength + 20,
                                 pResp,
                                 pInst->userCredentials.key,
                                 16) )
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d>  HandleStunAllocate(), failed message integrity",
                pInst->id);

      return false;
    }

  }

  if ( StoreRelayAddress(pInst, pResp)
       && StoreServerReflexiveAddress(pInst, pResp)
       && StoreLifetime(pInst, pResp)
       && StoreToken(pInst, pResp) )
  {
    return true;
  }

  return false;
}

/* signal the result of allocation back via callback using data supplied by
 * client */
static void
AllocateResponseCallback(TURN_INSTANCE_DATA* pInst)
{
  TurnCallBackData_T* pRes = &pInst->turnCbData;
  TurnAllocResp*      pData;

  if (pRes)
  {
    char srflxaddr[SOCKADDR_MAX_STRLEN];
    char reladdr[SOCKADDR_MAX_STRLEN];
    char activeaddr[SOCKADDR_MAX_STRLEN];

    pData            = &pInst->turnCbData.TurnResultData.AllocResp;
    pRes->turnResult = TurnResult_AllocOk;

    sockaddr_copy( (struct sockaddr*)&pData->activeTurnServerAddr,
                   (struct sockaddr*)&pInst->turnAllocateReq.serverAddr );

    sockaddr_copy( (struct sockaddr*)&pData->relAddrIPv4,
                   (struct sockaddr*)&pInst->relAddr_IPv4 );

    sockaddr_copy( (struct sockaddr*)&pData->relAddrIPv6,
                   (struct sockaddr*)&pInst->relAddr_IPv6 );


    sockaddr_copy( (struct sockaddr*)&pData->srflxAddr,
                   (struct sockaddr*)&pInst->srflxAddr );

    sockaddr_toString( (struct sockaddr*)&pData->relAddrIPv4, reladdr,
                       SOCKADDR_MAX_STRLEN, true );

    sockaddr_toString( (struct sockaddr*)&pData->relAddrIPv6, reladdr,
                       SOCKADDR_MAX_STRLEN, true );

    TurnPrint( pInst,
               TurnInfoCategory_Info,
               "<TURNCLIENT:%d> AllocResp Relay: %s  (%s) Srflx: %s lifetime %d sec from Server %s",
               pInst->id,
               sockaddr_toString( (struct sockaddr*)&pData->relAddrIPv4,
                                  reladdr,   SOCKADDR_MAX_STRLEN, true ),
               sockaddr_toString( (struct sockaddr*)&pData->relAddrIPv6,
                                  reladdr,   SOCKADDR_MAX_STRLEN, true ),
               sockaddr_toString( (struct sockaddr*)&pData->srflxAddr,
                                  srflxaddr, SOCKADDR_MAX_STRLEN, true ),
               pInst->lifetime,
               sockaddr_toString( (struct sockaddr*)&pData->activeTurnServerAddr,
                                  activeaddr, SOCKADDR_MAX_STRLEN, true ) );

    pData->token = pInst->token;
  }

  if (pInst->turnAllocateReq.turnCbFunc)
  {
    (pInst->turnAllocateReq.turnCbFunc)(pInst->turnAllocateReq.userCtx,
                                        &pInst->turnCbData);
  }
}


static void
CallBack(TURN_INSTANCE_DATA* pInst,
         TurnResult_T        turnResult)
{
  pInst->turnCbData.turnResult = turnResult;
  if (pInst->turnAllocateReq.turnCbFunc)
  {
    (pInst->turnAllocateReq.turnCbFunc)(pInst->turnAllocateReq.userCtx,
                                        &pInst->turnCbData);
  }
}


static void
InitRetryCounters(TURN_INSTANCE_DATA* pInst)
{
  pInst->retransmits = 0;
}


static bool
SendTurnReq(TURN_INSTANCE_DATA* pInst,
            StunMessage*        stunReqMsg)
{
  int  len;
  char addrStr[SOCKADDR_MAX_STRLEN];
  char tmp[TURN_TRANSID_BUFFER_SIZE];

  len = stunlib_encodeMessage(stunReqMsg,
                              (unsigned char*) (pInst->stunReqMsgBuf),
                              STUN_MAX_PACKET_SIZE,
                              pInst->userCredentials.realm[0] != '\0' ? pInst->userCredentials.key : NULL,
                              pInst->userCredentials.realm[0] != '\0' ? 16 : 0,
                              NULL);
  pInst->stunReqMsgBufLen = len;

  if (!len)
  {
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d>  SendTurnReq(), failed encode",
              pInst->id);



    return false;
  }
  sockaddr_toString( (struct sockaddr*)&pInst->turnAllocateReq.serverAddr,
                     addrStr,
                     SOCKADDR_MAX_STRLEN,
                     true );


  TurnTransactionIdString(tmp,
                          TURN_TRANSID_BUFFER_SIZE,
                          &stunReqMsg->msgHdr.id.octet[0]);
  TurnPrint(pInst,
            TurnInfoCategory_Trace,
            "<TURNCLIENT:%d> %s OUT-->STUN: %s Len=%i to %s",
            pInst->id,
            tmp,
            stunlib_getMessageName(stunReqMsg->msgHdr.msgType),
            len,
            addrStr);


  pInst->turnAllocateReq.sendFunc(pInst->stunReqMsgBuf,
                                  pInst->stunReqMsgBufLen,
                                  (struct sockaddr*)&pInst->turnAllocateReq.serverAddr,
                                  pInst->turnAllocateReq.userCtx);

  /* store transaction id, so we can match the response */
  StoreReqTransId(pInst, stunReqMsg);

  return true;
}

static void
SendPendingChannelBindReq(TURN_INSTANCE_DATA* pInst)
{
  StunMessage stunReqMsg;
  char        addrStr[SOCKADDR_MAX_STRLEN];

  TurnPrint( pInst,
             TurnInfoCategory_Info,
             "<TURNCLIENT:%d> ChannelBindReq (buffered) chan: %d Peer %s",
             pInst->id,
             pInst->channelBindInfo.channelNumber,
             sockaddr_toString( (struct sockaddr*)&pInst->channelBindInfo.
                                peerTrnspAddr,
                                addrStr,
                                SOCKADDR_MAX_STRLEN,
                                true ) );

  BuildChannelBindReq(pInst, &stunReqMsg);
  SendTurnReq(pInst, &stunReqMsg);
  StartFirstRetransmitTimer(pInst);
}

static bool
HandlePendingChannelBindReq(TURN_INSTANCE_DATA* pInst)
{
  if ( PendingChannelBindReq(pInst) )
  {
    SendPendingChannelBindReq(pInst);
    pInst->pendingChannelBind = false;
    return true;
  }
  return false;
}

static void
RetransmitLastReq(TURN_INSTANCE_DATA* pInst)
{
  pInst->turnAllocateReq.sendFunc(pInst->stunReqMsgBuf,
                                  pInst->stunReqMsgBufLen,
                                  (struct sockaddr*)&pInst->turnAllocateReq.serverAddr,
                                  pInst->turnAllocateReq.userCtx);

}

static void
StartAllocRefreshTimer(TURN_INSTANCE_DATA* pInst)
{
    StartTimer(pInst,
             TURN_SIGNAL_TimerRefreshAlloc,
             (pInst->lifetime / 2) * 1000);
}

static void
StartChannelBindRefreshTimer(TURN_INSTANCE_DATA* pInst)
{
    StartTimer(pInst,
             TURN_SIGNAL_TimerRefreshChannel,
             TURN_REFRESH_CHANNEL_TIMER_SEC * 1000);
}

static void
StartCreatePermissionRefreshTimer(TURN_INSTANCE_DATA* pInst)
{
    StartTimer(pInst,
             TURN_SIGNAL_TimerRefreshPermission,
             TURN_REFRESH_PERMISSION_TIMER_SEC * 1000);
}


static void
StartStunKeepAliveTimer(TURN_INSTANCE_DATA* pInst)
{
  if (pInst->doStunKeepAlive)
  {
    StartTimer(pInst,
               TURN_SIGNAL_TimerStunKeepAlive,
               STUN_KEEPALIVE_TIMER_SEC * 1000);
  }
}


static void
StartFirstRetransmitTimer(TURN_INSTANCE_DATA* pInst)
{
  pInst->retransmits = 0;
    StartTimer(pInst, TURN_SIGNAL_TimerRetransmit,
             stunTimeoutList[pInst->retransmits]);
}


static void
StartNextRetransmitTimer(TURN_INSTANCE_DATA* pInst)
{
    StartTimer(pInst, TURN_SIGNAL_TimerRetransmit,
             stunTimeoutList[pInst->retransmits]);
}


/* Common signal handling for all states */
static void
TurnAllState(TURN_INSTANCE_DATA* pInst,
             TURN_SIGNAL         sig,
             uint8_t*            payload)
{
  (void)payload;

  switch (sig)
  {
  default:
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> undefined signal %s in state %d",
              pInst->id,
              TurnsigToStr(sig),
              pInst->state);
  }
}

/* Common signal handling for all states after successful relay allocation */
static void
TurnAllState_Allocated(TURN_INSTANCE_DATA* pInst,
                       TURN_SIGNAL         sig,
                       uint8_t*            payload)
{
  (void)payload;

  switch (sig)
  {
  case TURN_SIGNAL_DeAllocate:
  {
    StunMessage stunReqMsg;
    StopAllTimers(pInst);
    pInst->lifetime = 0;
    BuildRefreshAllocateReq(pInst, &stunReqMsg, pInst->lifetime);
    SendTurnReq(pInst, &stunReqMsg);
    pInst->retransmits = 0;
    StartTimer(pInst,
               TURN_SIGNAL_TimerRetransmit,
               TURN_RETRANS_TIMEOUT_RELEASE_MSEC);
    SetNextState(pInst, TURN_STATE_WaitReleaseResp);
    break;
  }

  case TURN_SIGNAL_TimerStunKeepAlive:
  {
    SendStunKeepAlive(pInst);
    StartStunKeepAliveTimer(pInst);
    break;
  }

  default:
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> undefned signal %s in state %d",
              pInst->id,
              TurnsigToStr(sig),
              pInst->state);
    break;
  }
}



static void
TurnClientFsm(TURN_INSTANCE_DATA* pInst,
              TURN_SIGNAL         sig,
              uint8_t*            payload,
              uint8_t*            origMsgBuf)
{
  if (pInst->state < TURN_STATE_End)
  {
    TurnPrint(pInst,
              TurnInfoCategory_Trace,
              "<TURNCLIENT:%d> IN <-- %s (state %s)\n",
              (uint32_t) pInst->id, TurnsigToStr(sig),
              StateTable[pInst->state].StateStr);
    if (pInst->inUse)
    {
      (StateTable[pInst->state].Statefunc)(pInst, sig, payload, origMsgBuf);
    }
    else if (sig == TURN_SIGNAL_DeAllocate)
    {
      CallBack(pInst, TurnResult_RelayReleaseFailed);
    }
  }
  else if (sig == TURN_SIGNAL_DeAllocate)
  {
      CallBack(pInst, TurnResult_RelayReleaseFailed);
  }
  else
  {
    TurnPrint( pInst,
               TurnInfoCategory_Error,
               "<TURNCLIENT:%d> undefined state %d, sig %s",
               pInst->id,
               pInst->state,
               TurnsigToStr(sig) );
  }
}

static void
CommonRetryTimeoutHandler(TURN_INSTANCE_DATA* pInst,
                          TurnResult_T        turnResult,
                          const char*         errStr,
                          TURN_STATE          FailedState)
{

  if ( (pInst->retransmits < STUNCLIENT_MAX_RETRANSMITS)
       && (stunTimeoutList[pInst->retransmits] != 0) )  /* can be 0 terminated
                                                         * if using fewer
                                                         * retransmits */
  {
    char tmp[TURN_TRANSID_BUFFER_SIZE];
    TurnTransactionIdString(tmp,
                            TURN_TRANSID_BUFFER_SIZE,
                            &pInst->stunReqMsgBuf[8]);
    TurnPrint(pInst,
              TurnInfoCategory_Trace,
              "<TURNCLIENT:%d> %s Retransmit %s Retry: %d",
              pInst->id,
              tmp,
              errStr,
              pInst->retransmits + 1);

    RetransmitLastReq(pInst);
    StartNextRetransmitTimer(pInst);
    pInst->retransmits++;
  }
  else
  {
    pInst->failures++;
    TurnPrint(pInst,
              TurnInfoCategory_Error,
              "<TURNCLIENT:%d> Retransmit %s failed after %d retries",
              pInst->id,
              errStr,
              pInst->retransmits);

    if  (turnResult == TurnResult_CreatePermissionNoAnswer)
    {
      pInst->permissionsInstalled = false;
    }
    else if  (turnResult == TurnResult_ChanBindFailNoanswer)
    {
      pInst->channelBound = false;
    }

    SetNextState(pInst, FailedState);
    CallBack(pInst, turnResult);
  }
}


static void
TurnState_Idle(TURN_INSTANCE_DATA* pInst,
               TURN_SIGNAL         sig,
               uint8_t*            payload,
               uint8_t*            origMsgBuf)
{
  (void)origMsgBuf;

  switch (sig)
  {
  case TURN_SIGNAL_AllocateReq:
  {
    StunMessage           stunReqMsg;
    TurnAllocateReqStuct* pMsgIn = (TurnAllocateReqStuct*)payload;

    /* store request */
    StoreAllocateReq(pInst, pMsgIn);

    /* */
    BuildInitialAllocateReq(pInst, &stunReqMsg);

    InitRetryCounters(pInst);

    SendTurnReq(pInst, &stunReqMsg);

    StartFirstRetransmitTimer(pInst);

    SetNextState(pInst, TURN_STATE_WaitAllocRespNotAuth);

    break;
  }

  case TURN_SIGNAL_DeAllocate:        /* ignore extra clears */
    break;

  case TURN_SIGNAL_RefreshResp:       /* may arrive after sending refresh(0) */
    break;

  default:
    TurnAllState(pInst, sig, payload);
    break;
  }

} /* TurnState_Idle() */


/*
 * initial "empty" AllocateReq has been sent, waiting for response.
 */
static void
TurnState_WaitAllocRespNotAut(TURN_INSTANCE_DATA* pInst,
                              TURN_SIGNAL         sig,
                              uint8_t*            payload,
                              uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  switch (sig)
  {

  case TURN_SIGNAL_AllocateRespError:
  {
    StunMessage* pResp = (StunMessage*)payload;
    uint32_t     errCode;

    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);

    errCode = GetErrCode(pResp);
    switch (errCode)
    {
    case STUN_ERROR_UNAUTHORIZED:
    {
      if ( !StoreRealmAndNonce(pInst, pResp) )
      {
        SetNextState(pInst, TURN_STATE_Idle);
        CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
      }
      else
      {
        StunMessage stunReqMsg;
        BuildNewAllocateReq(pInst, &stunReqMsg);
        SendTurnReq(pInst, &stunReqMsg);
        StartFirstRetransmitTimer(pInst);
        SetNextState(pInst, TURN_STATE_WaitAllocResp);
      }
      break;
    }

    case STUN_ERROR_TRY_ALTERNATE:
    {
      /* start again, using  alternate server, stay in this state  */
      if ( GetServerAddrFromAltServer(pInst, pResp) )
      {
        StunMessage stunReqMsg;
        BuildInitialAllocateReq(pInst, &stunReqMsg);
        InitRetryCounters(pInst);
        SendTurnReq(pInst, &stunReqMsg);
        StartFirstRetransmitTimer(pInst);
        pInst->redirected = true;
      }
      else
      {
        SetNextState(pInst, TURN_STATE_Idle);
        CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
      }
      break;
    }

    case NoStunErrorCode:
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> Missing error code in AllocRespErr",
                pInst->id);
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
      break;
    }

    default:
    {
      TurnPrint(pInst,
                TurnInfoCategory_Error,
                "<TURNCLIENT:%d> Unhandled error code %d in AllocRespErr",
                pInst->id,
                errCode);
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
      break;
    }

    }         /* switch on errCode */
    break;
  }         /* TURN_SIGNAL_AllocateRespError */

  case TURN_SIGNAL_AllocateResp:         /* e.g if authentication is not
                                          * necessary */
  {
    StunMessage* pResp = (StunMessage*)payload;

    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    if ( HandleStunAllocateResponseMsg(pInst, pResp, NULL) )
    {
      StartAllocRefreshTimer(pInst);
      SetNextState(pInst, TURN_STATE_Allocated);
      AllocateResponseCallback(pInst);
    }
    else
    {
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
    }

    break;
  }


  case TURN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(pInst,
                              TurnResult_AllocFailNoAnswer,
                              "initial allocateReq",
                              TURN_STATE_Idle);
    break;
  }

  case TURN_SIGNAL_DeAllocate:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    SetNextState(pInst, TURN_STATE_Idle);
    break;
  }

  default:
    TurnAllState(pInst, sig, payload);
    break;
  }

} /* TurnState_WaitAllocRespNotAut() */


/*
 * Second AllocateReq has been sent, waiting for response.
 */
static void
TurnState_WaitAllocResp(TURN_INSTANCE_DATA* pInst,
                        TURN_SIGNAL         sig,
                        uint8_t*            payload,
                        uint8_t*            origMsgBuf)
{
  switch (sig)
  {
  case TURN_SIGNAL_AllocateRespError:
  {
    uint32_t     errCode;
    StunMessage* pResp = (StunMessage*)payload;
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    errCode = GetErrCode(pResp);
    TurnPrint(pInst, TurnInfoCategory_Info,
              "<TURNCLIENT:%d> Authorisation failed code %d",pInst->id,
              errCode);
    switch (errCode)
    {
    case STUN_ERROR_QUOTA_REACHED:
    {
      CallBack(pInst, TurnResult_CreatePermissionQuotaReached);
      SetNextState(pInst, TURN_STATE_Idle);
      break;
    }

    case STUN_ERROR_TRY_ALTERNATE:
    {
      /* start again, using  alternate server, stay in this state  */
      if ( GetServerAddrFromAltServer(pInst, pResp) )
      {
        StunMessage stunReqMsg;
        BuildNewAllocateReq(pInst, &stunReqMsg);
        InitRetryCounters(pInst);
        SendTurnReq(pInst, &stunReqMsg);
        StartFirstRetransmitTimer(pInst);
      }
      else
      {
        SetNextState(pInst, TURN_STATE_Idle);
        CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
      }
      break;
    }

    case STUN_ERROR_STALE_NONCE:
    {
      StunMessage stunReqMsg;
      /* store new nonce and realm, recalculate and resend channel refresh */
      TurnPrint(pInst,
                TurnInfoCategory_Info,
                "<TURNCLIENT:%d> Stale Nonce %d",
                pInst->id,
                errCode);

      StoreRealmAndNonce(pInst, pResp);
      BuildNewAllocateReq(pInst, &stunReqMsg);
      SendTurnReq(pInst, &stunReqMsg);
      StartFirstRetransmitTimer(pInst);
      break;
    }


    default:
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_AllocUnauthorised);
      break;
    }
    break;
  }

  case TURN_SIGNAL_AllocateResp:
  {
    StunMessage* pResp = (StunMessage*)payload;



    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    if ( HandleStunAllocateResponseMsg(pInst, pResp, origMsgBuf) )
    {
      StartAllocRefreshTimer(pInst);
      SetNextState(pInst, TURN_STATE_Allocated);
      AllocateResponseCallback(pInst);

    }
    else
    {
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_MalformedRespWaitAlloc);
    }
    break;
  }

  case TURN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(pInst,
                              TurnResult_AllocFailNoAnswer,
                              "allocateReq",
                              TURN_STATE_Idle);
    break;
  }

  case TURN_SIGNAL_DeAllocate:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    SetNextState(pInst, TURN_STATE_Idle);
    break;
  }

  default:
    TurnAllState(pInst, sig, payload);
    break;
  }

} /*TurnState_WaitAllocResp () */


/* Have an allocated relay */
static void
TurnState_Allocated(TURN_INSTANCE_DATA* pInst,
                    TURN_SIGNAL         sig,
                    uint8_t*            payload,
                    uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  StunMessage stunReqMsg;

  switch (sig)
  {
  case TURN_SIGNAL_CreatePermissionReq:
  {
    uint32_t                    i;
    TurnCreatePermissionInfo_T* pMsgIn = (TurnCreatePermissionInfo_T*)payload;
    char                        addrStr[SOCKADDR_MAX_STRLEN];

    pInst->createPermissionCallbackCalled = false;
    StoreCreatePermReq(pInst, pMsgIn);

    for (i = 0; i < pMsgIn->numberOfPeers; i++)
    {
      TurnPrint( pInst, TurnInfoCategory_Info,
                 "<TURNCLIENT:%d> CreatePermReq Peer %s",
                 pInst->id,
                 sockaddr_toString( (struct sockaddr*)&pMsgIn->peerTrnspAddr[i],
                                    addrStr,
                                    SOCKADDR_MAX_STRLEN,
                                    true ) );
    }

    BuildCreatePermReq(pInst, &stunReqMsg);
    SendTurnReq(pInst, &stunReqMsg);
    StartFirstRetransmitTimer(pInst);
    SetNextState(pInst, TURN_STATE_WaitCreatePermResp);
    break;
  }

  case TURN_SIGNAL_ChannelBindReq:
  {
    TurnChannelBindInfo_T* pMsgIn = (TurnChannelBindInfo_T*)payload;
    char                   addrStr[SOCKADDR_MAX_STRLEN];

    pInst->channelBindCallbackCalled = false;
    StoreChannelBindReq(pInst, pMsgIn);
    TurnPrint( pInst,
               TurnInfoCategory_Info,
               "<TURNCLIENT:%d> ChannelBindReq chan: %d Peer %s",
               pInst->id,
               pMsgIn->channelNumber,
               sockaddr_toString( (struct sockaddr*)&pMsgIn->peerTrnspAddr,
                                  addrStr,
                                  SOCKADDR_MAX_STRLEN,
                                  true ) );

    BuildChannelBindReq(pInst, &stunReqMsg);

    SendTurnReq(pInst, &stunReqMsg);
    StartFirstRetransmitTimer(pInst);
    SetNextState(pInst, TURN_STATE_WaitChanBindResp);
    break;
  }

  case TURN_SIGNAL_TimerRefreshAlloc:
  {
    /* build and send an allocation refresh */
    BuildRefreshAllocateReq(pInst, &stunReqMsg, pInst->lifetime);
    SendTurnReq(pInst, &stunReqMsg);
    StartFirstRetransmitTimer(pInst);
    SetNextState(pInst, TURN_STATE_WaitAllocRefreshResp);
    break;
  }

  case TURN_SIGNAL_TimerRefreshChannel:
  {
    /* build and send a channel bind refresh */
    BuildChannelBindReq(pInst, &stunReqMsg);
    SendTurnReq(pInst, &stunReqMsg);
    StartFirstRetransmitTimer(pInst);
    SetNextState(pInst, TURN_STATE_WaitChanBindResp);
    break;
  }

  case TURN_SIGNAL_TimerRefreshPermission:
  {
    /* no need to refresh permissions if channel is bound
     * coz a channel bind creates a permission
     */
    if (!pInst->channelBound)
    {
      /* build and send a Permission refresh */
      BuildCreatePermReq(pInst, &stunReqMsg);
      SendTurnReq(pInst, &stunReqMsg);
      StartFirstRetransmitTimer(pInst);
      SetNextState(pInst, TURN_STATE_WaitCreatePermResp);
    }
    else
    {
      pInst->permissionsInstalled = false;
    }

    break;
  }


  default:
    TurnAllState_Allocated(pInst, sig, payload);
    break;
  }

} /* TurnState_AllocatedChan() */


/*
 * (Allocation) Refresh sent, waiting for response.
 */
static void
TurnState_WaitAllocRefreshResp(TURN_INSTANCE_DATA* pInst,
                               TURN_SIGNAL         sig,
                               uint8_t*            payload,
                               uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  StunMessage stunReqMsg;

  switch (sig)
  {
  case TURN_SIGNAL_RefreshResp:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    StartAllocRefreshTimer(pInst);
    SetNextState(pInst, TURN_STATE_Allocated);
    break;
  }

  case TURN_SIGNAL_RefreshRespError:
  {
    StunMessage* pResp = (StunMessage*)payload;

    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);

    if ( CheckRefreshRespError(pInst, pResp) )
    {
      StartFirstRetransmitTimer(pInst);              /* store new nonce and
                                                      * realm, recalculate and
                                                      * resend channel refresh
                                                      **/
      TurnPrint( pInst, TurnInfoCategory_Info, "<TURNCLIENT:%d> Stale Nonce %d",
                 pInst->id, GetErrCode(pResp) );

      StoreRealmAndNonce(pInst, pResp);
      BuildRefreshAllocateReq(pInst, &stunReqMsg, pInst->lifetime);
      SendTurnReq(pInst, &stunReqMsg);
      StartFirstRetransmitTimer(pInst);
    }
    else
    {
      TurnPrint( pInst, TurnInfoCategory_Info,
                 "<TURNCLIENT:%d> Refresh failed code %d",pInst->id,
                 GetErrCode(pResp) );
      StopAllTimers(pInst);
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_RefreshFail);
    }
    break;
  }


  case TURN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(pInst,
                              TurnResult_RefreshFailNoAnswer,
                              "refreshReqChanId",
                              TURN_STATE_Idle);
    break;
  }

  case TURN_SIGNAL_TimerRefreshChannel:
  {
    /* just delay it til later, were busy with Allocation refresh  */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshChannel, 2 * 1000);
    break;
  }

  case TURN_SIGNAL_TimerRefreshPermission:
  {
    /* just delay it til later, we're busy */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshPermission, 3 * 1000);
    break;
  }


  default:
    TurnAllState_Allocated(pInst, sig, payload);
    break;

  }

} /* TurnState_WaitAllocRefreshResp() */



/*
 * ChannelBindReq has been sent. Waiting for  response.
 */
static void
TurnState_WaitChanBindResp(TURN_INSTANCE_DATA* pInst,
                           TURN_SIGNAL         sig,
                           uint8_t*            payload,
                           uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  switch (sig)
  {
  case TURN_SIGNAL_ChannelBindResp:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    pInst->channelBound = true;

    StartChannelBindRefreshTimer(pInst);
    SetNextState(pInst,TURN_STATE_Allocated);

    /* only do the callback on initial success, and not for every refresh  */
    if (!pInst->channelBindCallbackCalled)
    {
      pInst->channelBindCallbackCalled = true;
      CallBack(pInst, TurnResult_ChanBindOk);
    }
    break;
  }

  case TURN_SIGNAL_ChannelBindRespError:
  {
    StunMessage* pResp = (StunMessage*)payload;
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);

    if ( CheckRefreshRespError(pInst, pResp) )
    {
      StunMessage stunReqMsg;

      /* store new nonce and realm, recalculate and resend channel refresh */
      StartFirstRetransmitTimer(pInst);
      TurnPrint( pInst, TurnInfoCategory_Info,
                 "<TURNCLIENT:%d> ChannelBind Refresh Stale Nonce %d",pInst->id, GetErrCode(
                   pResp) );
      StoreRealmAndNonce(pInst, pResp);
      BuildChannelBindReq(pInst, &stunReqMsg);
      SendTurnReq(pInst, &stunReqMsg);
      StartFirstRetransmitTimer(pInst);
    }
    else
    {
      pInst->channelBound = false;
      TurnPrint( pInst, TurnInfoCategory_Error,
                 "<TURNCLIENT:%d>  ChannelBind Refresh got ErrorCode %d",
                 pInst->id, GetErrCode( (StunMessage*)payload ) );
      SetNextState(pInst,TURN_STATE_Allocated);
      CallBack(pInst, TurnResult_ChanBindFail);
    }
    break;
  }

  case TURN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(pInst,
                              TurnResult_ChanBindFailNoanswer,
                              "channelBindReq",
                              TURN_STATE_Allocated);
    break;
  }

  case TURN_SIGNAL_TimerRefreshAlloc:
  {
    /* just delay it til later, we're busy */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshAlloc, 3 * 1000);
    break;
  }

  case TURN_SIGNAL_TimerRefreshPermission:
  {
    /* just delay it til later, we're busy */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshPermission, 2 * 1000);
    break;
  }

  default:
    TurnAllState_Allocated(pInst, sig, payload);
    break;
  }

} /* TurnState_WaitChanBindResp() */


/*
 * CreatePermissionReq has been sent. Waiting for  response.
 */
static void
TurnState_WaitCreatePermResp(TURN_INSTANCE_DATA* pInst,
                             TURN_SIGNAL         sig,
                             uint8_t*            payload,
                             uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  switch (sig)
  {
  case TURN_SIGNAL_CreatePermissionResp:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);

    pInst->permissionsInstalled = true;
    StartCreatePermissionRefreshTimer(pInst);
    SetNextState(pInst, HandlePendingChannelBindReq(
                   pInst) ? TURN_STATE_WaitChanBindResp : TURN_STATE_Allocated);

    /* only do the callback on initial success, and not for every refresh  */
    if (!pInst->createPermissionCallbackCalled)
    {
      pInst->createPermissionCallbackCalled = true;
      CallBack(pInst, TurnResult_CreatePermissionOk);
    }
    break;
  }


  case TURN_SIGNAL_CreatePermissionRespError:
  {
    StunMessage* pResp = (StunMessage*)payload;
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    pInst->permissionsInstalled = false;

    if ( CheckRefreshRespError(pInst, pResp) )
    {
      StunMessage stunReqMsg;

      /* store new nonce and realm, recalculate and resend CreatePermissionReq
      **/
      StartFirstRetransmitTimer(pInst);
      TurnPrint( pInst, TurnInfoCategory_Info, "<TURNCLIENT:%d> Stale Nonce %d",
                 pInst->id, GetErrCode(pResp) );
      StoreRealmAndNonce(pInst, pResp);
      BuildCreatePermReq(pInst, &stunReqMsg);
      SendTurnReq(pInst, &stunReqMsg);
      StartFirstRetransmitTimer(pInst);
    }
    else
    {
      TurnPrint( pInst, TurnInfoCategory_Error,
                 "<TURNCLIENT:%d> WaitCreatePermResp got ErrorCode %d",
                 pInst->id, GetErrCode(
                   (StunMessage*)payload) );
      SetNextState(pInst, HandlePendingChannelBindReq(
                     pInst) ? TURN_STATE_WaitChanBindResp : TURN_STATE_Allocated);
      CallBack(pInst, TurnResult_PermissionRefreshFail);
    }
    break;
  }


  case TURN_SIGNAL_TimerRetransmit:
  {
    CommonRetryTimeoutHandler(pInst,
                              TurnResult_CreatePermissionNoAnswer,
                              "createPermissionReq",
                              TURN_STATE_Allocated);
    break;
  }

  case TURN_SIGNAL_TimerRefreshAlloc:
  {
    /* just delay it til later, we're busy */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshAlloc, 3 * 1000);
    break;
  }

  case TURN_SIGNAL_TimerRefreshChannel:
  {
    /* just delay it til later, we're busy */
    StartTimer(pInst, TURN_SIGNAL_TimerRefreshChannel, 2 * 1000);
    break;
  }

  case TURN_SIGNAL_ChannelBindReq:
  {
    TurnChannelBindInfo_T* pMsgIn = (TurnChannelBindInfo_T*)payload;
    char                   addrStr[SOCKADDR_MAX_STRLEN];
    StoreChannelBindReq(pInst, pMsgIn);
    pInst->pendingChannelBind        = true;
    pInst->channelBindCallbackCalled = false;
    TurnPrint( pInst,
               TurnInfoCategory_Info,
               "<TURNCLIENT:%d> Buffering ChannelBindReq chan: %d Peer %s",
               pInst->id,
               pMsgIn->channelNumber,
               sockaddr_toString( (struct sockaddr*)&pMsgIn->peerTrnspAddr,
                                  addrStr,
                                  SOCKADDR_MAX_STRLEN,
                                  true ) );
    break;
  }

  default:
    TurnAllState_Allocated(pInst, sig, payload);
    break;
  }

} /* TurnState_WaitCreatePermResp() */


/* Refresh(0) sent. Waiting for  Resp.
 * Note that in many cases (unfortunately) the socket gets closed by the
 * application after sending the Refresh(0).
 * This means that ResfreshResp will not be received. So hence use a relatively
 * short timer to get back to idle quick
 * and not lock up resources.
 */
static void
TurnState_WaitReleaseResp(TURN_INSTANCE_DATA* pInst,
                          TURN_SIGNAL         sig,
                          uint8_t*            payload,
                          uint8_t*            origMsgBuf)
{
  (void)(origMsgBuf);
  switch (sig)
  {
  case TURN_SIGNAL_RefreshResp:
  {
    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);
    SetNextState(pInst, TURN_STATE_Idle);
    CallBack(pInst, TurnResult_RelayReleaseComplete);
    break;
  }

  /* have to handle stale nonce, otherwise the relay will not be released ! */
  case TURN_SIGNAL_RefreshRespError:
  {
    StunMessage* pResp = (StunMessage*)payload;

    StopTimer(pInst, TURN_SIGNAL_TimerRetransmit);

    if ( CheckRefreshRespError(pInst, pResp) )
    {
      StunMessage stunReqMsg;

      /* store new nonce and realm, recalculate and resend channel refresh */
      TurnPrint( pInst, TurnInfoCategory_Info, "<TURNCLIENT:%d> Stale Nonce %d",
                 pInst->id, GetErrCode(pResp) );

      StoreRealmAndNonce(pInst, pResp);
      BuildRefreshAllocateReq(pInst, &stunReqMsg, pInst->lifetime);
      SendTurnReq(pInst, &stunReqMsg);
      pInst->retransmits = 0;
      StartTimer(pInst,
                 TURN_SIGNAL_TimerRetransmit,
                 TURN_RETRANS_TIMEOUT_RELEASE_MSEC);
    }
    else
    {
      TurnPrint( pInst, TurnInfoCategory_Info,
                 "<TURNCLIENT:%d> Refresh failed code %d",pInst->id,
                 GetErrCode(pResp) );
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_RelayReleaseFailed);
    }
    break;
  }

  case TURN_SIGNAL_TimerRetransmit:
  {
    if (pInst->retransmits < TURN_RETRIES_RELEASE)
    {
      char tmp[TURN_TRANSID_BUFFER_SIZE];
      TurnTransactionIdString(tmp,
                              TURN_TRANSID_BUFFER_SIZE,
                              &pInst->stunReqMsgBuf[8]);
      TurnPrint(pInst,
                TurnInfoCategory_Trace,
                "<TURNCLIENT:%d> %s Retransmit Refresh(0) Retry: %d",
                pInst->id,
                tmp,
                pInst->retransmits + 1);
      RetransmitLastReq(pInst);
      pInst->retransmits++;
      StartTimer(pInst,
                 TURN_SIGNAL_TimerRetransmit,
                 TURN_RETRANS_TIMEOUT_RELEASE_MSEC);
    }
    else
    {
      SetNextState(pInst, TURN_STATE_Idle);
      CallBack(pInst, TurnResult_RelayReleaseFailed);
    }
    break;
  }

  /* ignore duplicate disconnects */
  case TURN_SIGNAL_DeAllocate:
    break;

  default:
    TurnAllState(pInst, sig, payload);
    break;
  }
} /* TurnState_WaitReleaseResp() */

bool
TurnClient_HasBoundChannel(TURN_INSTANCE_DATA* inst)
{
  return inst && inst->channelBound;
}

/* send media (via turnserver) to peer */
bool
TurnClient_SendPacket(TURN_INSTANCE_DATA* pInst,
                      uint8_t*            buf,
                      size_t              bufSize,
                      uint32_t            dataLen,
                      uint32_t            offset,
                      const struct sockaddr* peerAddr,
                      bool                needChannelDataPadding)
{
  uint8_t* payload            = buf + offset;
  uint32_t turnSendIndHdrSize = TURN_SEND_IND_HDR_SIZE;

  /* insert TURN channel number + Len  before payload  */
  if (pInst->channelBound)
  {
    if (offset >= TURN_CHANNEL_DATA_HDR_SIZE)
    {
      /* overwrite part of offset data with turn header */
      stunlib_encodeTurnChannelNumber(
        (uint16_t)pInst->channelBindInfo.channelNumber,
        dataLen,
        (uint8_t*)(payload -
                   TURN_CHANNEL_DATA_HDR_SIZE) );
      offset -= TURN_CHANNEL_DATA_HDR_SIZE;
    }
    else
    {
      /* shift buffer TURN_CHANNEL_DATA_HDR_SIZE bytes to make room for turn
       * header */
      memmove(payload + TURN_CHANNEL_DATA_HDR_SIZE, payload, dataLen);
      stunlib_encodeTurnChannelNumber(
        (uint16_t)pInst->channelBindInfo.channelNumber,
        dataLen,
        (uint8_t*)payload);
    }
    dataLen += TURN_CHANNEL_DATA_HDR_SIZE;
    if (needChannelDataPadding)
    {
      while (dataLen & 3)
      {
        buf[offset + dataLen++] = 0;
      }
    }
  }

  /* Encapsulate in a send indication */
  else
  {
    if (offset >= turnSendIndHdrSize)
    {
      /* overwrite offset data with turn header */
      dataLen =
        stunlib_EncodeSendIndication( (uint8_t*)(payload - turnSendIndHdrSize),
                                      NULL,
                                      bufSize,
                                      dataLen,
                                      peerAddr );
      offset -= turnSendIndHdrSize;
    }
    else
    {
      /* shift buffer to make room for turn header */
      memmove(buf + turnSendIndHdrSize, buf, dataLen);
      dataLen = stunlib_EncodeSendIndication( (unsigned char*)buf,
                                              NULL,
                                              bufSize,
                                              dataLen,
                                              peerAddr );
    }
  }

  /* send packet using send callback */
  if (dataLen)
  {
    pInst->turnAllocateReq.sendFunc(buf + offset,
                                    dataLen,
                                    (struct sockaddr*)&pInst->turnAllocateReq.serverAddr,
                                    pInst->turnAllocateReq.userCtx);
    return true;
  }
  return false;
}


bool
TurnClient_ReceivePacket(TURN_INSTANCE_DATA* pInst,
                         uint8_t*            media,
                         size_t*             length,
                         struct sockaddr*    peerAddr,
                         size_t              addrSize,
                         uint64_t*           reservationToken)
{
  /* check for TURN channel  data */
  if ( stunlib_isTurnChannelData(media) )
  {
    uint16_t channelNumber = 0;
    uint16_t decodedLength = 0;

    if (!pInst->channelBound)
    {
      return false;
    }

    stunlib_decodeTurnChannelNumber(&channelNumber,
                                    &decodedLength,
                                    media);

    if ( (channelNumber != pInst->channelBindInfo.channelNumber) ||
         (decodedLength > *length - 4) )
    {
      return false;
    }

    *length = decodedLength;
    memmove(media, media + 4, *length);

    if (peerAddr)
    {
      if ( addrSize >= sizeof (pInst->channelBindInfo.peerTrnspAddr) )
      {
        memcpy( peerAddr, &pInst->channelBindInfo.peerTrnspAddr,
                sizeof (pInst->channelBindInfo.peerTrnspAddr) );
      }
    }
  }
  else if ( stunlib_isStunMsg(media, (uint16_t)*length) )
  {
    StunMessage stunMsg;
    if ( !stunlib_DecodeMessage(media, *length, &stunMsg, NULL, NULL) )
    {
      return false;
    }

    switch (stunMsg.msgHdr.msgType)
    {
    case STUN_MSG_DataIndicationMsg:
      if (stunMsg.hasData)
      {
        memmove(media, stunMsg.data.pData, stunMsg.data.dataLen);
        *length = (size_t)stunMsg.data.dataLen;
      }
      if ( (stunMsg.xorPeerAddrEntries > 0) && peerAddr )
      {
        if (stunMsg.xorPeerAddress[0].familyType == STUN_ADDR_IPv4Family)
        {
          sockaddr_initFromIPv4Int( (struct sockaddr_in*)peerAddr,
                                    htonl(
                                      stunMsg.xorPeerAddress[0].addr.v4.addr),
                                    htons(
                                      stunMsg.xorPeerAddress[0].addr.v4.port) );
        }
        else if (stunMsg.xorPeerAddress[0].familyType == STUN_ADDR_IPv6Family)
        {
          sockaddr_initFromIPv6Int( (struct sockaddr_in6*)peerAddr,
                                    stunMsg.xorPeerAddress[0].addr.v6.addr,
                                    htons(
                                      stunMsg.xorPeerAddress[0].addr.v6.port) );
        }
      }
      return false;

    /* Turn Reponses/Turn Error responses */
    case STUN_MSG_AllocateResponseMsg:
      if (stunMsg.hasReservationToken && reservationToken)
      {
        *reservationToken = stunMsg.reservationToken.value;
      }
    /*fallthrough*/
    case STUN_MSG_AllocateErrorResponseMsg:
    case STUN_MSG_CreatePermissionResponseMsg:
    case STUN_MSG_CreatePermissionErrorResponseMsg:
    case STUN_MSG_ChannelBindResponseMsg:
    case STUN_MSG_ChannelBindErrorResponseMsg:
    case STUN_MSG_RefreshResponseMsg:
    case STUN_MSG_RefreshErrorResponseMsg:
      TurnClient_HandleIncResp(pInst, &stunMsg, media);
      return true;

    default:
      return false;
    }
  }
  return false;
}

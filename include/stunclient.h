/*
 *  See license file
 */

#ifndef STUNCLIENT_H
#define STUNCLIENT_H


#include "stunlib.h"   /* stun enc/dec and msg formats*/
#include <stdint.h>
#include "sockaddr_util.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

#define MAX_STUN_TRANSACTIONS  60
#define SoftwareVersionStr "Cisco"


/* forward declarations */
struct STUN_CLIENT_DATA;
typedef struct STUN_CLIENT_DATA STUN_CLIENT_DATA;


/* category of info sent in STUN_INFO_FUNC */
typedef enum
{
  StunInfoCategory_Info,
  StunInfoCategory_Error,
  StunInfoCategory_Trace

} StunInfoCategory_T;

typedef enum
{
  StunResult_Empty,                      /* for testing */
  StunResult_BindOk,                     /* successful */
  StunResult_BindFail,                   /* Received BindErrorResp */
  StunResult_BindFailNoAnswer,           /* Bind Req failed - no contact with
                                          * stun server */
  StunResult_BindFailUnauthorised,       /* passwd/username is incorrect */
  StunResult_CancelComplete,             /* Request is cancelled and timed out
                                         **/
  StunResult_ICMPResp,                   /* Received ICMP */
  StunResult_InternalError,
  StunResult_MalformedResp
} StunResult_T;


/* Signalled back to the caller as a paramter in the TURN callback (see TURNCB)
**/


typedef struct
{
  StunMsgId               msgId;
  StunResult_T            stunResult;
  struct sockaddr_storage rflxAddr;
  struct sockaddr_storage srcAddr;
  struct sockaddr_storage dstBaseAddr;    /* The destination seen from the
                                           * sender of the response */
  uint32_t rtt;                           /* Rtt in microseconds */
  uint32_t retransmits;
  uint32_t ICMPtype;
  uint32_t ttl;
} StunCallBackData_T;

/* for output of managment info (optional) */
typedef void (* STUN_INFO_FUNC_PTR)(void*              userData,
                                    StunInfoCategory_T category,
                                    char*              ErrStr);

/* Signalling back to user e.g. result of BindResp.
 *   userCtx        - User provided context, as provided in
 * StunClient_startxxxx(userCtx,...)
 *   stunCbData     - User provided stun callback data. stunbind writes status
 * here. e.g. Alloc ok + reflexive + relay address
 */
typedef void (* STUNCB)(void*               userCtx,
                        StunCallBackData_T* stunCbData);


typedef struct {
  int32_t       globalSocketId;
  STUN_SENDFUNC sendFunc;

  /* Request Data */
  char     ufrag[STUN_MAX_STRING];
  uint32_t ufragLen;
  uint32_t peerPriority;
  bool     useCandidate;
  bool     iceControlling;
  bool     iceControlled;
  uint64_t tieBreaker;
  uint8_t  transactionId[12];
  bool     fromRelay;
  uint32_t peerPort;
} STUN_INCOMING_REQ_DATA;


/*
 *  initialisation:
 *    Should be called (once only) before StunClient_startxxxxxx().
 *    InstanceData - memory allocated by user, to be used by the StunClient.
 */
bool
StunClient_Alloc(STUN_CLIENT_DATA** clientDataPtr);


void
StunClient_free(STUN_CLIENT_DATA* clientData);


/*
 *  initialisation:
 *    Should be called (once only) before StunClient_startxxxxxx().
 *    InstanceData   - memory allocated by user, to be used by the StunClient.
 *    funcPtr        - Will be called by Stun when it outputs management info
 * and trace.
 *                     If this is NULL, then there is no output.  You can
 * provide a function such as below::
 *    userData       - void pointer to be returned with logger callback
 */
void
StunClient_RegisterLogger(STUN_CLIENT_DATA*  clientData,
                          STUN_INFO_FUNC_PTR logPtr,
                          void*              userData);


/*
 *  Initiate a Stun Bind Transaction
 *
 *     userCtx          -  user specific context info (e.g. CallId/ChanId).
 * Optional, can be NULL. STUN does not write to this data.
 *     serverAddr       -  Address of TURN server in format  "a.b.c.d:port"
 *     baseAddr         -  Address of BASE in format  "a.b.c.d:port"
 *     proto            -  Optional context passed to sendFunc. eg.
 * IPPROTO_UDP/TCP.
 *     useRelay         -  True to send via TURN server
 *     uFrag            -  Combination of local and remote ufrag exchanged in
 * INVITE(LFRAG) / OK(RFRAG) in format <LFRAG>:<RFRAG>
 *     password         -  Remote password, exchanged in invite/ok.    \0
 * terminated string. Max 512 chars.
 *     peerPriority     -  Candidate Priority. See ICE-19 spec.
 *     useCandidate     -
 *     iceControlling   -
 *     tieBreaker       -
 *     transactionId    -
 *     sockhandle       -  used as 1st parameter in STUN_SENDFUNC(), typically a
 * socket.
 *     sendFunc         -  function used to send STUN packet.
 * send(sockhandle,buff, len, turnServerAddr, userCtx)
 *     stunCbFunc       -  user provided callback function used by turn to
 * signal the result of an allocation or channel bind etc...
 *     stunCbData       -  user provided callback turn data. turn writes to this
 * data area.
 *
 *     returns          -  Turn instance/context. Application should store this
 * in further calls to TurnClient_StartChannelBindReq(),
 * TurnClient_HandleIncResp().
 */
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
                                DiscussData*           discussData);        /*
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *nullptr
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *if
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *no
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *malicedata
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *should
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *be
                                                                             *
                                                                             *
                                                                             *
                                                                             *
                                                                             *sent.
                                                                             **/

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
                          DiscussData*           discussData);          /*NULL
                                                                         * if
                                                                         *
                                                                         *
                                                                         *
                                                                         *
                                                                         *none*/

/*
 * This function must be called by the application every N msec. N must be same
 * as in StunClientBind_Init(instances, N)
 */
void
StunClient_HandleTick(STUN_CLIENT_DATA* clientData,
                      uint32_t          TimerResMsec);

/*
 *  msg           - Decoded STUN message.
 *  srcAddr       - Source adress in format  "a.b.c.d:port"
 *
 */
void
StunClient_HandleIncResp(STUN_CLIENT_DATA*      clientData,
                         const StunMessage*     msg,
                         const struct sockaddr* srcAddr);


void
StunClient_HandleICMP(STUN_CLIENT_DATA*      clientData,
                      const struct sockaddr* srcAddr,
                      uint32_t               ICMPtype);

/*
 * Cancel a transaction with  matching  transaction id
 *      transactionId  - Transaction id.
 * return -  if  transaction found returns ctx/instance
 *        -  if  no instance found with transactionid, returns
 * STUNCLIENT_CTX_UNKNOWN
 */
int
StunClient_cancelBindingTransaction(STUN_CLIENT_DATA* clientData,
                                    StunMsgId         transactionId);


/********* Server handling: send STUN BIND RESP *************/
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
                                       DiscussData*           discussData);

/********** Server handling:  incoming STUN BIND REQ **********/
bool
StunServer_HandleStunIncomingBindReqMsg(STUN_CLIENT_DATA*       clientData,
                                        STUN_INCOMING_REQ_DATA* pReq,
                                        const StunMessage*      stunMsg,
                                        bool                    fromRelay);

void
StunClient_clearStats(STUN_CLIENT_DATA* clientData);
void
StunClient_dumpStats(STUN_CLIENT_DATA*  clientData,
                     STUN_INFO_FUNC_PTR logPtr,
                     void*              userData);

void
StunPrint(void*              userData,
          STUN_INFO_FUNC_PTR Log_cb,
          StunInfoCategory_T category,
          const char*        fmt,
          ...);


#ifdef __cplusplus
}
#endif

#endif /* STUNCLIENT_H */

/*
 *  See License file
 */
#ifndef TURNCLIENT_H
#define TURNCLIENT_H


//#include <string.h>
#include <netinet/in.h>

#include "stunlib.h"   /* stun enc/dec and msg formats*/

#ifdef __cplusplus
extern "C" {
#endif


enum {
  TURN_DFLT_PORT            = 3478,
  TURN_MAX_PERMISSION_PEERS =   12   /* max. number of  Peers in a
                                      *createPermissionRequest */
};


/* forward declarations */
struct TURN_INSTANCE_DATA;
typedef struct TURN_INSTANCE_DATA TURN_INSTANCE_DATA;


/* Result of  Turn  protocol, returned in callback */
typedef enum
{
  TurnResult_Empty,                         /* Used for testing */
  TurnResult_AllocOk,                       /* Turn allocation was successful */
  TurnResult_AllocFail,                     /* Turn Allocation failed */
  TurnResult_AllocFailNoAnswer,             /* Turn Allocation failed - no
                                             *contact with turn server */
  TurnResult_AllocUnauthorised,             /* passwd/username is incorrect */
  TurnResult_CreatePermissionOk,            /* successfull CreatePermission */
  TurnResult_CreatePermissionFail,          /* Failed CreatePermission - no
                                             *contact with turn server */
  TurnResult_CreatePermissionNoAnswer,      /* CreatePermission failed  */
  TurnResult_CreatePermissionQuotaReached,  /* Quouta reached */
  TurnResult_PermissionRefreshFail,         /* Refresh Permission failed  */
  TurnResult_ChanBindOk,                    /* successful Channel Bind */
  TurnResult_ChanBindFail,                  /* Channel Bind failed */
  TurnResult_ChanBindFailNoanswer,          /* Channel bind failed - no contact
                                             *with turn server */
  TurnResult_RefreshFail,                   /* Allocation Refresh failed */
  TurnResult_RefreshFailNoAnswer,           /* Allocation Refresh failed */
  TurnResult_RelayReleaseComplete,          /* Relay has been sucessfully
                                             *released */
  TurnResult_RelayReleaseFailed,            /* Relay released failed */
  TurnResult_InternalError,
  TurnResult_MalformedRespWaitAlloc         /* server problem occurred when
                                             *waiting for alloc resp */
} TurnResult_T;


/*
 * Result of successful Turn allocation (TurnResult_AllocOk) has the following
 *format.
 *     srflxAddr -   Server Reflexive Address/port.  This is source addr/port of
 *the AllocateRequest as seen by the turn server
 *     relAddr   -   Relay Address/Port. As allocated on the  turn server.
 */
typedef struct
{
  struct sockaddr_storage activeTurnServerAddr;
  struct sockaddr_storage srflxAddr;
  struct sockaddr_storage relAddrIPv4;
  struct sockaddr_storage relAddrIPv6;
  uint64_t                token;
} TurnAllocResp;


/* Signalled back to the caller as a parameter in the TURN callback (see TURNCB)
 **/
typedef struct
{
  TurnResult_T turnResult;
  union
  {
    TurnAllocResp AllocResp;
  } TurnResultData;

} TurnCallBackData_T;

/* category of info sent in TURN_INFO_FUNC */
typedef enum
{
  TurnInfoCategory_Info,
  TurnInfoCategory_Error,
  TurnInfoCategory_Trace

} TurnInfoCategory_T;


typedef struct
{
  uint32_t                Retransmits;
  uint32_t                Failures;
  TurnAllocResp           AllocResp;
  bool                    channelBound;
  uint16_t                channelNumber;
  uint32_t                expiry;
  bool                    permissionsInstalled;
  struct sockaddr_storage BoundPeerTrnspAddr;
  struct sockaddr_storage PermPeerTrnspAddr[TURN_MAX_PERMISSION_PEERS];
  uint32_t                numberOfPeers; /* in permission */
}
TurnStats_T;


/* Defines how a user of turn sends data on e.g. socket */
typedef void (* TURN_SEND_FUNC)(const uint8_t*         buffer,      /* ptr to
                                                                     *buffer to
                                                                     *send */
                                size_t                 bufLen,      /* length of
                                                                     *send
                                                                     *buffer */
                                const struct sockaddr* dstAddr,     /* Optional,
                                                                     *if
                                                                     *connected
                                                                     *to socket
                                                                     **/
                                void*                  userCtx);    /* context -
                                                                     *e.g.
                                                                     *socket
                                                                     *handle */


/* Signalling back to user e.g. result of AllocateResp, ChanBindResp etc...
 *   userCtx        - User provided context, as provided in
 *TurnClient_startAllocateTransaction(userCtx,...)
 *   TurnCbData     - User provided turn callback data. Turn writes status here.
 *e.g. Alloc ok + reflexive + relay address
 */
typedef void (* TURN_CB_FUNC)(void*               userCtx,
                              TurnCallBackData_T* turnCbData);

/* for output of managment info (optional) */
typedef void (* TURN_INFO_FUNC)(void*              userCtx,
                                TurnInfoCategory_T category,
                                char*              ErrStr);


/*
 *  Initiate a Turn Allocate Transaction
 *     instance         -  instance data
 *     tickMsec         -  Tells turnclient how often TurnClient_HandleTick() is
 *called.
 *     funcPtr          -  Will be called by Turn when it outputs management
 *info and trace.
 *     SwVerStr         -  Software version string to be sent in TURN Requests*
 *     turnServerAddr   -  Address of TURN server
 *     userName         -  \0 terminated string. Max
 *STUN_MSG_MAX_USERNAME_LENGTH-1 chars.
 *     password         -  \0 terminated string. Max
 *STUN_MSG_MAX_PASSWORD_LENGTH-1 chars.
 *     ai_family         -  requested address family (AF_INET or AF_INET6)
 *     sendFunc         -  function used to send STUN packet.
 *send(sockhandle,buff, len, turnServerAddr, userCtx)
 *     turnCbFunc       -  user provided callback function used by turn to
 *signal the result of an allocation or channel bind etc...
 *     TurnCbData       -  user provided callback turn data. turn writes to this
 *data area.
 *     evenPortAndReserve - reserve an even port n and next port n+1
 *     reservationToken -  request a previously reserved port for the allocation
 *     returns          -  Turn instance/context. Application should store this
 *in further calls to TurnClient_StartChannelBindReq(),
 *TurnClient_HandleIncResp().
 */
bool
TurnClient_StartAllocateTransaction(TURN_INSTANCE_DATA**   instp,
                                    uint32_t               tickMsec,
                                    TURN_INFO_FUNC         funcPtr,
                                    const char*            SwVerStr,
                                    void*                  userCtx,
                                    const struct sockaddr* turnServerAddr,
                                    const char*            userName,
                                    const char*            password,
                                    int                    ai_family,
                                    TURN_SEND_FUNC         sendFunc,
                                    TURN_CB_FUNC           turnCbFunc,
                                    bool                   evenPortAndReserve,
                                    uint64_t               reservationToken);

/*
 * Bind Channel Number to peer transport address.
 *     instance         -  instance pointer
 *     channelNumber    - Valid range is  0x4000-0xFFFE
 *     peerTrnspAddr    - Peer address
 *
 */
bool
TurnClient_StartChannelBindReq(TURN_INSTANCE_DATA*    inst,
                               uint16_t               channelNumber,
                               const struct sockaddr* peerTrnspAddr);

/*
 * Create a permission in turn server.  i.e. CreatePermission(List of
 *RemotePeers).
 * This will enable the turn server to route DataIndicatins from the Remote
 *peers.
 *
 *     instance         -  instance pointer
 *     noOfPeers        - Number of peer addresses in peerTrnspAddrStr string
 *                        array
 *     peerTrnspAddrStr - Pointer to array of strings in format "a.b.c.d:port".
 *Note - Port is not used in create permission.
 *
 */
bool
TurnClient_StartCreatePermissionReq(TURN_INSTANCE_DATA*    inst,
                                    uint32_t               noOfPeers,
                                    const struct sockaddr* peerTrnspAddr[]);

/*
 * This function must be called by the application every N msec.
 * N must have same value as in call to TurnClient_StartAllocateTransaction()
 *  instance         -  instance pointer
 */
void
TurnClient_HandleTick(TURN_INSTANCE_DATA* inst);

/* TURN will be active for the duration of the Call Session.
 * TurnClient_Deallocate() must be called when the session terminates
 *  inst         -  instance pointer
 */
void
TurnClient_Deallocate(TURN_INSTANCE_DATA* inst);


bool
TurnClient_HasBoundChannel(TURN_INSTANCE_DATA* inst);

void
TurnClient_free(TURN_INSTANCE_DATA* inst);


/* send packet (via turnserver) to peer
 *
 *  instance         -  instance pointer
 *  buf       - buffer
 *  bufSize   - sizeof buffer
 *  offset    - offset of  payload in buffer
 *  dataLen   - length of payload
 *  peerAddr  - destination
 */
bool
TurnClient_SendPacket(TURN_INSTANCE_DATA*    inst,
                      uint8_t*               buf,
                      size_t                 bufSize,
                      uint32_t               dataLen,
                      uint32_t               offset,
                      const struct sockaddr* peerAddr,
                      bool needChannelDataPadding);

/*
 * handle received turn packets
 *
 *  inst      -  instance pointer
 *  media     - ptr to media inclusive of  turn/stun header
 *  length    - IN : length of media inclusive of any turn/stun header
 *            - OUT: length of media after removal of any turn/stun header
 *  peerAddr  - OUT: src of media if packet is a data packet
 *  reservationToken  - OUT: token to be use for rtcp allocation
 */
bool
TurnClient_ReceivePacket(TURN_INSTANCE_DATA* inst,
                         uint8_t*            media,
                         size_t*             length,
                         struct sockaddr*    peerAddr,
                         size_t              addrSize,
                         uint64_t*           reservationToken);

bool
TurnClient_HandleIncResp(TURN_INSTANCE_DATA* inst,
                         StunMessage*        msg,
                         uint8_t*            buf);

bool TurnClient_hasBeenRedirected(TURN_INSTANCE_DATA *pInst);
const struct sockaddr * TurnClient_getRedirectedServerAddr(TURN_INSTANCE_DATA *pInst);



/* management */
void
TurnClientGetStats(const TURN_INSTANCE_DATA* inst,
                   TurnStats_T*              Stats);
const char*
TurnResultToStr(TurnResult_T res);


#ifdef __cplusplus
}
#endif

#endif /* TURNCLIENT_H */

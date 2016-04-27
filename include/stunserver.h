

#ifndef STUNSERVER_H
#define STUNSERVER_H


#include "stunlib.h"   /* stun enc/dec and msg formats*/
#include <stdint.h>
#include "sockaddr_util.h"
#include "stunclient.h"
#include "stun_intern.h"

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

  bool
    CreateConnectivityBindingResp(StunMessage *           stunMsg,
                                  StunMsgId transactionId,
                                  const struct sockaddr* mappedSockAddr,
                                  uint8_t reqTrnspCnt,
                                  uint8_t respTrnspCnt,
                                  uint16_t response,
                                  uint32_t responseCode,
                                  DiscussData *           discussData);
/********* Server handling: send STUN BIND RESP *************/
  bool
    StunServer_SendConnectivityBindingResp(STUN_CLIENT_DATA *      clientData,
                                           int32_t globalSocketId,
                                           StunMsgId transactionId,
                                           const char*            password,
                                           const struct sockaddr* mappedAddr,
                                           const struct sockaddr* dstAddr,
                                           uint8_t reqTrnspCnt,
                                           uint8_t respTrnspCnt,
                                           void*                  userData,
                                           STUN_SENDFUNC sendFunc,
                                           int proto,
                                           bool useRelay,
                                           uint32_t responseCode,
                                           DiscussData *           discussData);

/********** Server handling:  incoming STUN BIND REQ **********/
  bool
    StunServer_HandleStunIncomingBindReqMsg(STUN_CLIENT_DATA *       clientData,
                                            STUN_INCOMING_REQ_DATA * pReq,
                                            const StunMessage *      stunMsg,
                                            bool fromRelay);
#endif

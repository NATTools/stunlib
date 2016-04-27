#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "stunserver.h"
#include "sockaddr_util.h"
#include "test_utils.h"

#define  MAX_INSTANCES  50
#define  TEST_THREAD_CTX 1

#define  TEST_IPv4_ADDR
#define  TEST_IPv4_PORT
#define  TEST_IPv6_ADDR

static StunMsgId               LastTransId;
static struct sockaddr_storage LastAddress;

StunResult_T stunResult;

struct sockaddr_storage stunServerAddr;
struct sockaddr_storage mappedAddr;

DiscussData discussData;

STUN_CLIENT_DATA* stunInstance;
#define STUN_TICK_INTERVAL_MS 50

const char passwd[] ="testtest";

static void
SendRawStun(void*                  ctx,
            int                    sockfd,
            const uint8_t*         buf,
            int                    len,
            const struct sockaddr* addr,
            int                    proto,
            bool                   useRelay,
            uint8_t                ttl)
{
  (void) ctx;
  (void) sockfd;
  (void) len;
  (void) proto;
  (void) useRelay;
  (void) ttl;
  char addr_str[SOCKADDR_MAX_STRLEN];
  /* find the transaction id  so we can use this in the simulated resp */

  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct sockaddr*)&LastAddress, addr );

  sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true);

  /* printf("Sendto: '%s'\n", addr_str); */

}


CTEST(stunserver, Encode_decode)
{
  StunMessage            stunMsg;
  StunMessage       stunResponse;
  StunMsgId              stunId;

  uint8_t stunBuff[STUN_MAX_PACKET_SIZE];
  stunlib_createId(&stunId);

  sockaddr_initFromString( (struct sockaddr*)&mappedAddr,
                           "193.200.93.152:3478" );
  CreateConnectivityBindingResp(&stunMsg,
                                stunId,
                                (struct sockaddr *)&mappedAddr,
                                1,
                                1,
                                STUN_MSG_BindResponseMsg,
                                200,
                                NULL);

  int len = stunlib_encodeMessage(&stunMsg,
                                  (uint8_t*)stunBuff,
                                  STUN_MAX_PACKET_SIZE,
                                  (unsigned char *) passwd,
                                  strlen(passwd),
                              NULL);
 ASSERT_TRUE(len == 72);

 ASSERT_TRUE( stunlib_DecodeMessage(stunBuff, len,
                                     &stunResponse,
                                    NULL, NULL /*stdout for debug*/));

}

CTEST(stunserver, HandleReq_Valid)
{
  STUN_INCOMING_REQ_DATA pReq;
  StunMessage            stunMsg;
  stunMsg.hasUsername        = true;
  stunMsg.username.sizeValue = 10;
  strncpy(stunMsg.username.value, "testPerson", stunMsg.username.sizeValue);
  stunMsg.username.value[stunMsg.username.sizeValue] = '\0';
  stunMsg.hasPriority                                = true;
  stunMsg.priority.value                             = 1;

  bool fromRelay = false;

  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );

  char ufrag[STUN_MAX_STRING] = "testPerson";
  ASSERT_FALSE( strcmp(pReq.ufrag, ufrag) == 0);

  fromRelay = true;
  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );
}

CTEST(stunserver, HandleReq_InValid)
{
  STUN_INCOMING_REQ_DATA pReq;
  StunMessage            stunMsg;
  stunMsg.hasUsername        = false;
  stunMsg.username.sizeValue = 10;
  strncpy(stunMsg.username.value, "testPerson", stunMsg.username.sizeValue);
  stunMsg.username.value[stunMsg.username.sizeValue] = '\0';
  stunMsg.hasPriority                                = true;
  stunMsg.priority.value                             = 1;

  bool fromRelay = false;

  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );

  fromRelay           = true;
  stunMsg.hasUsername = true;
  stunMsg.hasPriority = false;
  ASSERT_FALSE( StunServer_HandleStunIncomingBindReqMsg(stunInstance,
                                                        &pReq,
                                                        &stunMsg,
                                                        fromRelay) );
}

CTEST(stunserver, SendResp_Valid)
{
  bool                    useRelay = false;
  struct sockaddr_storage mappedAddr,servAddr;
  sockaddr_initFromString( (struct sockaddr*)&servAddr,
                           "193.200.93.152:3478" );

  StunClient_Alloc(&stunInstance);
  ASSERT_FALSE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                       0,  /* sockhandle */
                                                       LastTransId,
                                                       "pem",
                                                       (struct sockaddr*)&
                                                       mappedAddr,
                                                       (struct sockaddr*)&
                                                       servAddr,
                                                       0,
                                                       0,
                                                       NULL,
                                                       SendRawStun,
                                                       0,
                                                       useRelay,
                                                       0,  /* responseCode */
                                                       NULL) );
  sockaddr_initFromString( (struct sockaddr*)&mappedAddr,
                           "193.200.93.152:3478" );
  ASSERT_TRUE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                      0,
                                                      LastTransId,
                                                      "pem",
                                                      (struct sockaddr*)&
                                                      mappedAddr,
                                                      (struct sockaddr*)&
                                                      servAddr,
                                                      2,
                                                      3,
                                                      NULL,
                                                      SendRawStun,
                                                      0,
                                                      useRelay,
                                                      0,
                                                      NULL) );

}

CTEST(stunserver, SendResp_Valid_IPv6)
{
  bool                    useRelay = false;
  struct sockaddr_storage mappedAddr,servAddr;
  sockaddr_reset( &servAddr);
  sockaddr_reset( &mappedAddr);

  sockaddr_initFromString( (struct sockaddr*)&servAddr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );

  StunClient_Alloc(&stunInstance);
  ASSERT_FALSE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                       0,  /* sockhandle */
                                                       LastTransId,
                                                       "pem",
                                                       (struct sockaddr*)&
                                                       mappedAddr,
                                                       (struct sockaddr*)&
                                                       servAddr,
                                                       0,
                                                       0,
                                                       NULL,
                                                       SendRawStun,
                                                       0,
                                                       useRelay,
                                                       0,  /* responseCode */
                                                       NULL) );
  sockaddr_initFromString( (struct sockaddr*)&mappedAddr,
                           "[2a02:fe0:c410:cb31:e4d:e93f:fecb:bf6b]:1234" );
  ASSERT_TRUE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                      0,
                                                      LastTransId,
                                                      "pem",
                                                      (struct sockaddr*)&
                                                      mappedAddr,
                                                      (struct sockaddr*)&
                                                      servAddr,
                                                      0,
                                                      0,
                                                      NULL,
                                                      SendRawStun,
                                                      0,
                                                      useRelay,
                                                      0,
                                                      NULL) );

}


CTEST(stunserver, SendDiscussResp_Valid)
{
  bool useRelay = false;

  discussData.streamType    = 0x004;
  discussData.interactivity = 0x01;

  discussData.networkStatus_flags            = 0;
  discussData.networkStatus_nodeCnt          = 0;
  discussData.networkStatus_tbd              = 0;
  discussData.networkStatus_upMaxBandwidth   = 0;
  discussData.networkStatus_downMaxBandwidth = 0;

  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  StunClient_Alloc(&stunInstance);
  ASSERT_TRUE( StunServer_SendConnectivityBindingResp(stunInstance,
                                                       0,  /* sockhandle */
                                                       LastTransId,
                                                       "pem",
                                                       (struct sockaddr*)&
                                                       stunServerAddr,
                                                       (struct sockaddr*)&
                                                       stunServerAddr,
                                                       2,
                                                       2,
                                                       NULL,
                                                       SendRawStun,
                                                       0,
                                                       useRelay,
                                                       0,  /* responseCode */
                                                       &discussData) );

}

CTEST(stunserver, SendResp_InValid)
{

}

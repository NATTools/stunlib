#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_utils.h"
#include "stunclient.h"
#include "stuntrace.h"
#include "sockaddr_util.h"


static StunMsgId               LastTransId;
static struct sockaddr_storage LastAddress;
static struct sockaddr_storage LastHopAddr;
static int                     LastTTL;
static bool                    Done;
static bool                    EndOfTrace;


static void
sendPacket(void*                  ctx,
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
  char addr_str[SOCKADDR_MAX_STRLEN];
  /* find the transaction id  so we can use this in the simulated resp */

  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct sockaddr*)&LastAddress, addr );

  sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true);

  LastTTL = ttl;
  /* printf("Sendto: '%s'\n", addr_str); */

}

void
StunTraceCallBack(void*                    userCtx,
                  StunTraceCallBackData_T* data)
{
  (void) userCtx;
  if (data->nodeAddr == NULL)
  {
    printf(" * \n");
  }
  else
  {
    sockaddr_copy( (struct sockaddr*)&LastHopAddr, data->nodeAddr );
  }
  Done       = data->done;
  EndOfTrace = data->traceEnd;

}


CTEST(stuntrace, run_IPv4)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  struct sockaddr_storage localAddr, remoteAddr, hop1Addr, hop2Addr;
  int                     sockfd = 4;

  sockaddr_initFromString( (struct sockaddr*)&remoteAddr,
                           "193.200.93.152:45674" );

  sockaddr_initFromString( (struct sockaddr*)&localAddr,
                           "192.168.1.34:45674" );

  StunClient_Alloc(&clientData);


  int len = StunTrace_startTrace(clientData,
                                 &someData,
                                 (const struct sockaddr*)&remoteAddr,
                                 (const struct sockaddr*)&localAddr,
                                 sockfd,
                                 "test",
                                 "tset",
                                 1,
                                 StunTraceCallBack,
                                 sendPacket);
  ASSERT_TRUE(len == 68);
  ASSERT_TRUE(LastTTL == 1);

  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( LastTTL == 2);

  sockaddr_initFromString( (struct sockaddr*)&hop2Addr,
                           "193.200.93.152:45674" );

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop2Addr,
                        3);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop2Addr ) );
  ASSERT_TRUE( Done);
  ASSERT_TRUE( EndOfTrace);

}

CTEST(stuntrace, recurring_IPv4)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  struct sockaddr_storage localAddr, remoteAddr, hop1Addr, hop2Addr;
  int                     sockfd = 4;

  sockaddr_initFromString( (struct sockaddr*)&remoteAddr,
                           "193.200.93.152:45674" );

  sockaddr_initFromString( (struct sockaddr*)&localAddr,
                           "192.168.1.34:45674" );

  StunClient_Alloc(&clientData);


  int len = StunTrace_startTrace(clientData,
                                 &someData,
                                 (const struct sockaddr*)&remoteAddr,
                                 (const struct sockaddr*)&localAddr,
                                 sockfd,
                                 "test",
                                 "tset",
                                 2,
                                 StunTraceCallBack,
                                 sendPacket);
  ASSERT_TRUE(len == 68);
  ASSERT_TRUE(LastTTL == 1);

  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( LastTTL == 2);

  sockaddr_initFromString( (struct sockaddr*)&hop2Addr,
                           "193.200.93.152:45674" );

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop2Addr,
                        3);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop2Addr ) );
  ASSERT_FALSE(Done);
  ASSERT_TRUE(EndOfTrace);

  ASSERT_TRUE(LastTTL == 1);
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  ASSERT_TRUE(LastTTL == 2);

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop2Addr,
                        3);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop2Addr ) );

  ASSERT_TRUE(Done);
  ASSERT_TRUE(EndOfTrace);
}

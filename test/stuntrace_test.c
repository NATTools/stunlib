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
static StunMsgId               LastTransId;
static bool                    Done;
static bool                    EndOfTrace;

static const uint8_t StunCookie[]   = STUN_MAGIC_COOKIE_ARRAY;
const uint64_t       test_addr_ipv4 = 1009527574; /* "60.44.43.22"); */
const uint32_t       test_port_ipv4 = 43000;


void
stundbg(void*              ctx,
        StunInfoCategory_T category,
        char*              errStr)
{
  (void) category;
  (void) ctx;
  (void) errStr;
/*  strncpy(logStr, errStr, sizeof logStr); */
/*  printf("%s\n", errStr); */
}

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
  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct sockaddr*)&LastAddress, addr );

  sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true);

  LastTTL = ttl;
}

void
StunTraceCallBack(void*                    userCtx,
                  StunTraceCallBackData_T* data)
{
  (void) userCtx;
  if (data->nodeAddr == NULL)
  {
    sockaddr_copy( (struct sockaddr*)&LastHopAddr, data->nodeAddr );
  }
  else
  {
    sockaddr_copy( (struct sockaddr*)&LastHopAddr, data->nodeAddr );
  }
  Done       = data->done;
  EndOfTrace = data->traceEnd;

}
CTEST(stuntrace, null_ptr)
{
  int               someData   = 3;
  STUN_CLIENT_DATA* clientData = NULL;

  struct sockaddr_storage localAddr, remoteAddr;
  int                     sockfd = 4;

  sockaddr_initFromString( (struct sockaddr*)&remoteAddr,
                           "193.200.93.152:45674" );

  sockaddr_initFromString( (struct sockaddr*)&localAddr,
                           "192.168.1.34:45674" );




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

  ASSERT_TRUE(len == 0);

  StunClient_Alloc(&clientData);

  len = StunTrace_startTrace(clientData,
                             &someData,
                             (const struct sockaddr*)&remoteAddr,
                             (const struct sockaddr*)&localAddr,
                             sockfd,
                             "test",
                             "tset",
                             1,
                             StunTraceCallBack,
                             NULL);
  ASSERT_TRUE(len == 0);

  len = StunTrace_startTrace(clientData,
                             &someData,
                             NULL,
                             (const struct sockaddr*)&localAddr,
                             sockfd,
                             "test",
                             "tset",
                             1,
                             StunTraceCallBack,
                             sendPacket);
  ASSERT_TRUE(len == 0);
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

  /* First alive probe */
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);


  StunClient_HandleICMP(NULL,
                        (struct sockaddr*)&remoteAddr,
                        3);

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&remoteAddr,
                        3);
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  /* First hop.. */
  ASSERT_TRUE(LastTTL == 1);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
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

CTEST(stuntrace, run_IPv4_unhandled_ICMP)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  Done       = false;
  EndOfTrace = false;
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
  /* First alive probe */
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);


  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&remoteAddr,
                        3);
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  /* First hop.. */
  ASSERT_TRUE(LastTTL == 1);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( LastTTL == 2);
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        5);

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
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&remoteAddr,
                        3);

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

  ASSERT_TRUE( Done);
  ASSERT_TRUE( EndOfTrace);
}

CTEST(stuntrace, no_answer_IPv4)
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
  ASSERT_TRUE(len != 0);
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&remoteAddr,
                        3);

  /* HOP 1 Answer */
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
  /* HOP 2 No Answer */
  ASSERT_TRUE( LastTTL == 2);


  ASSERT_TRUE( LastTTL == 2);
  /*Timeout is roughtly 160*50 ms*/
  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  /* HOP 3 Answer */
  ASSERT_TRUE(LastTTL == 3);

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



CTEST(stuntrace, no_answer_recurring_IPv4)
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
  ASSERT_TRUE(len != 0);

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&remoteAddr,
                        3);

  /* HOP 1 Answer */
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
  /* HOP 2 No Answer */
  ASSERT_TRUE( LastTTL == 2);


  ASSERT_TRUE( LastTTL == 2);
  /*Timeout is roughtly 160*50 ms*/
  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_FALSE(Done);
  ASSERT_FALSE(EndOfTrace);

  /* HOP 3 Answer */
  ASSERT_TRUE(LastTTL == 3);

  sockaddr_initFromString( (struct sockaddr*)&hop2Addr,
                           "193.200.93.152:45674" );

  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop2Addr,
                        3);

  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop2Addr ) );

  ASSERT_FALSE(Done);
  ASSERT_TRUE(EndOfTrace);

  /* HOP 1 Answer */
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


  /* HOP 3 Answer */
  ASSERT_TRUE(LastTTL == 3);

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

CTEST(stuntrace, run_IPv4_Stunresp)
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
  StunClient_RegisterLogger(clientData,
                            stundbg,
                            NULL);
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
  /* First alive probe */
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType                = STUN_MSG_BindResponseMsg;
  m.hasXorMappedAddress           = true;
  m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
  m.xorMappedAddress.addr.v4.addr = test_addr_ipv4;
  m.xorMappedAddress.addr.v4.port = test_port_ipv4;
  StunClient_HandleIncResp(clientData,
                           &m,
                           NULL);
  /* First hop.. */
  ASSERT_TRUE(LastTTL == 40);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_FALSE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                                (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE(LastTTL == 40);

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

CTEST(stuntrace, run_IPv4_Stunresp_dead)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  struct sockaddr_storage localAddr, remoteAddr, hop1Addr;
  int                     sockfd = 4;

  sockaddr_initFromString( (struct sockaddr*)&remoteAddr,
                           "193.200.93.152:45674" );

  sockaddr_initFromString( (struct sockaddr*)&localAddr,
                           "192.168.1.34:45674" );

  StunClient_Alloc(&clientData);


  StunTrace_startTrace(clientData,
                       &someData,
                       (const struct sockaddr*)&remoteAddr,
                       (const struct sockaddr*)&localAddr,
                       sockfd,
                       "test",
                       "tset",
                       1,
                       StunTraceCallBack,
                       sendPacket);

  /*Timeout is roughtly 160*50 ms*/
  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }

  /* First hop.. */
  ASSERT_TRUE(LastTTL == 1);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( LastTTL == 2);

  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_TRUE(LastTTL == 3);

  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_TRUE(LastTTL == 4);

  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_TRUE(LastTTL == 5);

  for (int i = 0; i < 160; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }
  ASSERT_TRUE(LastTTL == 5);

  ASSERT_TRUE(Done);
  ASSERT_TRUE(EndOfTrace);
}


CTEST(stuntrace, run_IPv4_Stunresp_end)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  struct sockaddr_storage localAddr, remoteAddr, hop1Addr;
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
  /* First alive probe */
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType                = STUN_MSG_BindResponseMsg;
  m.hasXorMappedAddress           = true;
  m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
  m.xorMappedAddress.addr.v4.addr = test_addr_ipv4;
  m.xorMappedAddress.addr.v4.port = test_port_ipv4;

  StunClient_HandleIncResp(clientData,
                           &m,
                           NULL);

  /* First hop.. */
  ASSERT_TRUE(LastTTL == 40);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( LastTTL == 40);

  memcpy(&m.msgHdr.id, &LastTransId, STUN_MSG_ID_SIZE);
  StunClient_HandleIncResp(clientData,
                           &m,
                           (struct sockaddr*)&remoteAddr);

  ASSERT_TRUE(Done);
  ASSERT_TRUE(EndOfTrace);

}

CTEST(stuntrace, run_IPv4_Stunresp_max_ttl)
{
  int               someData = 3;
  STUN_CLIENT_DATA* clientData;

  struct sockaddr_storage localAddr, remoteAddr, hop1Addr;
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
  /* First alive probe */
  ASSERT_TRUE(len != 0);
  ASSERT_TRUE(LastTTL == 40);
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  m.msgHdr.msgType                = STUN_MSG_BindResponseMsg;
  m.hasXorMappedAddress           = true;
  m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
  m.xorMappedAddress.addr.v4.addr = test_addr_ipv4;
  m.xorMappedAddress.addr.v4.port = test_port_ipv4;

  StunClient_HandleIncResp(clientData,
                           &m,
                           NULL);

  /*Timeout is roughtly 160*50 ms*/
  for (int i = 0; i < 160 * 38; i++)
  {
    StunClient_HandleTick(clientData, 50);
  }

  /* First hop.. */
  ASSERT_TRUE(LastTTL == 40);
  sockaddr_initFromString( (struct sockaddr*)&hop1Addr,
                           "192.168.1.1:45674" );
  StunClient_HandleICMP(clientData,
                        (struct sockaddr*)&hop1Addr,
                        11);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastHopAddr,
                               (struct sockaddr*)&hop1Addr ) );

  ASSERT_TRUE( Done);
  ASSERT_TRUE( EndOfTrace);

}

CTEST(stuntrace, isDstUnreachable)
{
  ASSERT_TRUE( isDstUnreachable(3, AF_INET) );

  ASSERT_FALSE( isDstUnreachable(5,AF_INET) );

  ASSERT_TRUE( isDstUnreachable(1, AF_INET6) );
  ASSERT_FALSE( isDstUnreachable(3, AF_INET6) );

}

CTEST(stuntrace, isTimeExceeded)
{
  ASSERT_TRUE( isTimeExceeded(11, AF_INET) );
  ASSERT_FALSE( isTimeExceeded(3, AF_INET) );
  ASSERT_FALSE( isTimeExceeded(5, AF_INET) );

  ASSERT_TRUE( isTimeExceeded(3, AF_INET6) );
  ASSERT_FALSE( isTimeExceeded(11, AF_INET6) );
  ASSERT_FALSE( isTimeExceeded(5, AF_INET6) );

}

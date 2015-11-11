#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_utils.h"
#include "stunclient.h"
#include "sockaddr_util.h"



#define  MAX_INSTANCES  50
#define  TEST_THREAD_CTX 1

#define  TEST_IPv4_ADDR
#define  TEST_IPv4_PORT
#define  TEST_IPv6_ADDR

typedef  struct
{
  uint32_t a;
  uint8_t  b;
}
AppCtx_T;

static AppCtx_T AppCtx[MAX_INSTANCES];
static AppCtx_T CurrAppCtx;

static StunMsgId               LastTransId;
static struct sockaddr_storage LastAddress;

uint8_t test_addr_ipv6[16] =
{0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x1, 0x22, 0x21, 0x26, 0x18, 0xff, 0xfe,
 0x92, 0x6d, 0x53};
const uint64_t test_addr_ipv4 = 1009527574; /* "60.44.43.22"); */
const uint32_t test_port_ipv4 = 43000;

static const uint8_t StunCookie[] = STUN_MAGIC_COOKIE_ARRAY;

static bool             runningAsIPv6;
StunResult_T            stunResult;
STUN_CLIENT_DATA*       stunInstance;
struct sockaddr_storage stunServerAddr;
DiscussData             discussData;

CTEST_DATA(data)
{
  int a;



};
#define STUN_TICK_INTERVAL_MS 50


static void
StunStatusCallBack(void*               ctx,
                   StunCallBackData_T* retData)
{
  (void)ctx;
  stunResult = retData->stunResult;
  /* printf("Got STUN status callback\n");// (Result (%i)\n",
   * retData->stunResult); */
}

/* Callback for management info  */
static void
PrintStunInfo(void*              userData,
              StunInfoCategory_T category,
              char*              InfoStr)
{
  (void)userData;
  (void)category;
  (void)InfoStr;
  /* fprintf(stderr, "%s\n", ErrStr); */
}

static void
SendRawStun(int                    sockfd,
            const uint8_t*         buf,
            int                    len,
            const struct sockaddr* addr,
            bool                   useRelay,
            uint8_t                ttl)
{
  (void) sockfd;
  (void) len;
  (void) useRelay;
  (void) ttl;
  char addr_str[SOCKADDR_MAX_STRLEN];
  /* find the transaction id  so we can use this in the simulated resp */

  memcpy(&LastTransId, &buf[8], STUN_MSG_ID_SIZE);

  sockaddr_copy( (struct sockaddr*)&LastAddress, addr );

  sockaddr_toString(addr, addr_str, SOCKADDR_MAX_STRLEN, true);

  /* printf("Sendto: '%s'\n", addr_str); */

}

static int
StartBindTransaction(int n)
{
  n = 0;   /* hardcoded for now...  TODO: fixme */

  CurrAppCtx.a =  AppCtx[n].a = 100 + n;
  CurrAppCtx.b =  AppCtx[n].b = 200 + n;


  /* kick off stun */
  return StunClient_startBindTransaction(stunInstance,
                                         NULL,
                                         (struct sockaddr*)&stunServerAddr,
                                         NULL,
                                         false,
                                         "pem",
                                         "pem",
                                         0,             /* uint32_t 1845494271
                                                         * (priority) */
                                         false,
                                         false,
                                         0,             /* uint64_t
                                                         * 0x932FF9B151263B36LL
                                                         * (tieBreaker) */
                                         LastTransId,
                                         0,             /* socket */
                                         SendRawStun,   /* send func */
                                         StunStatusCallBack,
                                         NULL);
}


static int
StartDiscussBindTransaction(int n)
{
  n = 0;   /* hardcoded for now...  TODO: fixme */

  CurrAppCtx.a =  AppCtx[n].a = 100 + n;
  CurrAppCtx.b =  AppCtx[n].b = 200 + n;

  discussData.streamType    = 0x004;
  discussData.interactivity = 0x01;

  discussData.networkStatus_flags            = 0;
  discussData.networkStatus_nodeCnt          = 0;
  discussData.networkStatus_tbd              = 0;
  discussData.networkStatus_upMaxBandwidth   = 0;
  discussData.networkStatus_downMaxBandwidth = 0;



  /* kick off stun */
  return StunClient_startBindTransaction(stunInstance,
                                         NULL,
                                         (struct sockaddr*)&stunServerAddr,
                                         NULL,
                                         false,
                                         "pem",
                                         "pem",
                                         0,             /* uint32_t 1845494271
                                                         * (priority) */
                                         false,
                                         false,
                                         0,             /* uint64_t
                                                         * 0x932FF9B151263B36LL
                                                         * (tieBreaker) */
                                         LastTransId,
                                         0,             /* socket */
                                         SendRawStun,   /* send func */
                                         StunStatusCallBack,
                                         &discussData);
}

static void
SimBindSuccessResp(bool IPv6,
                   bool success)
{
  StunMessage m;
  memset( &m, 0, sizeof(m) );
  memcpy( &m.msgHdr.id,     &LastTransId, STUN_MSG_ID_SIZE);
  memcpy( &m.msgHdr.cookie, StunCookie,   sizeof(m.msgHdr.cookie) );
  if (success)
  {
    m.msgHdr.msgType = STUN_MSG_BindResponseMsg;
  }
  else
  {
    m.msgHdr.msgType = STUN_MSG_BindErrorResponseMsg;
  }

  m.hasXorMappedAddress = true;

  if (IPv6)
  {
    stunlib_setIP6Address(&m.xorMappedAddress, test_addr_ipv6, 0x4200);

  }
  else
  {
    m.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
    m.xorMappedAddress.addr.v4.addr = test_addr_ipv4;
    m.xorMappedAddress.addr.v4.port = test_port_ipv4;
  }

  StunClient_HandleIncResp(stunInstance, &m, NULL);

}

CTEST_SETUP(data)
{
  data->a       = 1;
  stunResult    = StunResult_Empty;
  runningAsIPv6 = false;
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  StunClient_Alloc(&stunInstance);

}

CTEST_TEARDOWN(data)
{
  data->a    = 0;
  stunResult = StunResult_Empty;
  StunClient_free(stunInstance);
}



/* static void setupIPv6 (void) */
/* { */
/*    stunResult = StunResult_Empty; */
/*    runningAsIPv6 = true; */
/*    sockaddr_initFromString((struct sockaddr*)&stunServerAddr,
 * "[2001:470:dc88:2:226:18ff:fe92:6d53]:3478"); */
/*    StunClient_Alloc(&stunInstance); */
/* } */

/* static void teardownIPv6 (void) */
/* { */
/*    stunResult = StunResult_Empty; */
/*    StunClient_free(stunInstance); */
/* } */


CTEST(stunclient, empty)
{
  ASSERT_TRUE(true);
}

CTEST(stunclient, WaitBindRespNotAut_Timeout)
{
  ASSERT_TRUE(stunResult == StunResult_Empty);
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  StartBindTransaction(0);
  /* 1 Tick */
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  ASSERT_TRUE( stunResult == StunResult_Empty);
  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&LastAddress,
                               (struct sockaddr*)&stunServerAddr ) );
  /* 2 Tick */
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  ASSERT_TRUE(stunResult == StunResult_Empty);

  /* 3 Tick */
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  ASSERT_TRUE(stunResult == StunResult_Empty);

  /* 4 Tick */
  int i = 0;
  for (i = 0; i < 100; i++)
  {
    StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  }

  ASSERT_TRUE(stunResult == StunResult_BindFailNoAnswer);
  StunClient_free(stunInstance);
}

CTEST(stunclient, WaitBindRespNotAut_BindSuccess)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  StartBindTransaction(0);
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);

  SimBindSuccessResp(runningAsIPv6, true);
  ASSERT_TRUE(stunResult == StunResult_BindOk);
  StunClient_free(stunInstance);
}

CTEST(stunclient, WaitBindRespNotAut_BindError)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );
  StartBindTransaction(0);
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);

  SimBindSuccessResp(runningAsIPv6, false);
  ASSERT_TRUE(stunResult == StunResult_BindFail);
  StunClient_free(stunInstance);
}

CTEST(stunclient, CancelTrans_BindResp)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );
  int ctx;
  ctx = StartBindTransaction(0);
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);

  ASSERT_TRUE(StunClient_cancelBindingTransaction(stunInstance,
                                                  LastTransId) == ctx);

  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  SimBindSuccessResp(runningAsIPv6, true);
  StunClient_free(stunInstance);
}

CTEST(stunclient, CancelTrans_BindErrorResp)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  int ctx;
  ctx = StartBindTransaction(0);
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);

  ASSERT_TRUE(StunClient_cancelBindingTransaction(stunInstance,
                                                  LastTransId) == ctx);

  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);
  SimBindSuccessResp(runningAsIPv6, false);
  StunClient_free(stunInstance);
}

CTEST(stunclient, DumpStats)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );

  StunClient_dumpStats(stunInstance, PrintStunInfo, NULL);
  StunClient_free(stunInstance);
}

CTEST(stunclient, Send_Discuss)
{
  StunClient_Alloc(&stunInstance);
  sockaddr_initFromString( (struct sockaddr*)&stunServerAddr,
                           "193.200.93.152:3478" );
  StartDiscussBindTransaction(0);
  StunClient_HandleTick(stunInstance, STUN_TICK_INTERVAL_MS);

  SimBindSuccessResp(runningAsIPv6, true);
  ASSERT_TRUE(stunResult == StunResult_BindOk);
  StunClient_free(stunInstance);
}

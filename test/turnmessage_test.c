#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_utils.h"
#include "stunlib.h"
#include "sockaddr_util.h"


static unsigned char allocate_resp[] =
  "\x01\x03\x00\x5c"
  "\x21\x12\xa4\x42"
  "\x64\x3c\x98\x69"
  "\x00\x01\x00\x00"
  "\x07\x5d\xfe\x0c"
  "\x00\x16\x00\x08"
  "\x00\x01\xf3\x10"
  "\x7c\x4f\xc4\x88"
  "\x00\x0d\x00\x04"
  "\x00\x00\x02\x58"
  "\x00\x20\x00\x08"
  "\x00\x01\x6d\x8a"
  "\x74\xb4\x2c\xa0"
  "\x80\x22\x00\x1d"
  "\x72\x65\x73\x74"
  "\x75\x6e\x64\x20"
  "\x76\x30\x2e\x31"
  "\x2e\x30\x20\x28"
  "\x78\x38\x36\x5f"
  "\x36\x34\x2f\x6c"
  "\x69\x6e\x75\x78"
  "\x29\x00\x00\x00"
  "\x00\x08\x00\x14"
  "\x9d\x89\xb4\x21"
  "\x26\x5c\xe2\x20"
  "\xd0\x45\xc1\x2c"
  "\x98\xbd\xcd\x2f"
  "\xce\xb4\x8f\x50";

static unsigned char requested_addrFamilyReq[] =
  "\x01\x03\x00\x28"
  "\x21\x12\xa4\x42"
  "\x64\x3c\x98\x69"
  "\x00\x01\x00\x00"
  "\x07\x5d\xfe\x0c"
  "\x00\x17\x00\x04"
  "\x01\x00\x00\x00"
  "\x00\x08\x00\x14"
  "\x1c\xea\x86\x3f"
  "\x2e\xc8\x4f\x3d"
  "\xbd\x85\x8c\x41"
  "\x3a\x4a\xe9\xbc"
  "\xd4\xa1\x28\xa6"
  "\x80\x28\x00\x04"
  "\x38\x98\xd0\x62";


static unsigned char requested_addrFamilyReq_IPv6[] =
  "\x01\x03\x00\x28"
  "\x21\x12\xa4\x42"
  "\x64\x3c\x98\x69"
  "\x00\x01\x00\x00"
  "\x07\x5d\xfe\x0c"
  "\x00\x17\x00\x04"
  "\x02\x00\x00\x00"
  "\x00\x08\x00\x14"
  "\xfc\x8f\x30\x45"
  "\x80\x06\x80\x29"
  "\x97\x6b\x5c\x90"
  "\xd2\x19\xc0\xba"
  "\x7c\x37\x6e\xab"
  "\x80\x28\x00\x04"
  "\xd3\x60\x20\xf1";

static char password[] = "pem\0";
static char user[]     = "pem\0";
static char realm[]    = "medianetworkservices.com\0";


static const unsigned char idOctet[] =
  "\x64\x3c\x98\x69"
  "\x00\x01\x00\x00"
  "\x07\x5d\xfe\x0c"
  "\x00\x16";

const char* software_restund = "restund v0.1.0 (x86_64/linux)\0";

CTEST(turnmessage, encode_integrity)
{
  StunMessage stunMsg, decodeStunMsg;

  unsigned char           stunBuf[120];
  struct sockaddr_storage a,b;

  sockaddr_initFromString( (struct sockaddr*)&a,
                           "85.166.136.226:19608" );


  sockaddr_initFromString( (struct sockaddr*)&b,
                           "93.93.96.202:53762" );



  memset( &stunMsg, 0, sizeof(StunMessage) );


  stunMsg.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Relay Address*/
  stunMsg.hasXorRelayAddressIPv4 = true;
  stunlib_setIP4Address( &stunMsg.xorRelayAddressIPv4,
                         htonl( ( (struct sockaddr_in*)&b )->sin_addr.s_addr ),
                         htons( ( (struct sockaddr_in*)&b )->sin_port ) );

  /*Lifetime*/
  stunMsg.hasLifetime    = true;
  stunMsg.lifetime.value = 600;


  /*Mapped Address*/
  stunMsg.hasXorMappedAddress = true;
  stunlib_setIP4Address( &stunMsg.xorMappedAddress,
                         htonl( ( (struct sockaddr_in*)&a )->sin_addr.s_addr ),
                         htons( ( (struct sockaddr_in*)&a )->sin_port ) );




  ASSERT_TRUE( stunlib_addSoftware(&stunMsg, software_restund, '\x20') );


  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );



  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     120,
                                     &decodeStunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                       120,
                                       &decodeStunMsg,
                                       (unsigned char*)password,
                                       sizeof(password) ) );


}


CTEST(turnmessage, decode_integrity)
{

  StunMessage stunMsg;
  int         keyLen = 16;
  char        md5[keyLen];



  stunlib_createMD5Key( (unsigned char*)md5, user, realm, password );

  ASSERT_TRUE( stunlib_DecodeMessage(allocate_resp,
                                     sizeof(allocate_resp),
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity(allocate_resp,
                                      sizeof(allocate_resp),
                                      &stunMsg,
                                      (unsigned char*)md5,
                                      keyLen) );

}


CTEST(turnmessage, encode_requestedAddrFamily)
{
  StunMessage stunMsg;

  unsigned char stunBuf[120];

  memset( &stunMsg, 0, sizeof(StunMessage) );


  stunMsg.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Add RequestedAddrFamily*/
  ASSERT_FALSE( stunlib_addRequestedAddrFamily(&stunMsg, 76) );
  ASSERT_TRUE( stunlib_addRequestedAddrFamily(&stunMsg, AF_INET) );

  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  ASSERT_TRUE(memcmp(stunBuf, requested_addrFamilyReq, 60) == 0);
}


CTEST(turnmessage, encode_requestedAddrFamily_IPv6)
{
  StunMessage stunMsg;

  unsigned char stunBuf[120];

  memset( &stunMsg, 0, sizeof(StunMessage) );


  stunMsg.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Add RequestedAddrFamily*/
  ASSERT_FALSE( stunlib_addRequestedAddrFamily(&stunMsg, 76) );
  ASSERT_TRUE( stunlib_addRequestedAddrFamily(&stunMsg, AF_INET6) );

  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  ASSERT_TRUE(memcmp(stunBuf, requested_addrFamilyReq_IPv6, 60) == 0);
}



CTEST(turnmessage, decode_requestedAddrFamily)
{
  StunMessage stunMsg;

  ASSERT_TRUE( stunlib_DecodeMessage(requested_addrFamilyReq,
                                     60,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE(stunMsg.hasRequestedAddrFamilyIPv4);
  ASSERT_TRUE(stunMsg.requestedAddrFamilyIPv4.family == 0x1);

}



CTEST(turnmessage, decode_requestedAddrFamily_IPv6)
{
  StunMessage stunMsg;

  ASSERT_TRUE( stunlib_DecodeMessage(requested_addrFamilyReq_IPv6,
                                     60,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE(stunMsg.hasRequestedAddrFamilyIPv6);
  ASSERT_TRUE(stunMsg.requestedAddrFamilyIPv6.family == 0x2);

}

CTEST(turnmessage, alternate_server_IPv4)
{
  StunMessage stunMsg;

  unsigned char stunBuf[120];
  char          pad    = ' ';
  uint32_t      mapped = 3221225985U;
  memset( &stunMsg, 0, sizeof(StunMessage) );


  stunMsg.msgHdr.msgType = STUN_MSG_AllocateErrorResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Add Error*/
  ASSERT_TRUE( stunlib_addError(&stunMsg, "Try Alternate",
                                STUN_ERROR_TRY_ALTERNATE, pad) );
  stunMsg.hasAlternateServer           = true;
  stunMsg.alternateServer.familyType   = STUN_ADDR_IPv4Family;
  stunMsg.alternateServer.addr.v4.addr = mapped;
  stunMsg.alternateServer.addr.v4.port = 3478;

  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  memset( &stunMsg, 0, sizeof(StunMessage) );

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     120,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE(stunMsg.hasAlternateServer);
  ASSERT_TRUE(stunMsg.alternateServer.addr.v4.addr == mapped);
  ASSERT_TRUE(stunMsg.alternateServer.addr.v4.port == 3478);

}

CTEST(turnmessage, alternate_server_IPv6)
{
  StunMessage stunMsg;

  unsigned char stunBuf[120];
  char          pad = ' ';

  memset( &stunMsg, 0, sizeof(StunMessage) );



  uint8_t ip6Addr[] =
  {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
   0x92, 0x6d, 0x53};
  stunMsg.msgHdr.msgType = STUN_MSG_AllocateErrorResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Add Error*/
  ASSERT_TRUE( stunlib_addError(&stunMsg, "Try Alternate",
                                STUN_ERROR_TRY_ALTERNATE, pad) );
  stunMsg.hasAlternateServer = true;
  stunlib_setIP6Address(&stunMsg.alternateServer,
                        ip6Addr,
                        3478);

  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  memset( &stunMsg, 0, sizeof(StunMessage) );

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     120,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE(stunMsg.hasAlternateServer);
  ASSERT_TRUE(stunMsg.alternateServer.familyType == STUN_ADDR_IPv6Family);
  ASSERT_TRUE(stunMsg.alternateServer.addr.v6.port == 3478);
  ASSERT_TRUE(memcmp( stunMsg.alternateServer.addr.v6.addr, ip6Addr,
                      sizeof(ip6Addr) ) == 0);


}

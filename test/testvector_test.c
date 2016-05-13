#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "stunlib.h"
#include "sockaddr_util.h"
#include "test_utils.h"


static unsigned char req[] =
  "\x00\x01\x00\x58"    /*   Request type and message length */
  "\x21\x12\xa4\x42"    /*   Magic cookie */
  "\xb7\xe7\xa7\x01"    /* } */
  "\xbc\x34\xd6\x86"    /* }  Transaction ID */
  "\xfa\x87\xdf\xae"    /* } */
  "\x80\x22\x00\x10"    /*     SOFTWARE attribute header */
  "\x53\x54\x55\x4e"    /* } */
  "\x20\x74\x65\x73"    /* }  User-agent... */
  "\x74\x20\x63\x6c"    /* }  ...name */
  "\x69\x65\x6e\x74"    /* } */
  "\x00\x24\x00\x04"    /* PRIORITY attribute header */
  "\x6e\x00\x01\xff"    /*    ICE priority value */
  "\x80\x29\x00\x08"    /*     ICE-CONTROLLED attribute header */
  "\x93\x2f\xf9\xb1"    /*  }  Pseudo-random tie breaker... */
  "\x51\x26\x3b\x36"    /*  }   ...for ICE control */
  "\x00\x06\x00\x09"    /*     USERNAME attribute header */
  "\x65\x76\x74\x6a"    /*  } */
  "\x3a\x68\x36\x76"    /*  }  Username (9 bytes) and padding (3 bytes) */
  "\x59\x20\x20\x20"    /*  } */
  "\x00\x08\x00\x14"    /*   MESSAGE-INTEGRITY attribute header */
  "\x9a\xea\xa7\x0c"    /* } */
  "\xbf\xd8\xcb\x56"    /* } */
  "\x78\x1e\xf2\xb5"    /* }  HMAC-SHA1 fingerprint */
  "\xb2\xd3\xf2\x49"    /* } */
  "\xc1\xb5\x71\xa2"    /* } */
  "\x80\x28\x00\x04"    /*   FINGERPRINT attribute header */
  "\xe5\x7a\x3b\xcf";   /*  CRC32 fingerprint */



static unsigned char respv4[] =
  "\x01\x01\x00\x3c"    /*     Response type and message length */
  "\x21\x12\xa4\x42"    /*     Magic cookie */
  "\xb7\xe7\xa7\x01"    /*  } */
  "\xbc\x34\xd6\x86"    /*  }  Transaction ID */
  "\xfa\x87\xdf\xae"    /*  } */
  "\x80\x22\x00\x0b"    /*     SOFTWARE attribute header */
  "\x74\x65\x73\x74"    /*  } */
  "\x20\x76\x65\x63"    /*  }  UTF-8 server name */
  "\x74\x6f\x72\x20"    /*  } */
  "\x00\x20\x00\x08"    /*     XOR-MAPPED-ADDRESS attribute header */
  "\x00\x01\xa1\x47"    /*     Address family (IPv4) and xor'd mapped port
                         * number */
  "\xe1\x12\xa6\x43"    /*     Xor'd mapped IPv4 address */
  "\x00\x08\x00\x14"    /*     MESSAGE-INTEGRITY attribute header */
  "\x2b\x91\xf5\x99"    /*  } */
  "\xfd\x9e\x90\xc3"    /*  } */
  "\x8c\x74\x89\xf9"    /*  }  HMAC-SHA1 fingerprint */
  "\x2a\xf9\xba\x53"    /*  } */
  "\xf0\x6b\xe7\xd7"    /*  } */
  "\x80\x28\x00\x04"    /*     FINGERPRINT attribute header */
  "\xc0\x7d\x4c\x96";   /*     CRC32 fingerprint */


static unsigned char respv6[] =
  "\x01\x01\x00\x48"    /*     Response type and message length */
  "\x21\x12\xa4\x42"    /*     Magic cookie */
  "\xb7\xe7\xa7\x01"    /*  } */
  "\xbc\x34\xd6\x86"    /*  }  Transaction ID */
  "\xfa\x87\xdf\xae"    /*  } */
  "\x80\x22\x00\x0b"    /*     SOFTWARE attribute header */
  "\x74\x65\x73\x74"    /*  } */
  "\x20\x76\x65\x63"    /*  }  UTF-8 server name */
  "\x74\x6f\x72\x20"    /*  } */
  "\x00\x20\x00\x14"    /*     XOR-MAPPED-ADDRESS attribute header */
  "\x00\x02\xa1\x47"    /*     Address family (IPv6) and xor'd mapped port
                         * number */
  "\x01\x13\xa9\xfa"    /*  } */
  "\xa5\xd3\xf1\x79"    /*  }  Xor'd mapped IPv6 address */
  "\xbc\x25\xf4\xb5"    /*  } */
  "\xbe\xd2\xb9\xd9"    /*  } */
  "\x00\x08\x00\x14"    /*     MESSAGE-INTEGRITY attribute header */
  "\xa3\x82\x95\x4e"    /*  } */
  "\x4b\xe6\x7b\xf1"    /*  } */
  "\x17\x84\xc9\x7c"    /*  }  HMAC-SHA1 fingerprint */
  "\x82\x92\xc2\x75"    /*  } */
  "\xbf\xe3\xed\x41"    /*  } */
  "\x80\x28\x00\x04"    /*     FINGERPRINT attribute header */
  "\xc8\xfb\x0b\x4c";   /*     CRC32 fingerprint */


static unsigned char unknwn[] =
  "\x00\x01\x00\x58"      /*   Request type and message length */
  "\x21\x12\xa4\x42"      /*   Magic cookie */
  "\xb7\xe7\xa7\x01"      /* } */
  "\xbc\x34\xd6\x86"      /* }  Transaction ID */
  "\xfa\x87\xdf\xae"      /* } */
  "\x80\x22\x00\x10"      /*     SOFTWARE attribute header */
  "\x53\x54\x55\x4e"      /* } */
  "\x20\x74\x65\x73"      /* }  User-agent... */
  "\x74\x20\x63\x6c"      /* }  ...name */
  "\x69\x65\x6e\x74"      /* } */
  "\x00\x26\x00\x04"      /* Unkown attribute header */
  "\x6e\x00\x01\xff"      /*    some value */
  "\x80\x29\x00\x08"      /*     ICE-CONTROLLED attribute header */
  "\x93\x2f\xf9\xb1"      /*  }  Pseudo-random tie breaker... */
  "\x51\x26\x3b\x36"      /*  }   ...for ICE control */
  "\x00\x06\x00\x09"      /*     USERNAME attribute header */
  "\x65\x76\x74\x6a"      /*  } */
  "\x3a\x68\x36\x76"      /*  }  Username (9 bytes) and padding (3 bytes) */
  "\x59\x20\x20\x20"      /*  } */
  "\x00\x08\x00\x14"      /*   MESSAGE-INTEGRITY attribute header */
  "\x9a\xea\xa7\x0c"      /* } */
  "\xbf\xd8\xcb\x56"      /* } */
  "\x78\x1e\xf2\xb5"      /* }  HMAC-SHA1 fingerprint */
  "\xb2\xd3\xf2\x49"      /* } */
  "\xc1\xb5\x71\xa2"      /* } */
  "\x80\x28\x00\x04"      /*   FINGERPRINT attribute header */
  "\xe5\x7a\x3b\xcf";     /*  CRC32 fingerprint */


static const char username[] = "evtj:h6vY";

char password[]       = "VOkJxbRl1RmTxUk/WvJxBt";
char password_wrong[] = "VOkJxbRl1RmTxUk/WvJxBr";

const unsigned char idOctet[] = "\xb7\xe7\xa7\x01"
                                "\xbc\x34\xd6\x86"
                                "\xfa\x87\xdf\xae";

const uint32_t priority = 1845494271;

const uint64_t tieBreaker = 0x932FF9B151263B36LL;
const uint32_t xorMapped  = 3221225985U; /*192.0.2.1*/
const uint16_t port       = 32853;

const char* software      = "STUN test client\0";
const char* software_resp = "test vector\0";

const char* user_longAuth =
  "<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>\0";
/* const char *pass_longAuth =  "The<U+00AD>M<U+00AA>tr<U+2168>\0"; */
const char* pass_longAuth  =  "TheMatrIX";
const char* realm_longAuth = "example.org\0";


#define MAX_STRING_TEST 5



CTEST(testvector, request_decode)
{
  StunMessage stunMsg;

  ASSERT_TRUE( stunlib_DecodeMessage(req,
                                     108,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( req,
                                       108,
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_FALSE( stunlib_checkIntegrity( req,
                                        108,
                                        &stunMsg,
                                        (uint8_t*)password_wrong,
                                        sizeof(password_wrong) ) );

  ASSERT_TRUE( stunMsg.msgHdr.msgType == STUN_MSG_BindRequestMsg);

  ASSERT_TRUE( 0 == memcmp(&stunMsg.msgHdr.id.octet,&idOctet,12) );

  ASSERT_TRUE( stunMsg.hasUsername);
  ASSERT_TRUE( 0 ==
               memcmp(&stunMsg.username.value, username,
                      stunMsg.username.sizeValue) );

  ASSERT_TRUE( stunMsg.hasSoftware);
  ASSERT_TRUE( 0 ==
               memcmp(&stunMsg.software.value, software,
                      stunMsg.software.sizeValue) );

  ASSERT_TRUE(stunMsg.hasPriority);
  ASSERT_TRUE(stunMsg.priority.value == priority);

  ASSERT_TRUE(stunMsg.hasControlled);
  ASSERT_TRUE(stunMsg.controlled.value == tieBreaker);
}


CTEST(testvector, request_encode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[120];
  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_BindRequestMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  ASSERT_TRUE( stunlib_addUserName(&stunMsg, username, '\x20') );
  ASSERT_TRUE( stunlib_addSoftware(&stunMsg, software, '\x20') );

  stunMsg.hasPriority      = true;
  stunMsg.priority.value   = priority;
  stunMsg.hasControlled    = true;
  stunMsg.controlled.value = tieBreaker;

  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     120,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  ASSERT_TRUE(memcmp(stunBuf, req, 108) == 0);

}


CTEST(testvector, response_decode)
{
  StunMessage stunMsg;

  ASSERT_TRUE( stunlib_DecodeMessage(respv4,
                                     80,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( respv4,
                                       80,
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE( 0 == memcmp(&stunMsg.msgHdr.id.octet,&idOctet,12) );

  ASSERT_TRUE( stunMsg.msgHdr.msgType == STUN_MSG_BindResponseMsg);

  ASSERT_TRUE( stunMsg.hasXorMappedAddress);
  ASSERT_TRUE( stunMsg.xorMappedAddress.addr.v4.addr == xorMapped);
  ASSERT_TRUE( stunMsg.xorMappedAddress.addr.v4.port == port);

  ASSERT_TRUE( stunMsg.hasSoftware);
  ASSERT_TRUE( strncmp( stunMsg.software.value,
                        software_resp,
                        max( stunMsg.software.sizeValue,
                             sizeof(software) ) ) == 0);
}



CTEST(testvector, response_encode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[120];

  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_BindResponseMsg;

  /*id*/
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Server*/
  stunMsg.hasSoftware = true;
  memcpy( stunMsg.software.value, software_resp, strlen(software_resp) );

  stunMsg.software.sizeValue = strlen(software_resp);

  /*Mapped Address*/
  stunMsg.hasXorMappedAddress           = true;
  stunMsg.xorMappedAddress.familyType   = STUN_ADDR_IPv4Family;
  stunMsg.xorMappedAddress.addr.v4.addr = xorMapped;
  stunMsg.xorMappedAddress.addr.v4.port = port;

  ASSERT_TRUE( stunlib_addSoftware(&stunMsg, software_resp, '\x20') );
  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     80,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  ASSERT_TRUE(memcmp(stunBuf, respv4, 80) == 0);
}

CTEST(testvector, response_decode_IPv6)
{
  StunMessage             stunMsg;
  struct sockaddr_storage a;
  struct sockaddr_storage b;

  sockaddr_initFromString( (struct sockaddr*)&b,
                           "[2001:db8:1234:5678:11:2233:4455:6677]:32853" );

  ASSERT_TRUE( stunlib_DecodeMessage(respv6,
                                     96,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( respv6,
                                       96,
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE( 0 == memcmp(&stunMsg.msgHdr.id.octet,&idOctet,12) );

  ASSERT_TRUE( stunMsg.msgHdr.msgType == STUN_MSG_BindResponseMsg);

  ASSERT_TRUE( stunMsg.hasXorMappedAddress);

  sockaddr_initFromIPv6Int( (struct sockaddr_in6*)&a,
                            stunMsg.xorMappedAddress.addr.v6.addr,
                            htons(stunMsg.xorMappedAddress.addr.v6.port) );

  ASSERT_TRUE( sockaddr_alike( (struct sockaddr*)&a,
                               (struct sockaddr*)&b ) );

  ASSERT_TRUE( stunMsg.xorMappedAddress.addr.v6.port == port);

  ASSERT_TRUE( stunMsg.hasSoftware);
  ASSERT_TRUE( strncmp( stunMsg.software.value,
                        software_resp,
                        max( stunMsg.software.sizeValue,
                             sizeof(software_resp) ) ) == 0);
}

CTEST(testvector, response_encode_IPv6)
{
  StunMessage             stunMsg;
  unsigned char           stunBuf[120];
  struct sockaddr_storage b;

  sockaddr_initFromString( (struct sockaddr*)&b,
                           "[2001:db8:1234:5678:11:2233:4455:6677]:32853" );
  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_BindResponseMsg;

  /*id*/
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /*Server*/
  stunMsg.hasSoftware = true;
  memcpy( stunMsg.software.value, software, strlen(software) );

  stunMsg.software.sizeValue = strlen(software);

  /*Mapped Address*/
  stunMsg.hasXorMappedAddress = true;
  stunlib_setIP6Address(&stunMsg.xorMappedAddress,
                        ( (struct sockaddr_in6*)&b )->sin6_addr.s6_addr,
                        port);

  ASSERT_TRUE( stunlib_addSoftware(&stunMsg, software_resp, '\x20') );
  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     96,
                                     (unsigned char*)password,
                                     strlen(password),
                                     NULL) );

  ASSERT_TRUE(memcmp(stunBuf, respv6, 92) == 0);
}

CTEST(testvector, keepalive_resp_encode)
{
  StunMessage   stunMsg;
  StunMsgId     transId;
  StunIPAddress ipAddr;
  uint8_t       ip6Addr[16] =
  {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
   0x92, 0x6d, 0x53};
  uint32_t i;
  uint8_t  encBuf[STUN_MAX_PACKET_SIZE];
  int      encLen;

  for (i = 0; i < sizeof(transId.octet); i++)
  {
    transId.octet[i] = i;
  }

  /* ip4 test */
  stunlib_setIP4Address(&ipAddr, 0xAABBCCDD, 0x1234);
  encLen =
    stunlib_encodeStunKeepAliveResp( &transId, &ipAddr, encBuf,
                                     sizeof(encBuf) );
  stunlib_DecodeMessage(encBuf,
                        encLen,
                        &stunMsg,
                        0,
                        NULL);

  ASSERT_TRUE( (encLen == 32)
               && (stunMsg.hasXorMappedAddress)
               && (stunMsg.xorMappedAddress.familyType == STUN_ADDR_IPv4Family)
               && (stunMsg.xorMappedAddress.addr.v4.port == 0x1234)
               && (stunMsg.xorMappedAddress.addr.v4.addr == 0xAABBCCDD) );

  /* ip4 test */
  stunlib_setIP6Address(&ipAddr, ip6Addr, 0x4321);
  encLen =
    stunlib_encodeStunKeepAliveResp( &transId, &ipAddr, encBuf,
                                     sizeof(encBuf) );
  stunlib_DecodeMessage(encBuf,
                        encLen,
                        &stunMsg,
                        0,
                        NULL);

  ASSERT_TRUE( (encLen == 44)
               && (stunMsg.hasXorMappedAddress)
               && (stunMsg.xorMappedAddress.familyType == STUN_ADDR_IPv6Family)
               && (stunMsg.xorMappedAddress.addr.v6.port == 0x4321)
               && (memcmp( stunMsg.xorMappedAddress.addr.v6.addr, ip6Addr,
                           sizeof(ip6Addr) ) == 0) );

}

CTEST(testvector, keepalive_req_encode)
{
  StunMsgId transId;
  uint8_t   encBuf[STUN_MAX_PACKET_SIZE];
  uint32_t  i;
  uint8_t   expected[STUN_MIN_PACKET_SIZE] = { 0x00, 0x01, 0x00, 0x00,
                                               0x21, 0x12, 0xA4, 0x42,
                                               0x00, 0x01, 0x02, 0x03,
                                               0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0A, 0x0B};

  for (i = 0; i < sizeof(transId.octet); i++)
  {
    transId.octet[i] = i;
  }

  expected[1] = (uint8_t)STUN_MSG_BindRequestMsg;
  stunlib_encodeStunKeepAliveReq( StunKeepAliveUsage_Outbound, &transId, encBuf,
                                  sizeof(encBuf) );
  ASSERT_TRUE(memcmp( encBuf, expected, sizeof(expected) ) == 0);

  stunlib_encodeStunKeepAliveReq( StunKeepAliveUsage_Ice, &transId, encBuf,
                                  sizeof(encBuf) );
  expected[1] = (uint8_t)STUN_MSG_BindIndicationMsg;
  ASSERT_TRUE(memcmp( encBuf, expected, sizeof(expected) ) == 0);
}


CTEST(testvector, string_software_encode_decode)
{
  uint8_t     stunBuf[STUN_MAX_PACKET_SIZE];
  const char* testStr[MAX_STRING_TEST] = {"a", "ab", "acb", "abcd", "abcde" };
  StunMessage stunMsg;
  int         i;

  for (i = 0; i < MAX_STRING_TEST; i++)
  {
    int encLen;
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;

    /*id*/
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
    stunlib_addSoftware(&stunMsg, testStr[i], STUN_DFLT_PAD);
    encLen = stunlib_encodeMessage(&stunMsg,
                                   stunBuf,
                                   sizeof(stunBuf),
                                   (unsigned char*)password,
                                   strlen(password),
                                   NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       encLen,
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         encLen,
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( stunMsg.software.sizeValue == strlen(testStr[i]) );
    ASSERT_TRUE( strcmp(stunMsg.software.value, testStr[i]) == 0);
  }
}


CTEST(testvector, string_nounce_encode_decode)
{
  uint8_t     stunBuf[STUN_MAX_PACKET_SIZE];
  const char* testStr[MAX_STRING_TEST] = {"a", "ab", "acb", "abcd", "abcde" };
  StunMessage stunMsg;
  int         i;

  for (i = 0; i < MAX_STRING_TEST; i++)
  {
    int encLen;
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;

    /*id*/
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
    stunlib_addNonce(&stunMsg, testStr[i], STUN_DFLT_PAD);
    encLen = stunlib_encodeMessage(&stunMsg,
                                   stunBuf,
                                   sizeof(stunBuf),
                                   (unsigned char*)password,
                                   strlen(password),
                                   NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       encLen,
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         encLen,
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( stunMsg.nonce.sizeValue == strlen(testStr[i]) );
    ASSERT_TRUE( strcmp(stunMsg.nonce.value, testStr[i]) == 0);
  }
}

CTEST(testvector, string_realm_encode_decode)
{
  uint8_t     stunBuf[STUN_MAX_PACKET_SIZE];
  const char* testStr[MAX_STRING_TEST] = {"a", "ab", "acb", "abcd", "abcde" };
  StunMessage stunMsg;
  int         i;

  for (i = 0; i < MAX_STRING_TEST; i++)
  {
    int encLen;
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;

    /*id*/
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
    stunlib_addRealm(&stunMsg, testStr[i], STUN_DFLT_PAD);
    encLen = stunlib_encodeMessage(&stunMsg,
                                   stunBuf,
                                   sizeof(stunBuf),
                                   (unsigned char*)password,
                                   strlen(password),
                                   NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       encLen,
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         encLen,
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( stunMsg.realm.sizeValue == strlen(testStr[i]) );
    ASSERT_TRUE( strcmp(stunMsg.realm.value, testStr[i]) == 0);
  }

}


CTEST(testvector, string_username_encode_decode)
{
  uint8_t     stunBuf[STUN_MAX_PACKET_SIZE];
  const char* testStr[MAX_STRING_TEST] = {"a", "ab", "acb", "abcd", "abcde" };
  StunMessage stunMsg;
  int         i;

  for (i = 0; i < MAX_STRING_TEST; i++)
  {
    int encLen;
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;

    /*id*/
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
    stunlib_addUserName(&stunMsg, testStr[i], STUN_DFLT_PAD);
    encLen = stunlib_encodeMessage(&stunMsg,
                                   stunBuf,
                                   sizeof(stunBuf),
                                   (unsigned char*)password,
                                   strlen(password),
                                   NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       encLen,
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         encLen,
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( stunMsg.username.sizeValue == strlen(testStr[i]) );
    ASSERT_TRUE( strcmp(stunMsg.username.value, testStr[i]) == 0);
  }

}

CTEST(testvector, error_encode_decode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[STUN_MAX_PACKET_SIZE];

  const char* testStr[MAX_STRING_TEST] = {"a", "ab", "acb", "abcd", "abcde" };
  int         i;

  for (i = 0; i < MAX_STRING_TEST; i++)
  {
    int encLen;
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

    stunlib_addError(&stunMsg, testStr[i], 400 + i, ' ');
    encLen = stunlib_encodeMessage(&stunMsg,
                                   stunBuf,
                                   STUN_MAX_PACKET_SIZE,
                                   (unsigned char*)password,
                                   strlen(password),
                                   NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       encLen,
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         encLen,
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( (stunMsg.errorCode.errorClass == 4)
                 && (stunMsg.errorCode.number == i)
                 && (stunMsg.errorCode.reserved == 0)
                 && (strncmp( stunMsg.errorCode.reason, testStr[i],
                              strlen(testStr[i]) ) == 0) );
  }
}

CTEST(testvector, xor_encode_decode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[STUN_MAX_PACKET_SIZE];
  int           encLen;
  uint8_t       ip6Addr[] =
  {0x20, 0x1, 0x4, 0x70, 0xdc, 0x88, 0x0, 0x2, 0x2, 0x26, 0x18, 0xff, 0xfe,
   0x92, 0x6d, 0x53};

  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /* ip4 test */
  stunlib_setIP4Address(&stunMsg.xorMappedAddress, 0x12345678, 4355);
  stunMsg.hasXorMappedAddress = true;
  encLen                      = stunlib_encodeMessage(&stunMsg,
                                                      stunBuf,
                                                      sizeof(stunBuf),
                                                      (unsigned char*)password,
                                                      strlen(password),
                                                      NULL);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     encLen,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                       encLen,
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE( (stunMsg.xorMappedAddress.familyType == STUN_ADDR_IPv4Family)
               && (stunMsg.xorMappedAddress.addr.v4.port == 4355)
               && (stunMsg.xorMappedAddress.addr.v4.addr == 0x12345678) );

  /* ip6 */
  stunlib_setIP6Address(&stunMsg.xorMappedAddress, ip6Addr, 4685);
  memcpy( stunMsg.xorMappedAddress.addr.v6.addr, ip6Addr, sizeof(ip6Addr) );
  stunMsg.hasXorMappedAddress = true;
  encLen                      = stunlib_encodeMessage(&stunMsg,
                                                      stunBuf,
                                                      sizeof(stunBuf),
                                                      (unsigned char*)password,
                                                      strlen(password),
                                                      NULL);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     encLen,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                       encLen,
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE( (stunMsg.xorMappedAddress.familyType == STUN_ADDR_IPv6Family)
               && (stunMsg.xorMappedAddress.addr.v6.port == 4685)
               && (memcmp( stunMsg.xorMappedAddress.addr.v6.addr, ip6Addr,
                           sizeof(ip6Addr) ) == 0) );

}



CTEST(testvector, transport_encode_decode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[STUN_MAX_PACKET_SIZE];

  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
  stunlib_addRequestedTransport(&stunMsg, STUN_REQ_TRANSPORT_UDP);
  stunlib_encodeMessage(&stunMsg,
                        stunBuf,
                        sizeof(stunBuf),
                        (unsigned char*)password,
                        strlen(password),
                        NULL);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     sizeof(stunBuf),
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                       sizeof(stunBuf),
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE( (stunMsg.requestedTransport.protocol == STUN_REQ_TRANSPORT_UDP)
               && (stunMsg.requestedTransport.rffu[0] == 0)
               && (stunMsg.requestedTransport.rffu[1] == 0)
               && (stunMsg.requestedTransport.rffu[2] == 0)
                );

}

CTEST(testvector, channel_encode_decode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[STUN_MAX_PACKET_SIZE];
  uint16_t      chan;

  for (chan = STUN_MIN_CHANNEL_ID; chan <= STUN_MAX_CHANNEL_ID; chan += 0x100)
  {
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;

    /*id*/
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
    stunlib_addChannelNumber(&stunMsg, chan);
    stunlib_encodeMessage(&stunMsg,
                          stunBuf,
                          sizeof(stunBuf),
                          (unsigned char*)password,
                          strlen(password),
                          NULL);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       sizeof(stunBuf),
                                       &stunMsg,
                                       NULL,
                                       NULL) );

    ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                         sizeof(stunBuf),
                                         &stunMsg,
                                         (uint8_t*)password,
                                         sizeof(password) ) );

    ASSERT_TRUE( (stunMsg.channelNumber.channelNumber == chan)
                 && (stunMsg.channelNumber.rffu == 0) );
  }
}


CTEST(testvector, print)
{

  StunMessage stunMsg;

  ASSERT_TRUE( stunlib_DecodeMessage(req,
                                     108,
                                     &stunMsg,
                                     NULL,
                                     NULL) );

}

CTEST(testvector, SendIndication)
{
  struct sockaddr_storage addr;
  unsigned char           stunBuf[200];
  char                    message[] = "Some useful data\0";
  int                     msg_len;
  StunMessage             msg;


  sockaddr_initFromString( (struct sockaddr*)&addr,
                           "1.2.3.4:2345" );

  msg_len = stunlib_EncodeSendIndication(stunBuf,
                                         (uint8_t*)message,
                                         sizeof(stunBuf),
                                         strlen(message),
                                         (struct sockaddr*)&addr);
  ASSERT_TRUE( msg_len == 52);
  ASSERT_TRUE( stunlib_isStunMsg(stunBuf, msg_len) );
  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     msg_len,
                                     &msg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( msg.msgHdr.msgType == STUN_MSG_SendIndicationMsg);
  ASSERT_TRUE( msg.hasData);
  ASSERT_TRUE( 0 == memcmp( &stunBuf[msg.data.offset], message, strlen(
                              message) ) );
}


CTEST(testvector, enf_encode_decode)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[STUN_MAX_PACKET_SIZE];
  uint8_t       type   = 0x04;
  uint8_t       tbd    = 0x00;
  uint16_t      bw_max = 4096;
  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_AllocateRequestMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

  /* Flow Descr */
  stunMsg.hasEnfFlowDescription           = true;
  stunMsg.enfFlowDescription.type         = type;
  stunMsg.enfFlowDescription.tbd          = tbd;
  stunMsg.enfFlowDescription.bandwidthMax = bw_max;
  stunMsg.enfFlowDescription.pad          = 0x00;


  stunMsg.hasEnfNetworkStatus               = true;
  stunMsg.enfNetworkStatus.flags            = 0x1;
  stunMsg.enfNetworkStatus.nodeCnt          = 4;
  stunMsg.enfNetworkStatus.upMaxBandwidth   = 34;
  stunMsg.enfNetworkStatus.downMaxBandwidth = 3456;

  stunMsg.hasEnfNetworkStatusResp               = true;
  stunMsg.enfNetworkStatusResp.flags            = 0x5;
  stunMsg.enfNetworkStatusResp.nodeCnt          = 7;
  stunMsg.enfNetworkStatusResp.upMaxBandwidth   = 4098;
  stunMsg.enfNetworkStatusResp.downMaxBandwidth = 6789;


  stunlib_encodeMessage(&stunMsg,
                        stunBuf,
                        sizeof(stunBuf),
                        (unsigned char*)password,
                        strlen(password),
                        NULL);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     sizeof(stunBuf),
                                     &stunMsg,
                                     NULL,
                                     NULL) );

  ASSERT_TRUE( stunlib_checkIntegrity( stunBuf,
                                       sizeof(stunBuf),
                                       &stunMsg,
                                       (uint8_t*)password,
                                       sizeof(password) ) );

  ASSERT_TRUE(stunMsg.hasEnfFlowDescription);
  ASSERT_TRUE(stunMsg.enfFlowDescription.type == type);
  ASSERT_TRUE(stunMsg.enfFlowDescription.tbd == tbd);
  ASSERT_TRUE(stunMsg.enfFlowDescription.bandwidthMax == bw_max);
  ASSERT_TRUE(stunMsg.enfFlowDescription.pad == 0);

  ASSERT_TRUE(stunMsg.hasEnfNetworkStatus);
  ASSERT_TRUE(stunMsg.enfNetworkStatus.flags            == 0x1);
  ASSERT_TRUE(stunMsg.enfNetworkStatus.nodeCnt          == 4);
  ASSERT_TRUE(stunMsg.enfNetworkStatus.upMaxBandwidth   == 34);
  ASSERT_TRUE(stunMsg.enfNetworkStatus.downMaxBandwidth == 3456);

  ASSERT_TRUE(stunMsg.hasEnfNetworkStatusResp);
  ASSERT_TRUE(stunMsg.enfNetworkStatusResp.flags            == 0x5);
  ASSERT_TRUE(stunMsg.enfNetworkStatusResp.nodeCnt          == 7);
  ASSERT_TRUE(stunMsg.enfNetworkStatusResp.upMaxBandwidth   == 4098);
  ASSERT_TRUE(stunMsg.enfNetworkStatusResp.downMaxBandwidth == 6789);


}



CTEST(testvector, dont_crash_if_atrLen_bogus_on_errors_messages)
{
  unsigned char id_000387_src_000097_op_havoc_rep_8[] = {
    0x00, 0x00, 0x00, 0x13, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff,
    0xff, 0xff, 0xef, 0xff, 0x67, 0x6c, 0x00, 0x01, 0x00, 0x13, 0x00, 0x08,
    0xe2, 0x00, 0x00, 0x01, 0xff, 0x6c, 0x00, 0x13, 0x00, 0x09, 0x00, 0x00,
    0x00, 0x01, 0xff, 0x6c, 0x6c, 0x00, 0x01, 0x00, 0x13, 0x00, 0x09, 0x00,
    0x00, 0x00, 0x01, 0xe8, 0x00, 0xef, 0xfa, 0x6c, 0x6c, 0x6c, 0x6c, 0x00,
    0x00, 0x01, 0xf8, 0xe8, 0x00, 0xef, 0xff, 0x6c, 0x6c, 0x6c, 0x6c, 0x00,
    0x00, 0x01, 0xf8, 0x00, 0x80, 0x15, 0x6c, 0x6c, 0x00, 0x6c, 0x6c, 0x6c,
    0x6c, 0x1f, 0x6c, 0x6c, 0x84, 0x6c, 0x6c, 0x00, 0x00, 0x01, 0xf8, 0x00,
    0x80, 0x00, 0x6c, 0x6c, 0x00, 0x6c, 0x6c, 0x6c, 0x6c, 0x1f, 0x6c, 0x6c,
    0x68, 0x6c, 0x00, 0x6c, 0x00, 0x01, 0x00, 0x13, 0x00, 0x09, 0x00, 0x00,
    0x00, 0x6c, 0x6c, 0x18, 0x6c, 0x6c, 0x6c, 0x6c, 0x1f, 0x6c, 0x6c, 0x84,
    0x6c, 0x6c, 0x00, 0x00, 0x01, 0xf8, 0x00, 0x80, 0x00, 0x6c, 0x6c, 0x00,
    0x6c, 0x6c, 0x6c, 0x6c, 0x1f, 0x6c, 0x6c, 0x6c, 0x6c, 0x00, 0x6c, 0x00,
    0x01, 0x00, 0x13, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0xe8, 0x00, 0xef,
    0xfa, 0x6c, 0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x01, 0xf8, 0xe8, 0x00, 0xef,
    0xff, 0x6c, 0x6c, 0x6c, 0x6c, 0x00, 0x00, 0x01, 0xf8, 0x00, 0x80, 0x00,
    0x6c, 0x6c, 0x00, 0x6c, 0x6c, 0x16, 0x6c, 0x1f, 0x6c, 0x6c, 0x84, 0x6c,
    0x6c, 0x00, 0x00, 0x01, 0xf8, 0x00, 0x80, 0x00, 0x6c, 0x6c, 0x00, 0x6c,
    0x6c, 0x6c, 0x6c, 0x1f, 0x6c, 0x6c, 0x6c, 0x6c, 0x00
  };
  unsigned int  id_000387_src_000097_op_havoc_rep_8_len = 225;

  StunMessage stunMsg;

  ASSERT_FALSE( stunlib_DecodeMessage(
                  id_000387_src_000097_op_havoc_rep_8,
                  id_000387_src_000097_op_havoc_rep_8_len,
                  &stunMsg,
                  NULL,
                  NULL) );
}

CTEST(testvector, unkowns_encode_decode)
{
  StunMessage    stunMsg;
  StunAtrUnknown unknowns;
  unsigned char  stunBuf[STUN_MAX_PACKET_SIZE];
  FILE*          f = fopen("/dev/null", "w+");
  ASSERT_TRUE( stunlib_DecodeMessage(unknwn,
                                     108,
                                     &stunMsg,
                                     &unknowns,
                                     f) );


  ASSERT_TRUE( stunMsg.msgHdr.msgType == STUN_MSG_BindRequestMsg);

  ASSERT_TRUE( 0 == memcmp(&stunMsg.msgHdr.id.octet,&idOctet,12) );

  ASSERT_TRUE( stunMsg.hasUsername);
  ASSERT_TRUE( 0 ==
               memcmp(&stunMsg.username.value, username,
                      stunMsg.username.sizeValue) );

  ASSERT_TRUE( stunMsg.hasSoftware);
  ASSERT_TRUE( 0 ==
               memcmp(&stunMsg.software.value, software,
                      stunMsg.software.sizeValue) );

  ASSERT_TRUE(unknowns.numAttributes == 1);

  ASSERT_TRUE(stunMsg.hasControlled);
  ASSERT_TRUE(stunMsg.controlled.value == tieBreaker);


  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunMsg.msgHdr.msgType = STUN_MSG_AllocateResponseMsg;
  memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);
  stunlib_addError(&stunMsg, "UNKNOWN-ATTRIBUTE", 420, ' ');
  stunMsg.hasUnknownAttributes = true;
  memcpy(&stunMsg.unknownAttributes, &unknowns, sizeof unknowns);

  memset( stunBuf, 0, sizeof(stunBuf) );
  ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                     stunBuf,
                                     sizeof(stunBuf),
                                     (unsigned char*)password,
                                     strlen(password),
                                     f) );
  memset(&stunMsg, 0, sizeof stunMsg);

  ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                     88,
                                     &stunMsg,
                                     NULL,
                                     NULL) );
  ASSERT_TRUE(stunMsg.hasUnknownAttributes);
}

CTEST(testvector, stun_msg_len)
{
  ASSERT_TRUE(stunlib_StunMsgLen(unknwn) == 88);
}

CTEST(testvector, encode_decode_ttl)
{
  StunMessage   stunMsg;
  unsigned char stunBuf[120];

  for (int ttl = 1; ttl < 20; ttl++)
  {
    memset( &stunMsg, 0, sizeof(StunMessage) );
    stunMsg.msgHdr.msgType = STUN_MSG_BindRequestMsg;
    memcpy(&stunMsg.msgHdr.id.octet,&idOctet,12);

    ASSERT_TRUE( stunlib_addUserName(&stunMsg, username, '\x20') );
    ASSERT_TRUE( stunlib_addSoftware(&stunMsg, software, '\x20') );
    stunMsg.hasTTL  = true;
    stunMsg.ttl.ttl = ttl;
    ASSERT_TRUE( stunlib_encodeMessage(&stunMsg,
                                       stunBuf,
                                       120,
                                       (unsigned char*)password,
                                       strlen(password),
                                       NULL) );

    memset(&stunMsg, 0, sizeof stunMsg);

    ASSERT_TRUE( stunlib_DecodeMessage(stunBuf,
                                       120,
                                       &stunMsg,
                                       NULL,
                                       NULL) );
    ASSERT_TRUE(stunMsg.hasTTL);
    ASSERT_TRUE(stunMsg.ttl.ttl == ttl);
  }
}

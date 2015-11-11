#include <stdlib.h>
#include <stdio.h>

#include "test_utils.h"
#include "stunlib.h"

static unsigned char turnResp[] =
  "\x01\x03\x00\x5c"
  "\x21\x12\xa4\x42"
  "\x32\x7b\x23\xc6"
  "\x00\x01\x00\x00"
  "\x51\x1a\x45\xa3"
  "\x00\x16\x00\x08"
  "\x00\x01\xf4\x87"
  "\x2b\x3d\xa8\x69"
  "\x00\x0d\x00\x04"
  "\x00\x00\x02\x58"
  "\x00\x20\x00\x08"
  "\x00\x01\xf6\x75"
  "\x2b\x24\xfe\x5f"
  "\x80\x22\x00\x1d"
  "\x72\x65\x73\x74"
  "\x75\x6e\x64\x20"
  "\x76\x30\x2e\x34"
  "\x2e\x32\x20\x28"
  "\x78\x38\x36\x5f"
  "\x36\x34\x2f\x6c"
  "\x69\x6e\x75\x78"
  "\x29\x00\x00\x00"
  "\x00\x08\x00\x14"
  "\x86\xfa\x92\x69"
  "\x64\x64\x80\xb8"
  "\xaf\xf2\xff\x06"
  "\xef\x3d\x5c\x17"
  "\xd1\x0d\xf2\xa0";



CTEST(realworld, integrity_turn_response)
{
  StunMessage stunResponse;
  int         numbytes   = sizeof(turnResp);
  const char  user[]     = "turnuser";
  const char  password[] = "turnpass";
  const char  realm[]    = "ice.qa";
  int         keyLen     = 16;
  char        md5[keyLen];

  ASSERT_TRUE( stunlib_isStunMsg(turnResp, numbytes) );

  ASSERT_TRUE( stunlib_DecodeMessage(turnResp, numbytes, &stunResponse, NULL,
                                     NULL) );

  stunlib_createMD5Key( (unsigned char*)md5, user, realm, password );

  ASSERT_TRUE( stunlib_checkIntegrity(turnResp, numbytes, &stunResponse,
                                      (unsigned char*)md5, keyLen) );
}

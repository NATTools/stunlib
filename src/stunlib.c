/*
 *  See license file
 */
#include "stunlib.h"
#include "stun_crypto.h"
#include <stdlib.h>
#include <string.h>


/**
 *  Defines a STUN Message object
 *
 *  <pre>
 *
 *  .---------------------.      /|\           /|\
 *  | STUN Header         |       |             |
 *  |---------------------|       |             |
 *  |         ....        |       |--------.    |
 *  |      N Attributes   |       |        |    |----.
 *  |         ....        |      \|/       |    |    |
 *  |---------------------|                |    |    |
 *  |  MESSAGE-INTEGRITY  | <-(HMAC-SHA1)--'   \|/   |
 *  |---------------------|                          |
 *  |     FINGERPRINT     | <-(CRC-32)---------------'
 *  '---------------------'
 *  |  </pre>
 *  |
 *  |  (ASCII art from Alfred E. Heggestad (libre)  (BSD license)
 */

static const uint8_t StunCookie[]   = STUN_MAGIC_COOKIE_ARRAY;
static const size_t  StunCookieSize = sizeof(StunCookie) /
                                      sizeof(StunCookie[0]);

uint32_t
stunlib_calculateFingerprint(const uint8_t* buf,
                             size_t         len);


/********************************
* Local helper funcs
********************************/


static void
printError(FILE*       stream,
           const char* fmt,
           ...)
{
  va_list ap;
  va_start(ap,fmt);

  vfprintf(stream, fmt, ap);
  fflush(stream);

  va_end(ap);
}

/*
 * Generic encode/decode stuff
 */
static void
write_8(uint8_t**     bufPtr,
        const uint8_t v)
{
  **bufPtr = v;
  (*bufPtr)++;
}

static void
write_8n(uint8_t**      bufPtr,
         const uint8_t* v,
         uint32_t       len)
{
  memcpy(*bufPtr, v, len);
  *bufPtr += len;
}

static void
write_16(uint8_t**      bufPtr,
         const uint16_t v)
{
  **bufPtr = (v >> 8) & 0xff;
  (*bufPtr)++;
  **bufPtr = v & 0xff;
  (*bufPtr)++;
}

static void
write_32(uint8_t**      bufPtr,
         const uint32_t v)
{
  **bufPtr = (v >> 24) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 16) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 8) & 0xff;
  (*bufPtr)++;
  **bufPtr = v & 0xff;
  (*bufPtr)++;
}

static void
write_64(uint8_t**      bufPtr,
         const uint64_t v)
{
  **bufPtr = (v >> 56) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 48) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 40) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 32) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 24) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 16) & 0xff;
  (*bufPtr)++;
  **bufPtr = (v >> 8) & 0xff;
  (*bufPtr)++;
  **bufPtr = v & 0xff;
  (*bufPtr)++;
}

static void
write_8_xor(uint8_t**     bufPtr,
            const uint8_t v,
            uint8_t*      xorId)
{

  **bufPtr = v ^ xorId[0];
  (*bufPtr)++;
}


static void
write_16_xor(uint8_t**      bufPtr,
             const uint16_t v,
             uint8_t*       xorId)
{
  **bufPtr = ( (v >> 8) & 0xff ) ^ xorId[0];
  (*bufPtr)++;
  **bufPtr = (v & 0xff) ^ xorId[1];
  (*bufPtr)++;
}

static void
write_32_xor(uint8_t**      bufPtr,
             const uint32_t v,
             uint8_t*       xorId)
{
  **bufPtr = ( (v >> 24) & 0xff ) ^ xorId[0];
  (*bufPtr)++;
  **bufPtr = ( (v >> 16) & 0xff ) ^ xorId[1];
  (*bufPtr)++;
  **bufPtr = ( (v >> 8) & 0xff )  ^ xorId[2];
  (*bufPtr)++;
  **bufPtr = (v & 0xff)         ^ xorId[3];
  (*bufPtr)++;
}


static void
read_8(const uint8_t** bufPtr,
       uint8_t*        v)
{
  *v = **bufPtr;
  (*bufPtr)++;
}

static void
read_8n(const uint8_t** bufPtr,
        uint8_t*        v,
        uint32_t        len)
{
  memcpy(v, *bufPtr, len);
  *bufPtr += len;
}

static void
read_16(const uint8_t** bufPtr,
        uint16_t*       v)
{
  *v = ( (**bufPtr << 8) & 0xFF00 );
  (*bufPtr)++;
  *v |= (**bufPtr) & 0x00FF;
  (*bufPtr)++;
}

static void
read_32(const uint8_t** bufPtr,
        uint32_t*       v)
{
  *v = ( (**bufPtr << 24)  & 0xFF000000 );
  (*bufPtr)++;
  *v |= ( (**bufPtr << 16) & 0x00FF0000 );
  (*bufPtr)++;
  *v |= ( (**bufPtr << 8)  & 0x0000FF00 );
  (*bufPtr)++;
  *v |= (**bufPtr)        & 0x000000FF;
  (*bufPtr)++;
}

static void
read_64(const uint8_t** bufPtr,
        uint64_t*       v)
{
  *v = ( ( (uint64_t)**bufPtr << 56 ) & 0xFF00000000000000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 48 ) & 0x00FF000000000000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 40 ) & 0x0000FF0000000000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 32 ) & 0x000000FF00000000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 24 ) & 0x00000000FF000000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 16 ) & 0x0000000000FF0000ll );
  (*bufPtr)++;
  *v |= ( ( (uint64_t)**bufPtr << 8 )  & 0x000000000000FF00ll );
  (*bufPtr)++;
  *v |= ( (uint64_t)**bufPtr )         & 0x0FF;
  (*bufPtr)++;
}


static void
read_8_xor(const uint8_t** bufPtr,
           uint8_t*        v,
           uint8_t*        xorId)
{
  *v = **bufPtr ^ xorId[0];
  (*bufPtr)++;

}


static void
read_16_xor(const uint8_t** bufPtr,
            uint16_t*       v,
            uint8_t*        xorId)
{
  *v = ( ( (uint16_t)(**bufPtr ^ xorId[0]) ) << 8 ) & 0xFF00;
  (*bufPtr)++;
  *v |= ( (uint16_t)(**bufPtr ^ xorId[1]) ) & 0x00FF;
  (*bufPtr)++;
}

static void
read_32_xor(const uint8_t** bufPtr,
            uint32_t*       v,
            uint8_t*        xorId)
{
  *v =  ( ( (uint32_t)(**bufPtr ^ xorId[0]) ) << 24 ) & 0xFF000000;
  (*bufPtr)++;
  *v |= ( ( (uint32_t)(**bufPtr ^ xorId[1]) ) << 16 ) & 0x00FF0000;
  (*bufPtr)++;
  *v |= ( ( (uint32_t)(**bufPtr ^ xorId[2]) ) << 8 )  & 0x0000FF00;
  (*bufPtr)++;
  *v |=  ( (uint32_t)(**bufPtr ^ xorId[3]) ) & 0x00FF;
  (*bufPtr)++;
}

#if 0
static void
dumpbuff(char*    s,
         uint8_t* buf,
         uint32_t len)
{
  uint32_t i;
  printError("%s\n", s);
  for (i = 0; i < len; i++)
  {
    printError("%02x,", buf[i]);
    if (i % 10 == 0)
    {
      printError("\n");
    }
  }
}
#endif

char const*
stunlib_getMessageName(uint16_t msgType)
{
  switch (msgType)
  {
  /* std stun */
  case STUN_MSG_BindRequestMsg:                   return "BindRequest";
  case STUN_MSG_BindResponseMsg:                  return "BindResponse";
  case STUN_MSG_BindIndicationMsg:                return "BindInd";
  case STUN_MSG_BindErrorResponseMsg:             return "BindErrorResponse";
  case STUN_MSG_AllocateRequestMsg:               return "AllocateRequest";
  case STUN_MSG_AllocateResponseMsg:              return "AllocateResponse";
  case STUN_MSG_AllocateErrorResponseMsg:         return "AllocateErrorResponse";
  case STUN_MSG_CreatePermissionRequestMsg:       return "CreatePermissionReq";
  case STUN_MSG_CreatePermissionResponseMsg:      return "CreatePermissionResp";
  case STUN_MSG_CreatePermissionErrorResponseMsg: return "CreatePermissionError";
  case STUN_MSG_ChannelBindRequestMsg:            return "ChannelBindRequest";
  case STUN_MSG_ChannelBindResponseMsg:           return "ChannelBindResponse";
  case STUN_MSG_ChannelBindErrorResponseMsg:      return
      "ChannelBindErrorResponse";
  case STUN_MSG_RefreshRequestMsg:                return "RefreshRequest";
  case STUN_MSG_RefreshResponseMsg:               return "RefreshResponse";
  case STUN_MSG_RefreshErrorResponseMsg:          return "RefreshErrorResponse";
  case STUN_MSG_DataIndicationMsg:                return "DataIndication";
  case STUN_MSG_SendIndicationMsg:                return "STUN_MSG_SendInd";
  case STUN_PathDiscoveryRequestMsg:              return "PathDiscReq";
  case STUN_PathDiscoveryResponseMsg:             return "PathDiscResp";
  case STUN_PathDiscoveryErrorResponseMsg:        return "PathDiscErrorResp";

  default:  return "???";
  }
}

/* calculate number of padding bytes for a given alignment */
static uint32_t
calcPadLen(uint32_t len,
           uint32_t allignment)
{
  return ( allignment - (len % allignment) ) % allignment;
}

/*** ENCODING ****/


static bool
stunEncodeHeader(StunMsgHdr* pMsgHdr,
                 uint8_t**   pBuf,
                 int*        nBufLen)
{
  if (*nBufLen < 20)
  {
    return false;
  }

  write_16(pBuf, pMsgHdr->msgType);
  write_16(pBuf, pMsgHdr->msgLength);

  /* cookie */
  write_8n(pBuf, StunCookie,        StunCookieSize);

  /* transaction id */
  write_8n(pBuf, pMsgHdr->id.octet, STUN_MSG_ID_SIZE);

  *nBufLen -= 20;
  return true;
}


static bool
stunEncodeIP4AddrAtr(StunAddress4* pAddr,
                     uint16_t      attrtype,
                     uint8_t**     pBuf,
                     int*          nBufLen)
{
  if (*nBufLen < 12)
  {
    return false;
  }
  write_16(pBuf, attrtype);   /* Attr type */
  write_16(pBuf, 8);          /* Lenght */
  write_16(pBuf, STUN_ADDR_IPv4Family);        /* 8 bit non used, 8 bit for
                                                * Family */
  write_16(pBuf, pAddr->port);
  write_32(pBuf, pAddr->addr);
  *nBufLen -= 12;
  return true;
}

/* */
static void
createXorId(uint8_t*   xorId,
            StunMsgId* pMsgId)
{
  /* magic cookie + transaction id */
  memcpy( xorId,     StunCookie, sizeof(StunCookie) );
  memcpy( xorId + 4, pMsgId,     STUN_MSG_ID_SIZE);
}

static bool
stunEncodeIP4AddrAtrXOR(StunAddress4* pAddr,
                        uint16_t      attrtype,
                        uint8_t**     pBuf,
                        int*          nBufLen,
                        StunMsgId*    pMsgId)
{
  uint8_t xorId[16];

  if (*nBufLen < 12)
  {
    return false;
  }

  createXorId(xorId, pMsgId);

  write_16(pBuf, attrtype);   /* Attr type */
  write_16(pBuf, 8);          /* Length */
  write_16(pBuf, STUN_ADDR_IPv4Family);        /* 8 bit non used, 8 bit for
                                                * Family */
  write_16_xor(pBuf, pAddr->port, xorId);
  write_32_xor(pBuf, pAddr->addr, xorId);
  *nBufLen -= 12;

  return true;
}

static bool
stunEncodeIP6AddrAtr(StunAddress6* pAddr,
                     uint16_t      attrtype,
                     uint8_t**     pBuf,
                     int*          nBufLen)
{
  if (*nBufLen < 24)
  {
    return false;
  }
  write_16(pBuf, attrtype);   /* Attr type */
  write_16(pBuf, 20);          /* Lenght */
  write_16(pBuf, STUN_ADDR_IPv6Family);        /* 8 bit non used, 8 bit for
                                                * Family */
  write_16(pBuf, pAddr->port);
  write_8(pBuf, pAddr->addr[0]);
  write_8(pBuf, pAddr->addr[1]);
  write_8(pBuf, pAddr->addr[2]);
  write_8(pBuf, pAddr->addr[3]);
  write_8(pBuf, pAddr->addr[4]);
  write_8(pBuf, pAddr->addr[5]);
  write_8(pBuf, pAddr->addr[6]);
  write_8(pBuf, pAddr->addr[7]);
  write_8(pBuf, pAddr->addr[8]);
  write_8(pBuf, pAddr->addr[9]);
  write_8(pBuf, pAddr->addr[10]);
  write_8(pBuf, pAddr->addr[11]);
  write_8(pBuf, pAddr->addr[12]);
  write_8(pBuf, pAddr->addr[13]);
  write_8(pBuf, pAddr->addr[14]);
  write_8(pBuf, pAddr->addr[15]);
  *nBufLen -= 24;
  return true;
}


static bool
stunEncodeIP6AddrAtrXOR(StunAddress6* pAddr,
                        uint16_t      attrtype,
                        uint8_t**     pBuf,
                        int*          nBufLen,
                        StunMsgId*    pMsgId)
{
  uint8_t xorId[16];
  createXorId(xorId, pMsgId);

  if (*nBufLen < 24)
  {
    return false;
  }
  write_16(pBuf, attrtype);   /* Attr type */
  write_16(pBuf, 20);          /* Lenght */
  write_16(pBuf, STUN_ADDR_IPv6Family);        /* 8 bit non used, 8 bit for
                                                * Family (always IPv4) or? */
  write_16_xor(pBuf, pAddr->port, xorId);
  write_8_xor(pBuf, pAddr->addr[0],  xorId);
  write_8_xor(pBuf, pAddr->addr[1],  xorId + 1);
  write_8_xor(pBuf, pAddr->addr[2],  xorId + 2);
  write_8_xor(pBuf, pAddr->addr[3],  xorId + 3);
  write_8_xor(pBuf, pAddr->addr[4],  xorId + 4);
  write_8_xor(pBuf, pAddr->addr[5],  xorId + 5);
  write_8_xor(pBuf, pAddr->addr[6],  xorId + 6);
  write_8_xor(pBuf, pAddr->addr[7],  xorId + 7);
  write_8_xor(pBuf, pAddr->addr[8],  xorId + 8);
  write_8_xor(pBuf, pAddr->addr[9],  xorId + 9);
  write_8_xor(pBuf, pAddr->addr[10], xorId + 10);
  write_8_xor(pBuf, pAddr->addr[11], xorId + 11);
  write_8_xor(pBuf, pAddr->addr[12], xorId + 12);
  write_8_xor(pBuf, pAddr->addr[13], xorId + 13);
  write_8_xor(pBuf, pAddr->addr[14], xorId + 14);
  write_8_xor(pBuf, pAddr->addr[15], xorId + 15);

  *nBufLen -= 24;
  return true;
}


static bool
stunEncodeIPAddrAtr(StunIPAddress* pAddr,
                    uint16_t       attrtype,
                    uint8_t**      pBuf,
                    int*           nBufLen)
{
  if ( pAddr && (pAddr->familyType == STUN_ADDR_IPv4Family) )
  {
    return stunEncodeIP4AddrAtr(&pAddr->addr.v4, attrtype, pBuf, nBufLen);
  }
  else if ( pAddr && (pAddr->familyType == STUN_ADDR_IPv6Family) )
  {
    return stunEncodeIP6AddrAtr(&pAddr->addr.v6, attrtype, pBuf, nBufLen);
  }
  else
  {
    printError( stderr, "unknown IP family type (%02x) to encode!\n",
                (pAddr ? pAddr->familyType : 0xdead) );
  }
  return false;
}


static bool
stunEncodeIPAddrAtrXOR(StunIPAddress* pAddr,
                       uint16_t       attrtype,
                       uint8_t**      pBuf,
                       int*           nBufLen,
                       StunMsgId*     pMsgId)
{
  if ( pAddr && (pAddr->familyType == STUN_ADDR_IPv4Family) )
  {
    return stunEncodeIP4AddrAtrXOR(&pAddr->addr.v4,
                                   attrtype,
                                   pBuf,
                                   nBufLen,
                                   pMsgId);
  }
  else if ( pAddr && (pAddr->familyType == STUN_ADDR_IPv6Family) )
  {
    return stunEncodeIP6AddrAtrXOR(&pAddr->addr.v6,
                                   attrtype,
                                   pBuf,
                                   nBufLen,
                                   pMsgId);
  }
  else
  {
    printError( stderr, "unknown IP family type (%x) to encode!\n",
                (pAddr ? pAddr->familyType : 0xdead) );
  }
  return false;
}

static bool
stunEncodeValueAtr(StunAtrValue* pChReq,
                   uint16_t      attrtype,
                   uint8_t**     pBuf,
                   int*          nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, attrtype);     /* Attr type */
  write_16(pBuf, 4);                 /* Length */
  write_32(pBuf, pChReq->value);
  *nBufLen -= 8;
  return true;
}

static bool
stunEncodeChannelAtr(StunAtrChannelNumber* channelAtr,
                     uint8_t**             pBuf,
                     int*                  nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_ChannelNumber);     /* Attr type */
  write_16(pBuf, 4);                           /* Length */
  write_16(pBuf, channelAtr->channelNumber);   /* channel */
  write_16(pBuf, channelAtr->rffu);            /* reserved */
  *nBufLen -= 8;
  return true;
}


static bool
stunEncodeDoubleValueAtr(StunAtrDoubleValue* pChReq,
                         uint16_t            attrtype,
                         uint8_t**           pBuf,
                         int*                nBufLen)
{
  if (*nBufLen < 12)
  {
    return false;
  }
  write_16(pBuf, attrtype);          /* Attr type */
  write_16(pBuf, 8);                 /* Length */
  write_64(pBuf, pChReq->value);
  *nBufLen -= 12;
  return true;
}


static bool
stunEncodeStringAtrAlligned(StunAtrString* pString,
                            uint16_t       attrtype,
                            uint8_t**      pBuf,
                            int*           nBufLen,
                            uint32_t       allignment)
{
  uint32_t padLen = calcPadLen(pString->sizeValue, allignment);
  write_16( pBuf, attrtype);              /* Attr type */
  write_16( pBuf, (pString->sizeValue) ); /* Attr length */
  write_8n(pBuf, (uint8_t*)pString->value, pString->sizeValue);
  if (padLen)
  {
    memset(*pBuf, pString->padChar, padLen);
  }
  *pBuf    += padLen;
  *nBufLen -= pString->sizeValue + padLen + 4;
  return true;
}


static bool
stunEncodeStringAtr(StunAtrString* pString,
                    uint16_t       attrtype,
                    uint8_t**      pBuf,
                    int*           nBufLen)
{
  return stunEncodeStringAtrAlligned(pString,
                                     attrtype,
                                     pBuf,
                                     nBufLen,
                                     STUN_STRING_ALLIGNMENT);
}


static bool
stunEncodeIntegrityAtr(StunAtrIntegrity* pIntg,
                       uint8_t**         pBuf,
                       int*              nBufLen,
                       int               packetLen)
{
  if (*nBufLen < 24)
  {
    return false;
  }
  /*Message Integrity is located offset bytes from the start of the packet.
   *  This is calculated by taking, whats left of packet(nBufLen), from the
   * packet len.
   *  pIntg->offset = (packetLen - *nBufLen);*/
  if (pIntg->offset == 0)
  {
    pIntg->offset = (packetLen - *nBufLen);
  }

  write_16(pBuf, STUN_ATTR_MessageIntegrity);     /* Attr type */
  write_16(pBuf, 20);                   /* Value length */
  write_8n(pBuf, pIntg->hash, 20);
  *nBufLen -= 24;
  return true;
}

static bool
stunEncodeFingerprintAtr(uint32_t  fingerprint,
                         uint8_t** pBuf,
                         int*      nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_FingerPrint);     /* Attr type */
  write_16(pBuf, 4);                 /* Length */
  write_32(pBuf, fingerprint);
  *nBufLen -= 8;
  return true;
}

static bool
stunEncodeErrorAtrAlligned(StunAtrError* pError,
                           uint8_t**     pBuf,
                           int*          nBufLen,
                           uint32_t      allignment,
                           char          padChar)
{
  uint32_t padLen = calcPadLen(pError->sizeReason, allignment);
  write_16( pBuf, STUN_ATTR_ErrorCode);         /* Attr type */
  write_16( pBuf, (4 + pError->sizeReason + padLen) ); /* Value length */
  write_16( pBuf, 0);                 /* The pad */

  write_8(pBuf, pError->errorClass & 0x7);
  write_8(pBuf, pError->number);              /* Error number 0-99 */
  write_8n(pBuf, (uint8_t*)pError->reason, pError->sizeReason);
  if (padLen)
  {
    memset(*pBuf, padChar, padLen);               /* Pad rest with space */
  }
  *pBuf    += padLen;
  *nBufLen -= 4 + 4 + pError->sizeReason + padLen;
  return true;
}



static bool
stunEncodeErrorAtr(StunAtrError* pError,
                   uint8_t**     pBuf,
                   int*          nBufLen)
{
  return stunEncodeErrorAtrAlligned(pError,
                                    pBuf,
                                    nBufLen,
                                    STUN_STRING_ALLIGNMENT,
                                    pError->padChar);
}


static bool
stunEncodeUnknownAtr(StunAtrUnknown* pUnk,
                     uint8_t**       pBuf,
                     int*            nBufLen)
{
  int i;
  int rest = pUnk->numAttributes % 2;
  if ( *nBufLen < 4 + ( (pUnk->numAttributes + rest) * 2 ) )
  {
    return false;
  }
  write_16( pBuf, STUN_ATTR_UnknownAttribute);
  write_16( pBuf, ( (pUnk->numAttributes) * 2 ) );
  for (i = 0; i < pUnk->numAttributes; i++)
  {
    write_16(pBuf, pUnk->attrType[i]);
  }
  if (rest)
  {
    write_16(pBuf, 0);
  }
  *nBufLen -= 4 + ( (pUnk->numAttributes + rest) * 2 );
  return true;
}


static bool
stunEncodeDataAtr(StunData* pData,
                  uint8_t** pBuf,
                  int*      nBufLen)
{
  uint32_t residue;
  uint32_t padding;

  residue = padding = 0;

  /* padding/alignment */
  residue = pData->dataLen % 4;
  if (residue > 0)
  {
    padding = 4 - residue;
  }

  if ( (uint32_t)(*nBufLen) < 4 + pData->dataLen + padding )
  {
    printError(stderr,
               "<stunEncodeDataAtr> Unable to encode data attr %d < 4 + %d + %d\n",
               (uint32_t)(*nBufLen),
               pData->dataLen,
               padding);
    return false;
  }
  write_16(pBuf, STUN_ATTR_Data);       /* Attr type */
  write_16(pBuf, pData->dataLen);          /* Length */

  /* If wanting to append data header to front of existing packet (avoid a copy)
   * then StunData struct will have been set-up with just the data len (and the
   * pData NULL)
   * it is then assumed that what follows (in *pBuf) is the data.
   */
  if (pData->pData != NULL)
  {
    write_8n(pBuf, pData->pData, pData->dataLen);
    if (residue > 0)
    {
      memset(*pBuf, '\xFF', padding);
    }
  }
  else
  {
    if (residue > 0)
    {
      memset(*pBuf + pData->dataLen, '\xFF', padding);
    }
  }
  *pBuf    += padding;
  *nBufLen -= (pData->dataLen + 4) + padding;
  return true;
}


static bool
stunEncodeFlagAtr(uint16_t  attrtype,
                  uint8_t** pBuf,
                  int*      nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }
  write_16(pBuf, attrtype);          /* Attr type */
  write_16(pBuf, 0);                 /* Length */
  *nBufLen -= 4;
  return true;
}

static bool
stunEncodeRequestedTransport(StunAtrRequestedTransport* pReqTrnsp,
                             uint8_t**                  pBuf,
                             int*                       nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, (uint8_t)STUN_ATTR_RequestedTransport);   /* Attr type */
  write_16(pBuf, 4);                                       /* Length */
  write_8(pBuf, pReqTrnsp->protocol);                      /* protocol */
  write_8n( pBuf, pReqTrnsp->rffu, sizeof(pReqTrnsp->rffu) ); /* reserved */
  *nBufLen -= 8;
  return true;
}


static bool
stunEncodeRequestedAddrFamily(StunAttrRequestedAddrFamily* pReqAddrFam,
                              uint8_t**                    pBuf,
                              int*                         nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, (uint8_t)STUN_ATTR_RequestedAddrFamily);   /* Attr type */
  write_16(pBuf, 4);                                       /* Length */
  write_8(pBuf, pReqAddrFam->family);                      /* family */
  write_8n( pBuf, pReqAddrFam->rffu, sizeof(pReqAddrFam->rffu) ); /* reserved */
  *nBufLen -= 8;
  return true;
}

static bool
stunEncodeEvenPort(StunAtrEvenPort* pEvenPort,
                   uint8_t**        pBuf,
                   int*             nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_EvenPort);   /* Attr type with R bit set */
  write_16(pBuf, 1);                    /* Length */
  write_8(pBuf, pEvenPort->evenPort);

  write_8n( pBuf, pEvenPort->pad, sizeof(pEvenPort->pad) );
  *nBufLen -= 8;
  return true;
}

static bool
stunEncodeEnfFlowDescription(StunAtrEnfFlowDescription* pStreamType,
                             uint8_t**                  pBuf,
                             int*                       nBufLen)
{
  if (*nBufLen < 24)
  {
    return false;
  }
  uint8_t typeAndTbd = pStreamType->type << 4;
  write_16(pBuf, STUN_ATTR_EnfFlowDescription);   /* Attr type */

  write_16(pBuf, 3);                    /* Length */
  write_8(pBuf, typeAndTbd);
  write_16(pBuf, pStreamType->bandwidthMax);
  write_8(pBuf, pStreamType->pad);
  *nBufLen -= 8;
  return true;
}


static bool
stunEncodeEnfNetworkStatus(StunAtrEnfNetworkStatus* pNetworkStatus,
                           uint8_t**                pBuf,
                           int*                     nBufLen)
{
  if (*nBufLen < 32)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_EnfNetworkStatus);   /* Attr type */
  write_16(pBuf, 8);                    /* Length */
  write_8(pBuf, pNetworkStatus->flags);
  write_8(pBuf, pNetworkStatus->nodeCnt);
  write_16(pBuf, pNetworkStatus->tbd);
  write_16(pBuf, pNetworkStatus->upMaxBandwidth);
  write_16(pBuf, pNetworkStatus->downMaxBandwidth);

  *nBufLen -= 12;
  return true;
}

static bool
stunEncodeTransCount(StunAtrTransCount* pTransCount,
                     uint8_t**          pBuf,
                     int*               nBufLen)
{
  if (*nBufLen < 24)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_TransCount);   /* Attr type */
  write_16(pBuf, 4);                    /* Length */
  write_16(pBuf, pTransCount->reserved);
  write_8(pBuf, pTransCount->reqCnt);
  write_8(pBuf, pTransCount->respCnt);

  *nBufLen -= 8;
  return true;
}

static bool
stunEncodeTTL(StunAtrTTL* pTTL,
              uint8_t**   pBuf,
              int*        nBufLen)
{
  if (*nBufLen < 32)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_TTL);   /* Attr type */
  write_16(pBuf, 4);                    /* Length */
  write_8(pBuf, pTTL->ttl);
  write_8(pBuf, pTTL->pad_8);
  write_16(pBuf, pTTL->pad_16);

  *nBufLen -= 8;
  return true;
}

#if 0
static bool
stunEncodeCiscoNetworkFeedback(StunAtrCiscoNetworkFeedback* ciscoNetFeed,
                               uint8_t**                    pBuf,
                               int*                         nBufLen)
{
  if (*nBufLen < 32)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_Cisco_Network_Feedback);   /* Attr type */
  write_16(pBuf, 12);                    /* Length */
  write_32(pBuf, ciscoNetFeed->first);
  write_32(pBuf, ciscoNetFeed->second);
  write_32(pBuf, ciscoNetFeed->third);

  *nBufLen -= 16;
  return true;
}


static bool
encodeStunAtrBandwidthUsage* pBandwidthUsage,
                           uint8_t**              pBuf,
int*                   nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }
  write_16(pBuf, STUN_ATTR_BandwidthUsage);   /* Attr type */
  write_16(pBuf, 4);                    /* Length */
  write_16(pBuf, pBandwidthUsage->average);
  write_16(pBuf, pBandwidthUsage->max);

  *nBufLen -= 8;
  return true;
}
#endif

static uint32_t
stunlib_EncodeIndication(uint8_t                msgType,
                         uint8_t*               stunBuf,
                         uint8_t*               dataBuf,
                         uint32_t               maxBufSize,
                         uint32_t               payloadLength,
                         const struct sockaddr* dstAddr)
{
  StunMessage   stunMsg;
  StunIPAddress activeDstAddr;
  int           length = 0;

  memset( &stunMsg, 0, sizeof(StunMessage) );
  stunlib_createId(&stunMsg.msgHdr.id);

  if (dstAddr->sa_family == AF_INET)
  {

    activeDstAddr.familyType   =  STUN_ADDR_IPv4Family;
    activeDstAddr.addr.v4.port = ntohs(
      ( (struct sockaddr_in*)dstAddr )->sin_port);
    activeDstAddr.addr.v4.addr = ntohl(
      ( (struct sockaddr_in*)dstAddr )->sin_addr.s_addr);

  }
  else if (dstAddr->sa_family == AF_INET6)
  {
    activeDstAddr.familyType   =  STUN_ADDR_IPv6Family;
    activeDstAddr.addr.v6.port = ntohs(
      ( (struct sockaddr_in6*)dstAddr )->sin6_port);
    memcpy( activeDstAddr.addr.v6.addr,
            ( (struct sockaddr_in6*)dstAddr )->sin6_addr.s6_addr,
            sizeof(activeDstAddr.addr.v6.addr) );

  }
  else
  {
    return 0;
  }

  /* STD TURN: sendInd(XorPeerAddr, Data)   no integrity */
  stunMsg.msgHdr.msgType     = msgType;
  stunMsg.xorPeerAddrEntries = 1;
  memcpy( &stunMsg.xorPeerAddress[0], &activeDstAddr, sizeof(StunIPAddress) );
  stunMsg.hasData      = true;
  stunMsg.data.dataLen = payloadLength;
  stunMsg.data.pData   = dataBuf;               /*The data (RTP packet) follows
                                                 * anyway..*/

  length = stunlib_encodeMessage(&stunMsg,
                                 stunBuf,
                                 maxBufSize,
                                 NULL, /* no message integrity */
                                 0,    /* no message integrity */
                                 NULL); /* stream */

  return length;
}


uint32_t
stunlib_EncodeSendIndication(uint8_t*               stunBuf,
                             uint8_t*               dataBuf,
                             uint32_t               maxBufSize,
                             uint32_t               payloadLength,
                             const struct sockaddr* dstAddr)
{
  return stunlib_EncodeIndication(
    STUN_MSG_SendIndicationMsg,
    stunBuf,
    dataBuf,
    maxBufSize,
    payloadLength,
    dstAddr);
}

uint32_t
stunlib_EncodeDataIndication(uint8_t*               stunBuf,
                             uint8_t*               dataBuf,
                             uint32_t               maxBufSize,
                             uint32_t               payloadLength,
                             const struct sockaddr* dstAddr)
{
  return stunlib_EncodeIndication(
    STUN_MSG_DataIndicationMsg,
    stunBuf,
    dataBuf,
    maxBufSize,
    payloadLength,
    dstAddr);
}



/**** DECODING *****/

static bool
stunDecodeHeader(StunMsgHdr*     pMsgHdr,
                 const uint8_t** pBuf,
                 int*            nBufLen)
{
  memset( pMsgHdr, 0, sizeof(StunMsgHdr) );

  read_16(pBuf, &pMsgHdr->msgType);
  read_16(pBuf, &pMsgHdr->msgLength);

  /* cookie */
  read_8n( pBuf, pMsgHdr->cookie.octet, sizeof(StunMsgCookie) );

  /* transaction id */
  read_8n( pBuf, pMsgHdr->id.octet,     STUN_MSG_ID_SIZE);
  *nBufLen -= 20;
  return true;
}


static bool
stunDecodeAttributeHead(StunAtrHdr*     pAtrHdr,
                        const uint8_t** pBuf,
                        int*            nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_16(pBuf, &pAtrHdr->type);
  read_16(pBuf, &pAtrHdr->length);
  *nBufLen -= 4;
  return true;
}

static bool
stunDecodeStringAtrAlligned(StunAtrString*  pStr,
                            const uint8_t** pBuf,
                            int*            nBufLen,
                            int             atrLen,
                            uint32_t        allignment)
{
  int      len;
  uint32_t padLen = calcPadLen(atrLen, allignment);

  if (*nBufLen < atrLen)
  {
    printError(stderr,
               "stunDecodeStringAtr: failed nBufLen %d atrLen %d\n",
               *nBufLen,
               atrLen);
    return false;
  }

  len             = min(STUN_MAX_STRING, atrLen);
  pStr->sizeValue = len;
  read_8n(pBuf, (uint8_t*)pStr->value, len);
  *pBuf    += padLen;
  *nBufLen -= (atrLen + padLen);
  return true;
}


static bool
stunDecodeStringAtr(StunAtrString*  pStr,
                    const uint8_t** pBuf,
                    int*            nBufLen,
                    int             atrLen)
{
  return stunDecodeStringAtrAlligned(pStr,
                                     pBuf,
                                     nBufLen,
                                     atrLen,
                                     STUN_STRING_ALLIGNMENT);
}

static bool
stunDecodeValueAtr(StunAtrValue*   pVal,
                   const uint8_t** pBuf,
                   int*            nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_32(pBuf, &pVal->value);
  *nBufLen -= 4;
  return true;
}

static bool
stunDecodeChannelAtr(StunAtrChannelNumber* channelAtr,
                     const uint8_t**       pBuf,
                     int*                  nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_16(pBuf, &channelAtr->channelNumber);
  read_16(pBuf, &channelAtr->rffu);
  *nBufLen -= 4;
  return true;
}

static bool
stunDecodeEvenPortAtr(StunAtrEvenPort* evenPortAtr,
                      const uint8_t**  pBuf,
                      int*             nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_8(pBuf, &evenPortAtr->evenPort);
  read_8n( pBuf, evenPortAtr->pad, sizeof(evenPortAtr->pad) );
  *nBufLen -= 4;
  return true;
}


static bool
stunDecodeRequestedTransportAtr(StunAtrRequestedTransport* reqTransAtr,
                                const uint8_t**            pBuf,
                                int*                       nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_8(pBuf, &reqTransAtr->protocol);
  read_8n( pBuf, reqTransAtr->rffu, sizeof(reqTransAtr->rffu) );
  *nBufLen -= 4;
  return true;
}

static bool
stunDecodeRequestedAddrFamilyAtr(StunAttrRequestedAddrFamily* reqAddrFamily,
                                 const uint8_t**              pBuf,
                                 int*                         nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_8(pBuf, &reqAddrFamily->family);
  read_8n( pBuf, reqAddrFamily->rffu, sizeof(reqAddrFamily->rffu) );
  *nBufLen -= 4;
  return true;
}




static bool
stunDecodeDoubleValueAtr(StunAtrDoubleValue* pVal,
                         const uint8_t**     pBuf,
                         int*                nBufLen)
{
  if (*nBufLen < 8)
  {
    return false;
  }

  read_64(pBuf, &pVal->value);
  *nBufLen -= 8;

  return true;
}

static bool
stunDecodeIPAddrAtr(StunIPAddress*  pAddr,
                    const uint8_t** pBuf,
                    int*            nBufLen)
{
  uint16_t flagtype;
  if (*nBufLen < 2)
  {
    return false;
  }

  read_16(pBuf, &flagtype);
  pAddr->familyType = (flagtype & 0xff);

  if (pAddr->familyType == STUN_ADDR_IPv4Family)
  {
    if (*nBufLen < 6)
    {
      return false;
    }
    read_16(pBuf, &pAddr->addr.v4.port);
    read_32(pBuf, &pAddr->addr.v4.addr);
    *nBufLen -= 8;
  }
  else if (pAddr->familyType == STUN_ADDR_IPv6Family)
  {
    if (*nBufLen < 18)
    {
      return false;
    }
    read_16(pBuf, &pAddr->addr.v6.port);
    read_8(pBuf, &pAddr->addr.v6.addr[0]);
    read_8(pBuf, &pAddr->addr.v6.addr[1]);
    read_8(pBuf, &pAddr->addr.v6.addr[2]);
    read_8(pBuf, &pAddr->addr.v6.addr[3]);
    read_8(pBuf, &pAddr->addr.v6.addr[4]);
    read_8(pBuf, &pAddr->addr.v6.addr[5]);
    read_8(pBuf, &pAddr->addr.v6.addr[6]);
    read_8(pBuf, &pAddr->addr.v6.addr[7]);
    read_8(pBuf, &pAddr->addr.v6.addr[8]);
    read_8(pBuf, &pAddr->addr.v6.addr[9]);
    read_8(pBuf, &pAddr->addr.v6.addr[10]);
    read_8(pBuf, &pAddr->addr.v6.addr[11]);
    read_8(pBuf, &pAddr->addr.v6.addr[12]);
    read_8(pBuf, &pAddr->addr.v6.addr[13]);
    read_8(pBuf, &pAddr->addr.v6.addr[14]);
    read_8(pBuf, &pAddr->addr.v6.addr[15]);

    *nBufLen -= 20;
  }
  else
  {
    printError(stderr,
               "Decode IP: Got unfamiliar IP family type: %02x\n",
               flagtype & 0xff);
    return false;
  }
  return true;
}

static bool
stunDecodeIPAddrAtrXOR(StunIPAddress*  pAddr,
                       const uint8_t** pBuf,
                       int*            nBufLen,
                       StunMsgId*      pMsgId)
{
  uint16_t flagtype;
  uint8_t  xorId[16];
  if (*nBufLen < 2)
  {
    return false;
  }

  createXorId(xorId, pMsgId);

  read_16(pBuf, &flagtype);
  pAddr->familyType = (flagtype & 0xff);

  if (pAddr->familyType == STUN_ADDR_IPv4Family)
  {
    if (*nBufLen < 6)
    {
      return false;
    }
    read_16_xor(pBuf, &pAddr->addr.v4.port, xorId);
    read_32_xor(pBuf, &pAddr->addr.v4.addr, xorId);
    *nBufLen -= 8;
  }
  else if (pAddr->familyType == STUN_ADDR_IPv6Family)
  {
    if (*nBufLen < 18)
    {
      return false;
    }
    read_16_xor(pBuf, &pAddr->addr.v6.port, xorId);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[0],  xorId);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[1],  xorId + 1);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[2],  xorId + 2);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[3],  xorId + 3);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[4],  xorId + 4);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[5],  xorId + 5);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[6],  xorId + 6);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[7],  xorId + 7);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[8],  xorId + 8);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[9],  xorId + 9);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[10], xorId + 10);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[11], xorId + 11);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[12], xorId + 12);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[13], xorId + 13);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[14], xorId + 14);
    read_8_xor(pBuf, &pAddr->addr.v6.addr[15], xorId + 15);
    *nBufLen -= 20;

  }
  else
  {
    printError(stderr,
               "Decode IP: Got unfamiliar IP family type: %02x\n",
               flagtype & 0xff);
    return false;
  }
  return true;
}




static bool
stunDecodeIntegrityAtr(StunAtrIntegrity* pIntg,
                       const uint8_t**   pBuf,
                       int*              nBufLen,
                       int               packetLen)
{
  if (*nBufLen < 20)
  {
    return false;
  }
  /* Message Integrity is located offset bytes from the start of the packet.
   *  This is calulated by taking, whats left from this attribute value to end
   * of packet(nBufLen),
   *  plus the 4 bytes attribute header, from the packet len.*/

  pIntg->offset = ( packetLen -  (*nBufLen + 4) );
  read_8n(pBuf, pIntg->hash, 20);
  *nBufLen -= 20;
  return true;
}

static bool
stunDecodeErrorAtrAlligned(StunAtrError*   pError,
                           const uint8_t** pBuf,
                           int*            nBufLen,
                           int             atrLen,
                           uint32_t        allignment)
{
  uint32_t padLen = calcPadLen(atrLen, allignment);

  if ( (*nBufLen < atrLen) || (atrLen < 4) )
  {
    printError(stderr,
               "stunDecodeErrorAtr: failed nBufLen %d atrLen %d\n",
               *nBufLen,
               atrLen);
    return false;
  }
  read_16(pBuf, &pError->reserved);
  read_8(pBuf, &pError->errorClass);          /* The Error clase, number from
                                               * 1-6 */
  read_8(pBuf, &pError->number);              /* Error number 0-99 */
  read_8n(pBuf, (uint8_t*)pError->reason, atrLen - 4);  /* reason string */
  pError->sizeReason = atrLen - 4;
  *pBuf             += padLen;
  *nBufLen          -= (atrLen + padLen);
  return true;
}


static bool
stunDecodeErrorAtr(StunAtrError*   pError,
                   const uint8_t** pBuf,
                   int*            nBufLen,
                   int             atrLen)
{
  return stunDecodeErrorAtrAlligned(pError,
                                    pBuf,
                                    nBufLen,
                                    atrLen,
                                    STUN_STRING_ALLIGNMENT);

}


static bool
stunDecodeUnknownAtr(StunAtrUnknown* pUnk,
                     const uint8_t** pBuf,
                     int*            nBufLen,
                     int             atrLen)
{
  uint32_t padLen = calcPadLen(atrLen, 4);
  int      i;
  if (*nBufLen < atrLen)
  {
    return false;
  }
  for (i = 0; i < STUN_MAX_UNKNOWN_ATTRIBUTES && i < (atrLen / 2); i++)
  {
    read_16(pBuf, &pUnk->attrType[i]);
  }
  pUnk->numAttributes = i;
  *nBufLen           -= (atrLen + padLen);
  *pBuf              += padLen;
  if ( i < (atrLen / 2) )
  {
    *nBufLen -= (atrLen - 2 * i);
  }
  return true;
}


static bool
stunDecodeDataAtr(StunData*       pData,
                  const uint8_t** pBuf,
                  int*            nBufLen,
                  int             atrLen,
                  int             stunBufLen)
{
  if (*nBufLen < atrLen)
  {
    return false;
  }

  pData->offset  = stunBufLen - *nBufLen;
  pData->dataLen = atrLen;
  pData->pData   = (uint8_t*)*pBuf;
  *pBuf         += atrLen;
  if ( (atrLen % 4 == 0) )
  {
    *nBufLen -= atrLen;
  }
  else
  {
    *nBufLen -= ( atrLen + (4 - atrLen % 4) );
  }

  return true;
}


static bool
stunDecodeEnfFlowDescription(StunAtrEnfFlowDescription* streamTypeAtr,
                             const uint8_t**            pBuf,
                             int*                       nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }
  uint8_t typeAndTbd;
  read_8(pBuf, &typeAndTbd);
  streamTypeAtr->type = typeAndTbd >> 4;
  read_16(pBuf, &streamTypeAtr->bandwidthMax);
  read_8(pBuf, &streamTypeAtr->pad);
  *nBufLen -= 4;
  return true;
}


static bool
stunDecodeEnfNetworkStatus(StunAtrEnfNetworkStatus* networkStatusAtr,
                           const uint8_t**          pBuf,
                           int*                     nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_8(pBuf, &networkStatusAtr->flags);
  read_8(pBuf, &networkStatusAtr->nodeCnt);
  read_16(pBuf, &networkStatusAtr->tbd);
  read_16(pBuf, &networkStatusAtr->upMaxBandwidth);
  read_16(pBuf, &networkStatusAtr->downMaxBandwidth);

  *nBufLen -= 8;
  return true;
}

static bool
stunDecodeTransCount(StunAtrTransCount* transCountAtr,
                     const uint8_t**    pBuf,
                     int*               nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }
  read_16(pBuf, &transCountAtr->reserved);
  read_8(pBuf, &transCountAtr->reqCnt);
  read_8(pBuf, &transCountAtr->respCnt);

  *nBufLen -= 4;
  return true;
}


static bool
stunDecodeTTL(StunAtrTTL*     ttl,
              const uint8_t** pBuf,
              int*            nBufLen)
{
  if (*nBufLen < 4)
  {
    return false;
  }

  read_8(pBuf, &ttl->ttl);
  read_8(pBuf, &ttl->pad_8);
  read_16(pBuf, &ttl->pad_16);

  *nBufLen -= 4;
  return true;
}


/**** DEBUGGING ****/

static void
stun_printIP4Address(FILE*               stream,
                     char const*         szHead,
                     const StunAddress4* pAdr)
{
  printError(stream, "  %s \t= {%d.%d.%d.%d:%d}\n", szHead,
             pAdr->addr >> 24 & 0xff,
             pAdr->addr >> 16 & 0xff,
             pAdr->addr >> 8 & 0xff,
             pAdr->addr  & 0xff,
             pAdr->port);
}


static void
stun_printIP6Address(FILE*               stream,
                     char const*         szHead,
                     const StunAddress6* pAdr)
{
  if (stream)
  {
    printError(stream,
               "  %s \t= { %02x%02x : %02x%02x : %02x%02x : %02x%02x : %02x%02x : %02x%02x : %02x%02x : %02x%02x - %d}\n",
               szHead,
               pAdr->addr[0],
               pAdr->addr[1],
               pAdr->addr[2],
               pAdr->addr[3],
               pAdr->addr[4],
               pAdr->addr[5],
               pAdr->addr[6],
               pAdr->addr[7],
               pAdr->addr[8],
               pAdr->addr[9],
               pAdr->addr[10],
               pAdr->addr[11],
               pAdr->addr[12],
               pAdr->addr[13],
               pAdr->addr[14],
               pAdr->addr[15],
               pAdr->port);
  }
}


static void
stun_printIPAddress(FILE*                stream,
                    char const*          szHead,
                    const StunIPAddress* pAdr)
{
  if (pAdr->familyType == STUN_ADDR_IPv4Family)
  {
    stun_printIP4Address(stream,szHead, &pAdr->addr.v4);
  }
  else if (pAdr->familyType == STUN_ADDR_IPv6Family)
  {
    stun_printIP6Address(stream, szHead, &pAdr->addr.v6);
  }
  else
  {
    printError(stream,
               "  %s \t [Illegal IP family type: %02x]\n",
               szHead,
               pAdr->familyType);
  }
}


static void
stun_printString(FILE*                stream,
                 char const*          szHead,
                 const StunAtrString* pStr)
{
  char buf[1512];
  memcpy(buf, pStr->value, pStr->sizeValue);
  buf[pStr->sizeValue] = '\0';
  printError(stream,"  %s \t= \"%s\"\n", szHead, buf);
}


static void
stun_printValue(FILE*               stream,
                char const*         szHead,
                const StunAtrValue* pVal)
{
  printError(stream, "  %s \t= 0x%04x\n", szHead, pVal->value);
}

static void
stun_printByteValue(FILE*          stream,
                    char const*    szHead,
                    const uint8_t* pVal)
{
  printError(stream, "  %s \t= 0x%02x\n", szHead, *pVal);
}


static void
stun_printDoubleValue(FILE*                     stream,
                      char const*               szHead,
                      const StunAtrDoubleValue* pVal)
{

  printError(stream, "  %s \t= ", szHead);
  printError(stream, "0x%llx",    pVal->value);
  printError(stream, "\n");
}


static void
stun_printFlag(FILE*       stream,
               char const* szHead,
               bool        bIsSet)
{
  printError( stream, "  %s \t= %s\n", szHead, (bIsSet ? "true" : "false") );
}


static void
stun_printErrorCode(FILE*               stream,
                    const StunAtrError* pErr)
{
  char buf[1512];
  memcpy(buf, pErr->reason, pErr->sizeReason);
  buf[pErr->sizeReason] = '\0';
  printError(stream, "  error = {%d %d, \"%s\"[%d]}\n",
             pErr->errorClass, pErr->number, buf, pErr->sizeReason);
}

static void
stun_printUnknown(FILE*                 stream,
                  const StunAtrUnknown* pUnk)
{
  int i;
  printError(stream, "  unknownAttribute = [%d]{", pUnk->numAttributes);
  for (i = 0; i < pUnk->numAttributes; i++)
  {
    printError(stream,
               "%c%04x ",
               (i ? ',' : ' '),
               pUnk->attrType[i]);
  }
  printError(stream, "\n");
}


static void
stun_printData(FILE*           stream,
               char const*     szHead,
               const StunData* pData)
{
  if (!szHead || !pData)
  {
    return;
  }
  printError(stream,
             "  %s \t= %p (%d)\n",
             szHead,
             pData->pData,
             pData->dataLen);
}

void
stun_printTransId(FILE*            stream,
                  const StunMsgId* pId)
{
  int i;
  for (i = 0; i < 12; i++)
  {
    printError(stream, " %02x", pId->octet[i]);
  }

}

void
stun_printMessage(FILE*              stream,
                  const StunMessage* pMsg)
{
  uint32_t           i;
  const StunMessage* message = pMsg;
  if (!pMsg)
  {
    printError(stream, "NULL\n");
    return;
  }
  printError(stream, "{\n");
  printError(stream, "  msgHdr.type \t= %d\n",   pMsg->msgHdr.msgType);
  printError(stream, "  msgHdr.length \t= %d\n", pMsg->msgHdr.msgLength);
  printError(stream, "  msgHdr.id[] \t = ");

  stun_printTransId(stream, &pMsg->msgHdr.id);
  printError(stream, "\n");


  /* First write all attributes to calculate total length.... */
  if (message->hasMappedAddress)
  {
    stun_printIPAddress(stream, "mappedAddress", &pMsg->mappedAddress);
  }

  if (message->hasNonce)
  {
    stun_printString(stream, "nonce", &message->nonce);
  }

  if (message->hasRealm)
  {
    stun_printString(stream, "realm", &message->realm);
  }

  if (message->hasUsername)
  {
    stun_printString(stream, "username", &message->username);
  }

  if (message->hasErrorCode)
  {
    stun_printErrorCode(stream, &message->errorCode);
  }

  if (message->hasUnknownAttributes)
  {
    stun_printUnknown(stream, &message->unknownAttributes);
  }

  if (message->hasXorMappedAddress)
  {
    stun_printIPAddress(stream, "xorMappedAddress", &message->xorMappedAddress);
  }

  if (message->hasSoftware)
  {
    stun_printString(stream, "softwareName", &message->software);
  }

  /* TURN usage specific attributes */
  if (message->hasXorRelayAddressIPv4)
  {
    stun_printIPAddress(stream,
                        "xorRelayAddressIPv4",
                        &pMsg->xorRelayAddressIPv4);
  }

  if (message->hasXorRelayAddressIPv6)
  {
    stun_printIPAddress(stream,
                        "xorRelayAddressIPv6",
                        &pMsg->xorRelayAddressIPv6);
  }

  if (message->hasLifetime)
  {
    stun_printValue(stream, "lifetime", &message->lifetime);
  }

  if (message->hasAlternateServer)
  {
    stun_printIPAddress(stream, "alternateServer", &message->alternateServer);
  }

  if (message->xorPeerAddrEntries)
  {
    for (i = 0; i < message->xorPeerAddrEntries; i++)
    {
      stun_printIPAddress(stream, "xorPeerAddress",
                          &message->xorPeerAddress[i]);
    }
  }

  if (message->hasData)
  {
    stun_printData(stream, "data", &message->data);
  }

  if (message->hasPriority)
  {
    stun_printValue(stream, "priority", &message->priority);
  }

  if (message->hasUseCandidate)
  {
    stun_printFlag(stream, "useCandidate", true);
  }

  if (message->hasDontFragment)
  {
    stun_printFlag(stream, "Dontfragment", true);
  }

  if (message->hasEvenPort)
  {
    stun_printByteValue(stream, "evenPort", &message->evenPort.evenPort);
  }

  if (message->hasReservationToken)
  {
    stun_printDoubleValue(stream, "reservationToken",
                          &message->reservationToken);
  }

  if (message->hasControlling)
  {
    stun_printDoubleValue(stream, "controlling", &message->controlling);
  }

  if (message->hasControlled)
  {
    stun_printDoubleValue(stream, "controlled", &message->controlled);
  }

  if (message->hasMessageIntegrity)
  {
    printError(stream,
               "  integrity.offset = %02u",
               message->messageIntegrity.offset);
    printError(stream, "  integrity.hash[] = ");
    for (i = 0; i < 20; i++)
    {
      printError(stream, "%02x ", message->messageIntegrity.hash[i]);
    }
    printError(stream, "\n");
  }

  printError(stream, "}\n");
}

void
stunlib_printBuffer(FILE*          stream,
                    const uint8_t* pBuf,
                    int            len,
                    char const*    szHead)
{
  int i;
  int linecnt = 0;

  printError(stream, "%s Buffer (%i) = [\n", szHead, len);
  for (i = 0; i < len; i++, linecnt++)
  {
    if (linecnt == 4)
    {
      printError(stream, ",\n");
      linecnt = 0;

    }
    else
    {
      printError( stream, "%c", (linecnt ? ',' : ' ') );
    }
    printError( stream, " %02x", (uint8_t)( *( (pBuf + i) ) ) );
  }
  printError(stream, "];\n");
}

char const*
stunlib_getErrorReason(uint16_t errorClass,
                       uint16_t errorNumber)
{
  switch (errorClass * 100 + errorNumber)
  {
  case STUN_ERROR_TRY_ALTERNATE:     return "Try Alternate"; break;
  case STUN_ERROR_BAD_REQUEST:       return "Bad Request"; break;
  case STUN_ERROR_UNAUTHORIZED:      return "Unauthorized"; break;
  case STUN_ERROR_UNKNOWN_ATTR:      return "Unknown Attribute"; break;
  case STUN_ERROR_STALE_CREDS:       return "Stale Credentials"; break;
  case STUN_ERROR_INTEG_CHECK_FAIL:  return "Integrity Check Failure"; break;
  case STUN_ERROR_MISSING_USERNAME:  return "Missing Username"; break;
  case STUN_ERROR_NO_BINDING:        return "No Binding"; break;
  case STUN_ERROR_STALE_NONCE:       return "Stale Nonce"; break;
  case STUN_ERROR_WRONG_USERNAME:    return "Wrong Username"; break;
  case STUN_ERROR_UNSUPPORTED_PROTO: return "Unsupported Transport Protocol";
    break;
  case STUN_ERROR_SERVER_ERROR:      return "Server Error"; break;
  case STUN_ERROR_GLOBAL_FAIL:       return "Global Failure"; break;
  case STUN_ERROR_QUOTA_REACHED:     return "Allocation Quota Reached"; break;
  case STUN_ERROR_INSUFFICIENT_CAPACITY: return "Insufficient Capacity"; break;
  case STUN_ERROR_ROLE_CONFLICT:     return "Role Conflict"; break;
  default: return "???";
  }
}


/*
 *  There is 1 format supported, which is standard stun.
 *
 *   RFC5389
 *   -------
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |0 0|     STUN Message Type     |         Message Length        |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                RFC5389  Magic Cookie                          |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                                                               |
 *      |                     Transaction ID (96 bits)                  |
 *      |                                                               |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */
bool
stunlib_isStunMsg(const uint8_t* payload,
                  uint16_t       length)
{
  /* first 2 bits must be 00, STUN header and magic cookie */
  return ( ( (*payload & STUN_PACKET_MASK) == STUN_PACKET )
           &&  (length >= 20)
           &&  (memcmp(payload + 4, (void*)StunCookie, StunCookieSize) == 0) );
}

uint16_t
stunlib_StunMsgLen(const uint8_t* payload)
{
  uint16_t length = *(payload + 2);
  length = length << 8;
  length = length | *(payload + 3);

  return length;
}

/* Channel data has first 2 bits = 01 */
bool
stunlib_isTurnChannelData(const uint8_t* payload)
{
  return ( (*payload & STUN_PACKET_MASK) == TURN_CHANNEL_PACKET );
}

bool
stunlib_isRequest(const StunMessage* msg)
{
  return (msg->msgHdr.msgType & STUN_CLASS_MASK) == STUN_CLASS_REQUEST;
}

bool
stunlib_isSuccessResponse(const StunMessage* msg)
{
  return (msg->msgHdr.msgType & STUN_CLASS_MASK) == STUN_CLASS_SUCCESS_RESP;
}

bool
stunlib_isErrorResponse(const StunMessage* msg)
{
  return (msg->msgHdr.msgType & STUN_CLASS_MASK) == STUN_CLASS_ERROR_RESP;
}

bool
stunlib_isResponse(const StunMessage* msg)
{
  return ( stunlib_isSuccessResponse(msg) || stunlib_isErrorResponse(msg) );
}

bool
stunlib_isIndication(const StunMessage* msg)
{
  return (msg->msgHdr.msgType & STUN_CLASS_MASK) == STUN_CLASS_INDICATION;
}


bool
stunlib_DecodeMessage(const uint8_t*  buf,
                      size_t          bufLen,
                      StunMessage*    message,
                      StunAtrUnknown* unknowns,
                      FILE*           stream)
{
  const uint8_t* pCurrPtr;
  int            restlen = bufLen;
  StunAtrHdr     sAtr;

  if ( !buf || !message || (bufLen < STUN_MIN_PACKET_SIZE) ||
       (bufLen > STUN_MAX_PACKET_SIZE) )
  {
    if (stream)
    {
      printError(stderr, "No buffer or no message recieved\n");
    }
    return false;
  }

  memset( message, 0, sizeof(StunMessage) );

  if (unknowns)
  {
    unknowns->numAttributes = 0;
  }
  if (stream)
  {
    printError(stream,"STUN_parse, buffer to parse: \n");
    stunlib_printBuffer(stream, (uint8_t*)buf, bufLen, "STUN");
  }

  pCurrPtr = (uint8_t*)buf;

  if ( !stunDecodeHeader(&message->msgHdr, &pCurrPtr, &restlen) )
  {
    printError(stream,
               "stunlib_DecodeMessage: Failed to decode message header! (%d, %p)\n",
               restlen,
               pCurrPtr);
    return false;
  }
  if (stream)
  {
    printError(stream, "After parsed header:\n");
    stun_printMessage(stream, message);
  }
  if (restlen < message->msgHdr.msgLength)
  {
    printError(stream,
               "stunlib_DecodeMessage: The length in msg (%d) is larger than rest of buffer (%d)!\n",
               message->msgHdr.msgLength,
               restlen);
    return false;     /* Should perhaps be == to avoid extra stuff */
  }
  restlen = message->msgHdr.msgLength;
  while (restlen > 0)
  {
    if (stream)
    {
      printError(stream,
                 "Parsing attribute head with restlen=%d at %p\n",
                 restlen,
                 pCurrPtr);
    }
    if ( !stunDecodeAttributeHead(&sAtr, &pCurrPtr, &restlen) )
    {
      if (stream)
      {
        printError(stream,
                   "stunlib_DecodeMessage: Failed to parse Attribute head (%d)\n",
                   restlen);
      }
      return false;
    }
    if (stream)
    {
      printError(stream,
                 "Attribute Header parsed: type == %d, length == %d\n",
                 sAtr.type,
                 sAtr.length);
    }
    switch (sAtr.type)
    {
    case STUN_ATTR_FingerPrint:
      /* Length of message + header(20) - rest of message */
      if (!stunlib_checkFingerPrint(buf, message->msgHdr.msgLength + 20 -
                                    restlen) && stream)
      {
        printError(stream, "stunlib_DecodeMessage: --Fingerprint CRC error");
      }
      restlen                -= 4;
      message->hasFingerPrint = true;
      break;

    case STUN_ATTR_MappedAddress:
      if ( !stunDecodeIPAddrAtr(&message->mappedAddress, &pCurrPtr, &restlen) )
      {
        return false;
      }
      message->hasMappedAddress = true;
      break;

    case STUN_ATTR_Username:
      if ( !stunDecodeStringAtr(&message->username,
                                &pCurrPtr,
                                &restlen,
                                sAtr.length) )
      {
        return false;
      }
      message->hasUsername = true;
      break;

    case STUN_ATTR_MessageIntegrity:
      if ( !stunDecodeIntegrityAtr(&message->messageIntegrity,
                                   &pCurrPtr,
                                   &restlen,
                                   message->msgHdr.msgLength + 20) )
      {
        return false;
      }
      message->hasMessageIntegrity = true;
      break;

    case STUN_ATTR_ErrorCode:
      if ( !stunDecodeErrorAtr(&message->errorCode,
                               &pCurrPtr,
                               &restlen,
                               sAtr.length) )
      {
        return false;
      }
      message->hasErrorCode = true;
      break;
    case STUN_ATTR_UnknownAttribute:
      if ( !stunDecodeUnknownAtr(&message->unknownAttributes,
                                 &pCurrPtr,
                                 &restlen,
                                 sAtr.length) )
      {
        return false;
      }
      message->hasUnknownAttributes = true;
      break;
    case STUN_ATTR_XorMappedAddress:
      if ( !stunDecodeIPAddrAtrXOR(&message->xorMappedAddress,
                                   &pCurrPtr,
                                   &restlen,
                                   &message->msgHdr.id) )
      {
        return false;
      }
      message->hasXorMappedAddress = true;
      break;
    case STUN_ATTR_Software:
      if ( !stunDecodeStringAtr(&message->software,
                                &pCurrPtr,
                                &restlen,
                                sAtr.length) )
      {
        return false;
      }
      message->hasSoftware = true;
      break;
    case STUN_ATTR_Lifetime:
      if ( !stunDecodeValueAtr(&message->lifetime,
                               &pCurrPtr,
                               &restlen) )
      {
        return false;
      }
      message->hasLifetime = true;
      break;
    case STUN_ATTR_AlternateServer:
      if ( !stunDecodeIPAddrAtr(&message->alternateServer,
                                &pCurrPtr,
                                &restlen) )
      {
        return false;
      }
      message->hasAlternateServer = true;
      break;

    case STUN_ATTR_XorPeerAddress:
      if ( !stunDecodeIPAddrAtrXOR(&message->xorPeerAddress[message->
                                                            xorPeerAddrEntries],
                                   &pCurrPtr,
                                   &restlen,
                                   &message->msgHdr.id) )
      {
        return false;
      }
      message->xorPeerAddrEntries++;
      break;
    case STUN_ATTR_Data:
      if ( !stunDecodeDataAtr(&message->data,
                              &pCurrPtr,
                              &restlen,
                              sAtr.length,
                              bufLen) )
      {
        return false;
      }
      message->hasData = true;
      break;
    case STUN_ATTR_Nonce:
      if ( !stunDecodeStringAtr(&message->nonce,
                                &pCurrPtr,
                                &restlen,
                                sAtr.length) )
      {
        return false;
      }
      message->hasNonce = true;
      break;
    case STUN_ATTR_Realm:
      if ( !stunDecodeStringAtr(&message->realm,
                                &pCurrPtr,
                                &restlen,
                                sAtr.length) )
      {
        return false;
      }
      message->hasRealm = true;
      break;
    case STUN_ATTR_XorRelayAddress:
      if ( !stunDecodeIPAddrAtrXOR(&message->xorRelayAddressTMP,
                                   &pCurrPtr,
                                   &restlen,
                                   &message->msgHdr.id) )
      {
        return false;
      }

      if (message->xorRelayAddressTMP.familyType == STUN_ADDR_IPv4Family)
      {
        message->hasXorRelayAddressIPv4 = true;
        memcpy( &message->xorRelayAddressIPv4,
                &message->xorRelayAddressTMP,
                sizeof(StunIPAddress) );
      }
      else if (message->xorRelayAddressTMP.familyType == STUN_ADDR_IPv6Family)
      {
        message->hasXorRelayAddressIPv6 = true;
        memcpy( &message->xorRelayAddressIPv6,
                &message->xorRelayAddressTMP,
                sizeof(StunIPAddress) );
      }
      if (message->hasXorRelayAddressIPv6 && message->hasXorRelayAddressIPv4)
      {
        message->hasXorRelayAddressSSODA = true;
      }

      break;
    case STUN_ATTR_Priority:
      if ( !stunDecodeValueAtr(&message->priority,
                               &pCurrPtr,
                               &restlen) )
      {
        return false;
      }
      message->hasPriority = true;
      break;
    case STUN_ATTR_RequestedTransport:
      if ( !stunDecodeRequestedTransportAtr(&message->requestedTransport,
                                            &pCurrPtr,
                                            &restlen) )
      {
        return false;
      }
      message->hasRequestedTransport = true;
      break;
    case STUN_ATTR_RequestedAddrFamily:
      if ( !stunDecodeRequestedAddrFamilyAtr(&message->requestedAddrFamilyTMP,
                                             &pCurrPtr,
                                             &restlen) )
      {
        return false;
      }

      if (message->requestedAddrFamilyTMP.family == 0x01)
      {
        message->hasRequestedAddrFamilyIPv4 = true;
        memcpy( &message->requestedAddrFamilyIPv4,
                &message->requestedAddrFamilyTMP,
                sizeof(StunAttrRequestedAddrFamily) );
      }
      if (message->requestedAddrFamilyTMP.family == 0x02)
      {
        message->hasRequestedAddrFamilyIPv6 = true;
        memcpy( &message->requestedAddrFamilyIPv6,
                &message->requestedAddrFamilyTMP,
                sizeof(StunAttrRequestedAddrFamily) );
      }

      if (message->hasRequestedAddrFamilyIPv4 &&
          message->hasRequestedAddrFamilyIPv6)
      {
        message->hasRequestedAddrFamilySSODA = true;
      }

      break;


    case STUN_ATTR_UseCandidate:
      message->hasUseCandidate = true;
      break;

    case STUN_ATTR_DontFragment:
      message->hasDontFragment = true;
      break;

    case STUN_ATTR_EvenPort:
      if ( !stunDecodeEvenPortAtr(&message->evenPort,
                                  &pCurrPtr,
                                  &restlen) )
      {
        return false;
      }
      message->hasEvenPort = true;
      break;

    case STUN_ATTR_ReservationToken:
      if ( !stunDecodeDoubleValueAtr(&message->reservationToken,
                                     &pCurrPtr,
                                     &restlen) )
      {
        return false;
      }
      message->hasReservationToken = true;
      break;

    case STUN_ATTR_TTL:
      if ( !stunDecodeTTL(&message->ttl,
                          &pCurrPtr,
                          &restlen) )
      {
        return false;
      }
      message->hasTTL = true;
      break;
#if 0
    case STUN_ATTR_StreamType:
      if ( !stunDecodeStreamType(&message->streamType,
                                 &pCurrPtr,
                                 &restlen) )
      {
        return false;
      }
      message->hasStreamType = true;
      break;
#endif
    case STUN_ATTR_EnfFlowDescription:
      if ( !stunDecodeEnfFlowDescription(&message->enfFlowDescription,
                                         &pCurrPtr,
                                         &restlen) )
      {
        return false;
      }
      message->hasEnfFlowDescription = true;
      break;


    case STUN_ATTR_TransCount:
      if ( !stunDecodeTransCount(&message->transCount,
                                 &pCurrPtr,
                                 &restlen) )
      {
        return false;
      }
      message->hasTransCount = true;
      break;


    case STUN_ATTR_EnfNetworkStatus:
      if (message->hasMessageIntegrity)
      {
        if ( !stunDecodeEnfNetworkStatus(&message->enfNetworkStatus,
                                         &pCurrPtr,
                                         &restlen) )
        {
          return false;
        }
        message->hasEnfNetworkStatus = true;
      }
      else
      {
        if ( !stunDecodeEnfNetworkStatus(&message->enfNetworkStatusResp,
                                         &pCurrPtr,
                                         &restlen) )
        {
          return false;
        }
        message->hasEnfNetworkStatusResp = true;
      }
      break;
#if 0
    case STUN_ATTR_Cisco_Network_Feedback:
      if (message->hasMessageIntegrity)
      {
        if ( !stunDecodeCiscoNetworkFeedback(&message->ciscoNetFeed,
                                             &pCurrPtr,
                                             &restlen) )
        {
          return false;
        }
        message->hasCiscoNetFeed = true;
      }
      else
      {
        if ( !stunDecodeCiscoNetworkFeedback(&message->ciscoNetFeedResp,
                                             &pCurrPtr,
                                             &restlen) )
        {
          return false;
        }
        message->hasCiscoNetFeedResp = true;
      }
      break;
#endif
    case STUN_ATTR_ICEControlling:
      if ( !stunDecodeDoubleValueAtr(&message->controlling,
                                     &pCurrPtr,
                                     &restlen) )
      {
        return false;
      }
      message->hasControlling = true;
      break;

    case STUN_ATTR_ICEControlled:
      if ( !stunDecodeDoubleValueAtr(&message->controlled,
                                     &pCurrPtr,
                                     &restlen) )
      {
        return false;
      }
      message->hasControlled = true;
      break;

    case STUN_ATTR_ChannelNumber:
      if ( !stunDecodeChannelAtr(&message->channelNumber,
                                 &pCurrPtr,
                                 &restlen) )
      {
        return false;
      }
      message->hasChannelNumber = true;
      break;


    default:
      if ( !(sAtr.type & 0x8000) )
      {
        /* Set unknowns.....*/
        if ( unknowns &&
             (unknowns->numAttributes < STUN_MAX_UNKNOWN_ATTRIBUTES) )
        {
          unknowns->attrType[unknowns->numAttributes++] = sAtr.type;
        }
      }
      sAtr.length += calcPadLen(sAtr.length, STUN_STRING_ALLIGNMENT);
      restlen     -= sAtr.length;
      pCurrPtr    += sAtr.length;
      break;
    }
  }
  if (restlen != 0)
  {
    if (stream)
    {
      fprintf(stream,
              "<stunmsg> Message length or attribute length error(%i).\n",
              restlen);
    }
    return false;
  }



  if (stream)
  {
    printError(stream, "STUN_parse, message parsed: \n");
    stun_printMessage(stream, message);
    if (unknowns && unknowns->numAttributes)
    {
      printError(stream, "STUN_parse, Unknown attributes encountered\n");
      stun_printUnknown(stream, unknowns);
    }
  }
  return true;
}


bool
stunlib_checkIntegrity(const uint8_t* buf,
                       size_t         bufLen,
                       StunMessage*   message,
                       unsigned char* integrityKey,
                       int            integrityKeyLen)

{

  if (message->hasMessageIntegrity)
  {
    unsigned char bufCopy[STUN_MAX_PACKET_SIZE];
    uint16_t      msgIntLength;
    unsigned char hash[20];
    uint8_t*      pCurrPtr;
    unsigned int  len;
    (void)len;
    /*Lengt of message including integiryty lenght (Header and attribute)
     *  Fingerprint and any trailing attributes are dismissed.
     *  msgIntLength = message->messageIntegrity.offset+24;*/
    msgIntLength = message->msgHdr.msgLength;
    if (message->hasFingerPrint)
    {
      msgIntLength =  msgIntLength - 8;
    }

    if (bufLen > STUN_MAX_PACKET_SIZE)
    {
      return false;
    }
    memcpy(&bufCopy, buf, bufLen);

    /*Write new packet length in header*/
    pCurrPtr  = (uint8_t*)bufCopy;
    pCurrPtr += 2;
    write_16(&pCurrPtr, msgIntLength);
    pCurrPtr = (uint8_t*)bufCopy;

    stunlib_util_sha1_hmac(integrityKey,
                           (size_t) integrityKeyLen,
                           pCurrPtr,
                           message->messageIntegrity.offset,
                           &hash[0], &len);
    if (memcmp(&hash, message->messageIntegrity.hash,20) != 0)
    {
      /*
       *  int i;
       *  printf("<STUNMSG>  Integrity Failed!(%s)\n",integrityKey);
       *  printf("     rcv: ");
       *  for (i = 0; i < 20; i++)
       *  printf("%02x ", message->messageIntegrity.hash[i]);
       *  printf("\n");
       *  printf("    calc: ");
       *  for (i = 0; i < 20; i++)
       *  printf("%02x ", hash[i]);
       *  printf("\n");
       *  stun_printMessage(stdout, message);
       */

      return false;
    }

  }
  else
  {
    printError(stderr,"<stunmsg> Missing integrity attribute\n");
    return false;
  }

  return true;

}



uint16_t
stunlib_createRandomTurnChanNum()
{
  return STUN_MIN_CHANNEL_ID +
         ( rand() & (STUN_MAX_CHANNEL_ID - STUN_MIN_CHANNEL_ID) );
}

unsigned int
stunlib_encodeTurnChannelNumber(uint16_t       channelNumber,
                                uint16_t       length,
                                unsigned char* buf)
{
  write_16(&buf, channelNumber);
  write_16(&buf, length);
  return 4;
}

unsigned int
stunlib_decodeTurnChannelNumber(uint16_t*      channelNumber,
                                uint16_t*      length,
                                const uint8_t* buf)
{
  read_16(&buf, channelNumber);
  read_16(&buf, length);
  return 4;
}


/* encode a stun keepalive, return the length or 0 if it fails  */
uint32_t
stunlib_encodeStunKeepAliveReq(StunKeepAliveUsage usage,
                               StunMsgId*         transId,
                               uint8_t*           buf,
                               int                bufLen)
{
  StunMsgHdr h;
  if (bufLen >= STUN_MIN_PACKET_SIZE)
  {
    memcpy( &h.id, transId, sizeof(h.id) );
    h.msgType =
      (usage ==
       StunKeepAliveUsage_Outbound) ? STUN_MSG_BindRequestMsg :
      STUN_MSG_BindIndicationMsg;
    h.msgLength = 0;
    if ( stunEncodeHeader(&h, &buf, &bufLen) )
    {
      return STUN_MIN_PACKET_SIZE;
    }
  }
  return 0;
}


/* encode an (outbound) stun keepalive, return the length or 0 if it fails  */
uint32_t
stunlib_encodeStunKeepAliveResp(StunMsgId*     transId,
                                StunIPAddress* srvrRflxAddr,
                                uint8_t*       buf,
                                int            bufLen)
{
  StunMsgHdr h;

  memcpy( &h.id, transId, sizeof(h.id) );
  h.msgType   = STUN_MSG_BindResponseMsg;
  h.msgLength = (srvrRflxAddr->familyType == STUN_ADDR_IPv4Family) ? 12 : 24;

  if (bufLen < STUN_MIN_PACKET_SIZE + h.msgLength)
  {
    return 0;
  }
  if ( !stunEncodeHeader(&h, &buf, &bufLen) )
  {
    return 0;
  }
  if ( !stunEncodeIPAddrAtrXOR(srvrRflxAddr,
                               STUN_ATTR_XorMappedAddress,
                               &buf,
                               &bufLen,
                               transId) )
  {
    return 0;
  }
  return STUN_MIN_PACKET_SIZE + h.msgLength;
}

static bool
addFingerPrint (StunMessage* message)
{
  uint16_t type = message->msgHdr.msgType;
  if ( (type == STUN_MSG_SendIndicationMsg)
       ||  (type == STUN_MSG_DataIndicationMsg)
       ||  (type == STUN_PathDiscoveryRequestMsg)
       ||  (type == STUN_PathDiscoveryResponseMsg) )
  {
    return false;
  }
  if (message->hasTTL)
  {
    return false;
  }
  return true;
}


uint32_t
stunlib_encodeMessage(StunMessage*   message,
                      unsigned char* buf,
                      unsigned int   bufLen,
                      unsigned char* md5key,
                      unsigned int   keyLen,
                      FILE*          stream)
{
  bool addFingerprint;
  int  msglen;
  int  restlen      = bufLen - STUN_HEADER_SIZE; /* Make space for STUN header
                                                 **/
  uint8_t* pCurrPtr = (uint8_t*)buf + STUN_HEADER_SIZE;

  if ( !message || !buf || (bufLen < STUN_HEADER_SIZE) )
  {
    if (stream)
    {
      printError(stream,
                 "invalid arguments (%p, %p, %d)\n",
                 message,
                 buf,
                 bufLen);
    }
    return 0;
  }

  addFingerprint = addFingerPrint(message);

  /* First write all attributes to calculate total length.... */

  if ( message->hasSoftware && !stunEncodeStringAtr(&message->software,
                                                    STUN_ATTR_Software,
                                                    &pCurrPtr,
                                                    &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Software (Name)\n");
    }
    return 0;
  }

  if ( message->hasPriority && !stunEncodeValueAtr(&message->priority,
                                                   STUN_ATTR_Priority,
                                                   &pCurrPtr,
                                                   &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Priority attribute\n");
    }
    return 0;
  }

  if ( message->hasControlled && !stunEncodeDoubleValueAtr(&message->controlled,
                                                           STUN_ATTR_ICEControlled,
                                                           &pCurrPtr,
                                                           &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid ICEControlled\n");
    }
    return 0;
  }

  if ( message->hasUsername && !stunEncodeStringAtr(&message->username,
                                                    STUN_ATTR_Username,
                                                    &pCurrPtr,
                                                    &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Username\n");
    }
    return 0;
  }

  if ( message->hasNonce && !stunEncodeStringAtr(&message->nonce,
                                                 STUN_ATTR_Nonce,
                                                 &pCurrPtr,
                                                 &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Nonce attribute\n");
    }
    return 0;
  }


  if ( message->hasRealm && !stunEncodeStringAtr(&message->realm,
                                                 STUN_ATTR_Realm,
                                                 &pCurrPtr,
                                                 &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Realm attribute\n");
    }
    return 0;
  }

  if ( message->hasLifetime && !stunEncodeValueAtr(&message->lifetime,
                                                   STUN_ATTR_Lifetime,
                                                   &pCurrPtr,
                                                   &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Lifetime attribute\n");
    }
    return 0;
  }

  if ( message->hasRequestedTransport &&
       !stunEncodeRequestedTransport(&message->requestedTransport,
                                     &pCurrPtr,
                                     &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid RequestedTransport attribute\n");
    }
    return 0;
  }

  if ( message->hasRequestedAddrFamilyIPv4 &&
       !stunEncodeRequestedAddrFamily(&message->requestedAddrFamilyIPv4,
                                      &
                                      pCurrPtr,
                                      &
                                      restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid RequestedAddressFamily attribute\n");
    }
    return 0;
  }

  if ( message->hasRequestedAddrFamilyIPv6 &&
       !stunEncodeRequestedAddrFamily(&message->requestedAddrFamilyIPv6,
                                      &
                                      pCurrPtr,
                                      &
                                      restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid RequestedAddressFamily attribute\n");
    }
    return 0;
  }

  if ( message->hasControlling &&
       !stunEncodeDoubleValueAtr(&message->controlling,
                                 STUN_ATTR_ICEControlling,
                                 &pCurrPtr,
                                 &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid IceControlling\n");
    }
    return 0;
  }

  if ( message->hasMappedAddress &&
       !stunEncodeIPAddrAtr(&message->mappedAddress,
                            STUN_ATTR_MappedAddress,
                            &pCurrPtr,
                            &restlen) )
  {
    if (stream)
    {
      printError(stream, "mappedAddress failed \n");
    }
    return 0;
  }

  if ( message->hasErrorCode && !stunEncodeErrorAtr(&message->errorCode,
                                                    &pCurrPtr,
                                                    &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Error attribute\n");
    }
    return 0;
  }
  if ( message->hasUnknownAttributes &&
       !stunEncodeUnknownAtr(&message->unknownAttributes,
                             &pCurrPtr,
                             &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid unknown attribute\n");
    }
    return 0;
  }

  if ( message->hasXorMappedAddress &&
       !stunEncodeIPAddrAtrXOR(&message->xorMappedAddress,
                               STUN_ATTR_XorMappedAddress,
                               &pCurrPtr,
                               &restlen,
                               &message->msgHdr.
                               id) )
  {
    if (stream)
    {
      printError(stream, "Invalid xorMappedAddress\n");
    }
    return 0;
  }

  if ( message->hasChannelNumber &&
       !stunEncodeChannelAtr(&message->channelNumber,
                             &pCurrPtr,
                             &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid ChannelNumber attribute\n");
    }
    return 0;
  }


  if ( message->hasAlternateServer &&
       !stunEncodeIPAddrAtr(&message->alternateServer,
                            STUN_ATTR_AlternateServer,
                            &pCurrPtr,
                            &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Alternate Server\n");
    }
    return 0;
  }
  if (message->xorPeerAddrEntries)
  {
    uint32_t i;
    for (i = 0; i < message->xorPeerAddrEntries; i++)
    {
      if ( !stunEncodeIPAddrAtrXOR(&message->xorPeerAddress[i],
                                   STUN_ATTR_XorPeerAddress,
                                   &pCurrPtr,
                                   &restlen,
                                   &message->msgHdr.id) )
      {
        printError(stream, "Invalid Peer Address entry  %d\n", i);
        return 0;
      }
    }
  }
  if ( message->hasXorRelayAddressIPv4 &&
       !stunEncodeIPAddrAtrXOR(&message->xorRelayAddressIPv4,
                               STUN_ATTR_XorRelayAddress,
                               &pCurrPtr,
                               &restlen,
                               &message->
                               msgHdr.id) )
  {
    if (stream)
    {
      printError(stream, "xorRelayAddressIPv4 failed \n");
    }
    return 0;
  }

  if ( message->hasXorRelayAddressIPv6 &&
       !stunEncodeIPAddrAtrXOR(&message->xorRelayAddressIPv6,
                               STUN_ATTR_XorRelayAddress,
                               &pCurrPtr,
                               &restlen,
                               &message->
                               msgHdr.id) )
  {
    if (stream)
    {
      printError(stream, "xorRelayAddressIPv6 failed \n");
    }
    return 0;
  }

  if ( message->hasUseCandidate && !stunEncodeFlagAtr(STUN_ATTR_UseCandidate,
                                                      &pCurrPtr,
                                                      &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid UseCandidate\n");
    }
    return 0;
  }

  if ( message->hasDontFragment && !stunEncodeFlagAtr(STUN_ATTR_DontFragment,
                                                      &pCurrPtr,
                                                      &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid DontFragment\n");
    }
    return 0;
  }

  if ( message->hasEvenPort && !stunEncodeEvenPort(&message->evenPort,
                                                   &pCurrPtr,
                                                   &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid EvenPort attribute\n");
    }
    return 0;
  }

  if ( message->hasReservationToken &&
       !stunEncodeDoubleValueAtr(&message->reservationToken,
                                 STUN_ATTR_ReservationToken,
                                 &pCurrPtr,
                                 &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Reservation Token attribute\n");
    }
    return 0;
  }


  if ( message->hasEnfFlowDescription &&
       !stunEncodeEnfFlowDescription(&message->enfFlowDescription,
                                     &pCurrPtr,
                                     &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid StreamType attribute\n");
    }
    return 0;
  }

  if ( message->hasTTL && !stunEncodeTTL(&message->ttl,
                                         &pCurrPtr,
                                         &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid TTL attribute\n");
    }
    return 0;
  }

  if ( message->hasEnfNetworkStatusResp &&
       !stunEncodeEnfNetworkStatus(&message->enfNetworkStatusResp,
                                   &pCurrPtr,
                                   &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Network Status attribute\n");
    }
    return 0;
  }

  if ( message->hasTransCount &&
       !stunEncodeTransCount(&message->transCount,
                             &pCurrPtr,
                             &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid TransCount attribute\n");
    }
    return 0;
  }

  /* note: DATA should be the last attribute */
  if ( message->hasData && !stunEncodeDataAtr(&message->data,
                                              &pCurrPtr,
                                              &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Data attribute\n");
    }
    return 0;
  }



  if (md5key)
  {
    message->hasMessageIntegrity = true;
    memset( &message->messageIntegrity,0,sizeof(message->messageIntegrity) );
    if ( !stunEncodeIntegrityAtr(&message->messageIntegrity,
                                 &pCurrPtr,
                                 &restlen,
                                 bufLen) )
    {
      if (stream)
      {
        printError(stream, "Faild to encode integrity!\n");
      }
      return 0;
    }

  }

  /*ENF NETWORK-STATUS Attribute is to be placed after integrity attribute*/

  if ( message->hasEnfNetworkStatus &&
       !stunEncodeEnfNetworkStatus(&message->enfNetworkStatus,
                                   &pCurrPtr,
                                   &restlen) )
  {
    if (stream)
    {
      printError(stream, "Invalid Network Status attribute\n");
    }
    return 0;
  }

  msglen                    = bufLen - restlen;
  message->msgHdr.msgLength = msglen - STUN_HEADER_SIZE;
  pCurrPtr                  = (uint8_t*)buf;
  restlen                   = bufLen;
  stunEncodeHeader(&message->msgHdr, &pCurrPtr, &restlen);
  if (md5key)
  {
    uint32_t length;
    (void)length;
    /*calculate and insert integrity hash*/
    pCurrPtr = (uint8_t*)buf;
    stunlib_util_sha1_hmac(md5key, keyLen,
                           pCurrPtr,
                           message->messageIntegrity.offset,
                           &message->messageIntegrity.hash[0], &length);

    pCurrPtr = (uint8_t*)buf + message->messageIntegrity.offset;
    if ( !stunEncodeIntegrityAtr(&message->messageIntegrity, &pCurrPtr,
                                 &restlen, bufLen) )
    {
      if (stream)
      {
        printError(stream, "Failed to write Integrity hash\n");
      }
    }

  }

  /* Add CRC Fingerprint */
  if (addFingerprint)
  {
    uint32_t crc;
    message->msgHdr.msgLength += 8;

    pCurrPtr = (uint8_t*)buf;
    restlen  = bufLen;

    stunEncodeHeader(&message->msgHdr, &pCurrPtr, &restlen);
    crc       = stunlib_calculateFingerprint( (uint8_t*)buf, msglen );
    pCurrPtr += message->msgHdr.msgLength - 8;

    if ( !stunEncodeFingerprintAtr(crc,
                                   &pCurrPtr,
                                   &restlen) )
    {
      if (stream)
      {
        printError(stream, "Faild to add CRC Fingerprint\n");
      }
    }
    else
    {
      msglen += 8;
    }

  }
  if (stream)
  {
    printError(stream, "STUN_encode, messages to encode: \n");
    stun_printMessage(stream, message);
    printError(stream, "STUN_encode, buffer encoded: \n");
    stunlib_printBuffer(stream, (uint8_t*)buf, msglen, "STUN");
  }
  return message->msgHdr.msgLength + STUN_HEADER_SIZE;
}



static void
stunSetString(StunAtrString* pStr,
              char const*    szCStr,
              char           padChar)
{
  if (!pStr || !szCStr)
  {
    return;
  }
  pStr->sizeValue = min( STUN_MAX_STRING, strlen(szCStr) );
  pStr->padChar   = padChar;
  memcpy(pStr->value, szCStr, pStr->sizeValue);
}


bool
stunlib_addNonce(StunMessage* stunMsg,
                 const char*  nonce,
                 char         padChar)
{
  stunMsg->hasNonce = true;
  stunSetString(&stunMsg->nonce, nonce, padChar);
  return true;
}

bool
stunlib_addUserName(StunMessage* stunMsg,
                    const char*  userName,
                    char         padChar)
{
  if (strlen(userName) > STUN_MSG_MAX_USERNAME_LENGTH)
  {
    return false;
  }

  stunMsg->hasUsername = true;
  stunSetString(&stunMsg->username, userName, padChar);
  return true;
}

bool
stunlib_addRealm(StunMessage* stunMsg,
                 const char*  realm,
                 char         padChar)
{
  if (strlen(realm) > STUN_MSG_MAX_REALM_LENGTH)
  {
    return false;
  }

  stunMsg->hasRealm = true;
  stunSetString(&stunMsg->realm, realm, padChar);
  return true;

}

bool
stunlib_addRequestedTransport(StunMessage* stunMsg,
                              uint8_t      protocol)
{
  stunMsg->hasRequestedTransport       = true;
  stunMsg->requestedTransport.protocol = protocol;
  memset( stunMsg->requestedTransport.rffu, 0,
          sizeof(stunMsg->requestedTransport.rffu) );
  return true;
}

bool
stunlib_addRequestedAddrFamily(StunMessage* stunMsg,
                               int          sa_family)
{
  memset( stunMsg->requestedAddrFamilyIPv4.rffu, 0,
          sizeof(stunMsg->requestedAddrFamilyIPv4.rffu) );
  memset( stunMsg->requestedAddrFamilyIPv6.rffu, 0,
          sizeof(stunMsg->requestedAddrFamilyIPv6.rffu) );

  if (sa_family == AF_INET)
  {
    stunMsg->hasRequestedAddrFamilyIPv4     = true;
    stunMsg->requestedAddrFamilyIPv4.family = 0x01;
    return true;
  }
  else if (sa_family == AF_INET6)
  {
    stunMsg->hasRequestedAddrFamilyIPv6     = true;
    stunMsg->requestedAddrFamilyIPv6.family = 0x02;
    return true;
  }
  else if ( sa_family == (AF_INET6 + AF_INET) )
  {
    stunMsg->hasRequestedAddrFamilyIPv4     = true;
    stunMsg->requestedAddrFamilyIPv4.family = 0x01;
    stunMsg->hasRequestedAddrFamilyIPv6     = true;
    stunMsg->requestedAddrFamilyIPv6.family = 0x02;
    stunMsg->hasRequestedAddrFamilySSODA    = true;
    return true;
  }

  return false;
}


bool
stunlib_addSoftware(StunMessage* stunMsg,
                    const char*  software,
                    char         padChar)
{
  stunMsg->hasSoftware = true;
  stunSetString(&stunMsg->software, software, padChar);
  return true;
}

bool
stunlib_addError(StunMessage* stunMsg,
                 const char*  reasonStr,
                 uint16_t     classAndNumber,
                 char         padChar)
{
  stunMsg->errorCode.reserved   = 0;
  stunMsg->errorCode.errorClass = classAndNumber / 100;
  stunMsg->errorCode.number     = classAndNumber % 100;
  snprintf(stunMsg->errorCode.reason,
           sizeof (stunMsg->errorCode.reason),
           "%s",
           reasonStr);
  stunMsg->errorCode.padChar    = padChar;
  stunMsg->errorCode.sizeReason = strlen(reasonStr);
  stunMsg->hasErrorCode         = true;
  return true;
}


bool
stunlib_addChannelNumber(StunMessage* stunMsg,
                         uint16_t     channelNumber)
{
  stunMsg->hasChannelNumber            = true;
  stunMsg->channelNumber.channelNumber = channelNumber;
  stunMsg->channelNumber.rffu          = 0;
  return true;
}

/* transaction id compare */
bool
stunlib_transIdIsEqual(const StunMsgId* a,
                       const StunMsgId* b)
{
  return (memcmp(a, b, STUN_MSG_ID_SIZE) == 0);
}

/*****
 * Create our magic id....
 *********/
void
stunlib_createId(StunMsgId* pId)
{
    stunlib_util_random(pId, STUN_MSG_ID_SIZE);
}


void
stunlib_setIP4Address(StunIPAddress* pIpAddr,
                      uint32_t       addr,
                      uint16_t       port)
{
  if (pIpAddr)
  {
    pIpAddr->familyType   = STUN_ADDR_IPv4Family;
    pIpAddr->addr.v4.addr = addr;
    pIpAddr->addr.v4.port = port;
  }
}

void
stunlib_setIP6Address(StunIPAddress* pIpAddr,
                      const uint8_t  addr[16],
                      const uint16_t port)
{
  if (pIpAddr)
  {
    pIpAddr->familyType   = STUN_ADDR_IPv6Family;
    pIpAddr->addr.v6.port = port;

    memcpy( &pIpAddr->addr.v6.addr, addr, sizeof(pIpAddr->addr.v6.addr) );
  }
}

uint32_t
stunlib_calculateFingerprint(const uint8_t* buf,
                             size_t         len)
{
  return stunlib_util_crc32(0L, buf, len) ^ 0x5354554e;
}


bool
stunlib_checkFingerPrint(const uint8_t* buf,
                         uint32_t       fpOffset)
{
  uint32_t       crc = stunlib_calculateFingerprint(buf, fpOffset - 4);
  uint32_t       val;
  const uint8_t* pos = buf + fpOffset;
  read_32(&pos, &val);
  if (crc == val)
  {
    return true;
  }

  return false;
}


/* Concat  username+realm+passwd into string "<username>:<realm>:<password>"
 * then run the MD5 alg.
 * to create a 128but MD5 hash in md5key.
 */
void
stunlib_createMD5Key(unsigned char* md5key,
                     const char*    userName,
                     const char*    realm,
                     const char*    password)
{
  char keyStr[STUN_MSG_MAX_USERNAME_LENGTH + STUN_MSG_MAX_PASSWORD_LENGTH +
              STUN_MSG_MAX_REALM_LENGTH + 2];
  int bytes_written;

  bytes_written = snprintf(keyStr,
                           sizeof keyStr,
                           "%s:%s:%s",
                           userName,
                           realm,
                           password);
  if ( (size_t)bytes_written >= sizeof keyStr )
  {
    abort();
  }
  stunlib_util_md5((uint8_t*)keyStr, (size_t) bytes_written, md5key );
}

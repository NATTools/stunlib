/*
 *  See license file
 */

#include <stun_crypto.h>
#include <string.h>

enum
{
  shaSuccess = 0,
  shaNull,          /* Null pointer parameter */
  shaInputTooLong,  /* input data too long */
  shaStateError     /* called Input after Result */
};

#define SHA1HashSize 20

typedef struct
{
  uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */
  uint32_t Length_Low;                        /* Message length in bits */
  uint32_t Length_High;                       /* Message length in bits */
  int_least16_t Message_Block_Index;          /* Index into message block array */
  uint8_t Message_Block[64];                  /* 512-bit message blocks */
  int Computed;                               /* Is the digest computed? */
  int Corrupted;                              /* Is the message digest corrupted? */
} SHA1Context;

#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

static void
SHA1ProcessMessageBlock(SHA1Context *context)
{
  /* Constants defined in SHA-1   */
  static const uint32_t K[] = { 0x5A827999,
                                0x6ED9EBA1,
                                0x8F1BBCDC,
                                0xCA62C1D6
                              };
  int         t;                /* Loop counter        */
  uint32_t    temp;             /* Temporary word value    */
  uint32_t    W[80];            /* Word sequence         */
  uint32_t    A, B, C, D, E;    /* Word buffers        */

  /*
   *  Initialize the first 16 words in the array W
   */
  for(t = 0; t < 16; t++)
  {
    W[t] = context->Message_Block[t * 4] << 24;
    W[t] |= context->Message_Block[t * 4 + 1] << 16;
    W[t] |= context->Message_Block[t * 4 + 2] << 8;
    W[t] |= context->Message_Block[t * 4 + 3];
  }

  for(t = 16; t < 80; t++)
  {
     W[t] = SHA1CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
  }

  A = context->Intermediate_Hash[0];
  B = context->Intermediate_Hash[1];
  C = context->Intermediate_Hash[2];
  D = context->Intermediate_Hash[3];
  E = context->Intermediate_Hash[4];

  for(t = 0; t < 20; t++)
  {
    temp =  SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);

    B = A;
    A = temp;
  }

  for(t = 20; t < 40; t++)
  {
    temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }

  for(t = 40; t < 60; t++)
  {
    temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }

  for(t = 60; t < 80; t++)
  {
    temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
    E = D;
    D = C;
    C = SHA1CircularShift(30,B);
    B = A;
    A = temp;
  }

  context->Intermediate_Hash[0] += A;
  context->Intermediate_Hash[1] += B;
  context->Intermediate_Hash[2] += C;
  context->Intermediate_Hash[3] += D;
  context->Intermediate_Hash[4] += E;

  context->Message_Block_Index = 0;
}

static void
SHA1PadMessage(SHA1Context *context)
{
  /*
   *  Check to see if the current message block is too small to hold
   *  the initial padding bits and length.  If so, we will pad the
   *  block, process it, and then continue padding into a second
   *  block.
   */
  if (context->Message_Block_Index > 55)
  {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 64)
    {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }

    SHA1ProcessMessageBlock(context);

    while(context->Message_Block_Index < 56)
    {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  }
  else
  {
    context->Message_Block[context->Message_Block_Index++] = 0x80;
    while(context->Message_Block_Index < 56)
    {
      context->Message_Block[context->Message_Block_Index++] = 0;
    }
  }

  /*
   *  Store the message length as the last 8 octets
   */
  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >> 8;
  context->Message_Block[59] = context->Length_High;
  context->Message_Block[60] = context->Length_Low >> 24;
  context->Message_Block[61] = context->Length_Low >> 16;
  context->Message_Block[62] = context->Length_Low >> 8;
  context->Message_Block[63] = context->Length_Low;

  SHA1ProcessMessageBlock(context);
}

static int
SHA1Reset(SHA1Context *context)
{
  if (!context)
    return shaNull;

  context->Length_Low       = 0;
  context->Length_High      = 0;
  context->Message_Block_Index  = 0;

  context->Intermediate_Hash[0]   = 0x67452301;
  context->Intermediate_Hash[1]   = 0xEFCDAB89;
  context->Intermediate_Hash[2]   = 0x98BADCFE;
  context->Intermediate_Hash[3]   = 0x10325476;
  context->Intermediate_Hash[4]   = 0xC3D2E1F0;

  context->Computed   = 0;
  context->Corrupted  = 0;

  return shaSuccess;
}

static int
SHA1Result(SHA1Context* context,
           uint8_t      Message_Digest[SHA1HashSize])
{
  int i;

  if (!context || !Message_Digest)
    return shaNull;

  if (context->Corrupted)
    return context->Corrupted;

  if (!context->Computed)
  {
    SHA1PadMessage(context);
    for(i=0; i<64; ++i)
    {
      /* message may be sensitive, clear it out */
      context->Message_Block[i] = 0;
    }
    context->Length_Low = 0;  /* and clear length */
    context->Length_High = 0;
    context->Computed = 1;
  }

  for(i = 0; i < SHA1HashSize; ++i)
  {
    Message_Digest[i] = context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
  }

  return shaSuccess;
}

static int
SHA1Input(SHA1Context*   context,
          const uint8_t* message_array,
          unsigned length)
{
  if (!length)
    return shaSuccess;

  if (!context || !message_array)
    return shaNull;

  if (context->Computed)
  {
    context->Corrupted = shaStateError;
    return shaStateError;
  }

  if (context->Corrupted)
  {
     return context->Corrupted;
  }

  while(length-- && !context->Corrupted)
  {
    context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

    context->Length_Low += 8;
    if (context->Length_Low == 0)
    {
      context->Length_High++;
      if (context->Length_High == 0)
      {
        /* Message is too long */
        context->Corrupted = 1;
      }
    }

    if (context->Message_Block_Index == 64)
    {
      SHA1ProcessMessageBlock(context);
    }

    message_array++;
  }

  return shaSuccess;
}

void
stunlib_util_sha1_hmac(const void*   key,
                       size_t        keyLength,
                       const void*   data,
                       size_t        dataLength,
                       void*         macOut,
                       unsigned int* macLength) {

  SHA1Context context;

  uint8_t k_ipad[65] = { 0 };     /* inner padding-key XORd with ipad */
  uint8_t k_opad[65] = { 0 };     /* outer padding-key XORd with opad */

  uint8_t tk[SHA1HashSize];

  int i;

  if (keyLength > 64)
  {
    SHA1Context tctx;

    SHA1Reset(&tctx);
    SHA1Input(&tctx, (const uint8_t *)key, (unsigned)keyLength);
    SHA1Result(&tctx, tk);

    key = tk;
    keyLength = SHA1HashSize;
  }

  memcpy(k_ipad, key, keyLength);
  memcpy(k_opad, key, keyLength);

  /* XOR key with ipad and opad values */
  for (i=0; i<64; i++)
  {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  SHA1Reset(&context);            /* init context for 1st pass */
  SHA1Input(&context, k_ipad, 64);      /* start with inner pad */
  SHA1Input(&context, data, dataLength);    /* then text of datagram */
  SHA1Result(&context, macOut);

  SHA1Reset(&context);            /* init context for 2nd pass */
  SHA1Input(&context, k_opad, 64);      /* start with outer pad */
  SHA1Input(&context, macOut, SHA1HashSize);  /* then results of 1st hash */
  SHA1Result(&context, macOut);

  *macLength = SHA1HashSize;
}

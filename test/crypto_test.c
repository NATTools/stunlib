#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "test_utils.h"
#include "stun_crypto.h"

static const char lazyDogString[] = "The quick brown fox jumps over the lazy dog";

CTEST(crypto, Sha1_Hmac)
{
    unsigned char macOut[20] = { 0 };
    unsigned int macLength = 0;
    const unsigned char macResult0[] = { 0xfb, 0xdb, 0x1d, 0x1b, 0x18, 0xaa, 0x6c, 0x08, 0x32, 0x4b, 0x7d, 0x64, 0xb7, 0x1f, 0xb7, 0x63, 0x70, 0x69, 0x0e, 0x1d };
    const unsigned char macResult1[] = { 0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a, 0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9 };

    stunlib_util_sha1_hmac("", 0, "", 0, macOut, &macLength);
    ASSERT_TRUE(memcmp(macResult0, macOut, sizeof macOut) == 0);

    stunlib_util_sha1_hmac("key", 3, lazyDogString, sizeof lazyDogString - 1, macOut, &macLength);
    ASSERT_TRUE(memcmp(macResult1, macOut, sizeof macOut) == 0);
}

CTEST(crypto, MD5)
{
    unsigned char md5[16];
    const unsigned char md5Result0[] = { 0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6 };

    stunlib_util_md5(lazyDogString, sizeof lazyDogString - 1, md5);
    ASSERT_TRUE(memcmp(md5Result0, md5, sizeof md5) == 0);
}

CTEST(crypto, CRC32)
{
    uint32_t const crc32 = stunlib_util_crc32(0, (const uint8_t*)lazyDogString, sizeof lazyDogString - 1);
    ASSERT_TRUE(0x414fa339 == crc32);
}

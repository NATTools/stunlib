/*
 *  See license file
 */

#include "stun_crypto.h"

#if defined(STUNLIB_USE_OPENSSL)
#  include <openssl/md5.h>
#  include <openssl/evp.h>
#  include <openssl/hmac.h>

unsigned char* stunlib_util_md5(const void *data, size_t len, unsigned char *md) {
    return MD5( (uint8_t*)data, len, md );
}

void stunlib_util_sha1_hmac(const void *key, size_t keyLength, const void *data, size_t dataLength, void *macOut, unsigned int* macLength) {
    HMAC(EVP_sha1(),
         key,
         keyLength,
         data,
         dataLength,
         macOut, macLength);
}

#elif defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  include <CommonCrypto/CommonHMAC.h>

unsigned char* stunlib_util_md5(const void *data, size_t len, unsigned char *md) {
    return CC_MD5((uint8_t*)data, (CC_LONG) len, md);
}

void stunlib_util_sha1_hmac(const void *key,
                            size_t keyLength,
                            const void *data,
                            size_t dataLength,
                            void *macOut,
                            __attribute__((unused)) unsigned int* macLength) {
    CCHmac(kCCHmacAlgSHA1, key, keyLength, data, dataLength, macOut);
}

#endif // defined(__APPLE__)

#if defined(STUNLIB_USE_BSD)
#  include <bsd/stdlib.h>
#endif

#if defined(STUNLIB_USE_BSD) || defined(__APPLE__)
void stunlib_util_random(void* buffer, size_t size) {
    arc4random_buf(buffer, size);
}
#endif

#if defined(STUNLIB_USE_ZLIB)
#include <zlib.h>
uint32_t stunlib_util_crc32(long crc, const uint8_t* buf, size_t len) {
    return crc32(crc, buf, len);
}
#endif

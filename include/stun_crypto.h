/*
 *  See license file
 */

#include <stdlib.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char* stunlib_util_md5(const void* data, size_t len, unsigned char* md);

void stunlib_util_sha1_hmac(const void* key, size_t keyLength, const void* data, size_t dataLength, void* macOut, unsigned int* macLength);

void stunlib_util_random(void* buffer, size_t size);

uint32_t stunlib_util_crc32(long crc, const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif

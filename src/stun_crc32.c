/*
 *  See license file
 */

#include <stun_crypto.h>

static void
make_crc_table(uint32_t crc_table[256])
{
  uint32_t c, n, k;

  for (n = 0; n < 256u; n++)
  {
    c = n;
    for (k = 0; k < 8; k++)
    {
      c = c & 1 ? 0xedb88320ul ^ (c >> 1) : c >> 1;
    }
    crc_table[n] = c;
  }
}

static unsigned long
update_crc(uint32_t       crc,
           const uint8_t* buf,
           size_t         len,
           uint32_t       crc_table[256])
{
  uint32_t c = crc ^ 0xfffffffful;
  size_t   n;

  for (n = 0; n < len; n++)
  {
    c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
  }

  return c ^ 0xfffffffful;
}

uint32_t
stunlib_util_crc32(long           crc,
                   const uint8_t* buf,
                   size_t         len)
{
  uint32_t crc_table[256];
  make_crc_table(crc_table);
  return update_crc(crc, buf, len, crc_table);
}

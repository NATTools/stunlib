/*
 *  See license file
 */

#include "stun_crypto.h"
#include <time.h>
#include <string.h>

/*
 * Permuted congruential generator implementation: PCG-XSH-RR
 */

static uint64_t       state      = 0;
static uint64_t const multiplier = 6364136223846793005u;
static uint64_t const increment  = 1442695040888963407u;
static int            init       = 0;

static uint32_t
rotate32(uint32_t x,
         unsigned r)
{
  return x >> r | x << (-r & 31);
}

static uint32_t
pcg32()
{
  uint64_t x = state;
  unsigned count = (unsigned)(x >> 59);         // 59 = 64 - 5
  state = x * multiplier + increment;
  x ^= x >> 18;                                 // 18 = (64 - 27)/2
  return rotate32((uint32_t)(x >> 27), count);  // 27 = 32 - 5
}

static void
pcg32_init(uint64_t seed)
{
  state = seed + increment;
  (void)pcg32();
  init = 1;
}

void
stunlib_util_random(void*  buffer,
                    size_t size)
{
  if (!init)
      pcg32_init(time(0));

  size_t i;

  for(i = 0; i < size / sizeof(uint32_t); ++i)
  {
    uint32_t *p = ((uint32_t *)buffer) + i;
    *p = pcg32();
  }

  uint32_t const n = size % sizeof(uint32_t);

  if (n)
  {
    uint32_t *p = ((uint32_t *)buffer) + i;
    uint32_t const k = pcg32();
    memcpy(p, &k, n);
  }
}

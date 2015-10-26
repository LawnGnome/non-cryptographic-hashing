#include <stdint.h>
#include <string.h>

const uint32_t xxhash32_prime1 = 2654435761U;
const uint32_t xxhash32_prime2 = 2246822519U;
const uint32_t xxhash32_prime3 = 3266489917U;
const uint32_t xxhash32_prime4 = 668265263U;
const uint32_t xxhash32_prime5 = 374761393U;

inline uint32_t xxhash32_rotl(uint32_t x, int r) {
  return (x << r) | (x >> (32 - r));
}

inline uint32_t xxhash32_mix(uint32_t v, uint32_t chunk) {
  v += chunk * xxhash32_prime2;
  v = xxhash32_rotl(v, 13);
  return v * xxhash32_prime1;
}

uint32_t xxhash32(const char *data, size_t len, uint32_t seed) {
  const char *p = data;
  const char *end = data + len;

  uint32_t hash = 0;

  if (len >= 16) {
    uint32_t v1 = seed + xxhash32_prime1 + xxhash32_prime2;
    uint32_t v2 = seed + xxhash32_prime2;
    uint32_t v3 = seed;
    uint32_t v4 = seed - xxhash32_prime1;

    for (; p <= (end - 16); p += 16) {
      const uint32_t *chunk = (const uint32_t *) p;

      v1 = xxhash32_mix(v1, chunk[0]);
      v2 = xxhash32_mix(v2, chunk[1]);
      v3 = xxhash32_mix(v3, chunk[2]);
      v4 = xxhash32_mix(v4, chunk[3]);
    }

    hash = xxhash32_rotl(v1, 1) +
           xxhash32_rotl(v2, 7) +
           xxhash32_rotl(v3, 12) +
           xxhash32_rotl(v4, 18);
  } else {
    hash = seed + xxhash32_prime5;
  }

  for (; (p + 4) <= end; p += 4) {
    hash += *((const uint32_t *) p) * xxhash32_prime3;
    hash = xxhash32_rotl(hash, 17) * xxhash32_prime4;
  }

  for (; p < end; p++) {
    hash += ((uint8_t) *p) * xxhash32_prime5;
    hash = xxhash32_rotl(hash, 11) * xxhash32_prime1;
  }

  hash ^= hash >> 15;
  hash *= xxhash32_prime2;
  hash ^= hash >> 13;
  hash *= xxhash32_prime3;
  hash ^= hash >> 16;

  return hash;
}

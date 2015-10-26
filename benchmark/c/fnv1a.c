#include <stdint.h>
#include <string.h>

uint32_t fnv1a32(const char *data, size_t len, uint32_t ignored) {
  uint32_t hash = 2166136261;
  for (const char *byte = data; byte < (data + len); byte++) {
    hash ^= *byte;
    hash *= 16777619;
  }
  return hash;
}

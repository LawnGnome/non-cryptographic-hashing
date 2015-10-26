#include <cstring>
#include <iostream>
#include <list>
#include <set>
#include <string>
#include <sys/time.h>

uint32_t murmurhash3_32(const char *data, size_t len, uint32_t seed) {
  static const uint32_t c1 = 0xcc9e2d51;
  static const uint32_t c2 = 0x1b873593;
  static const uint32_t r1 = 15;
  static const uint32_t r2 = 13;
  static const uint32_t m = 5;
  static const uint32_t n = 0xe6546b64;

  uint32_t hash = seed;

  const int nblocks = len / 4;
  const uint32_t *blocks = (const uint32_t *) data;
  int i;
  for (i = 0; i < nblocks; i++) {
    uint32_t k = blocks[i];
    k *= c1;
    k = (k << r1) | (k >> (32 - r1));
    k *= c2;

    hash ^= k;
    hash = ((hash << r2) | (hash >> (32 - r2))) * m + n;
  }

  const uint8_t *tail = (const uint8_t *) (data + nblocks * 4);
  uint32_t k1 = 0;

  switch (len & 3) {
  case 3:
    k1 ^= tail[2] << 16;
  case 2:
    k1 ^= tail[1] << 8;
  case 1:
    k1 ^= tail[0];

    k1 *= c1;
    k1 = (k1 << r1) | (k1 >> (32 - r1));
    k1 *= c2;
    hash ^= k1;
  }

  hash ^= len;
  hash ^= (hash >> 16);
  hash *= 0x85ebca6b;
  hash ^= (hash >> 13);
  hash *= 0xc2b2ae35;
  hash ^= (hash >> 16);

  return hash;
}

uint32_t fnv1a32(const char *data, size_t len, uint32_t ignored) {
  uint32_t hash = 2166136261;
  for (const char *byte = data; byte < (data + len); byte++) {
    hash ^= *byte;
    hash *= 16777619;
  }
  return hash;
}

typedef uint32_t (*hash_func_t)(const char *, size_t, uint32_t);

typedef struct {
  const char *algo;
  hash_func_t func;
} algorithm_function;

algorithm_function algorithms[] = {
  {"fnv1a32", fnv1a32},
  {"murmurhash3", murmurhash3_32},
  {NULL, NULL},
};

uint64_t curtime() {
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return (tv.tv_sec * 1000000 + tv.tv_usec);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " ALGORITHM" << std::endl;
    return 1;
  }

  for (algorithm_function *af = algorithms; af->algo; af++) {
    if (0 == std::strcmp(argv[1], af->algo)) {
      std::list<std::string> input;
      std::string line;
      while (std::getline(std::cin, line)) {
        input.push_back(line);
      }
      if (std::cin.bad()) {
        std::cerr << "Input error" << std::endl;
        return 3;
      }

      const uint32_t seed = 0x3490f1ab;
      std::set<uint32_t> results;
      uint64_t start, end;

      start = curtime();
      for (auto &&i : input) {
        results.insert((af->func)(i.c_str(), i.size(), seed));
      }
      end = curtime();

      std::cout << "Time: " << (end - start) / 1000000.0 << " second(s)" << std::endl
                << "Collisions: " << (input.size() - results.size()) << std::endl;

      return 0;
    }
  }

  std::cerr << "Algorithm " << argv[1] << " not found" << std::endl;
  return 2;
}

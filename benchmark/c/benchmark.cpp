#include <cstring>
#include <iostream>
#include <list>
#include <set>
#include <string>
#include <sys/time.h>

extern "C" {
  uint32_t crc32(const char *data, size_t len, uint32_t ignored);
  uint32_t fnv1a32(const char *data, size_t len, uint32_t ignored);
  uint32_t murmurhash3_32(const char *data, size_t len, uint32_t seed);
  uint32_t superfasthash(const char *data, size_t len, uint32_t ignored);
  uint32_t xxhash32(const char *data, size_t len, uint32_t seed);
}

typedef uint32_t (*hash_func_t)(const char *, size_t, uint32_t);

typedef struct {
  const char *algo;
  hash_func_t func;
} algorithm_function;

algorithm_function algorithms[] = {
  {"crc32", crc32},
  {"fnv1a32", fnv1a32},
  {"murmurhash3", murmurhash3_32},
  {"superfasthash", superfasthash},
  {"xxhash32", xxhash32},
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

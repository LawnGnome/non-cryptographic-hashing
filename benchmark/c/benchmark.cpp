#include <cstring>
#include <iostream>
#include <set>
#include <string>
#include <sys/time.h>

uint32_t fnv1a32(const char *data, size_t len) {
  uint32_t hash = 2166136261;
  for (const char *byte = data; byte < (data + len); byte++) {
    hash ^= *byte;
    hash *= 16777619;
  }
  return hash;
}

typedef uint32_t (*hash_func_t)(const char *, size_t);

typedef struct {
  const char *algo;
  hash_func_t func;
} algorithm_function;

algorithm_function algorithms[] = {
  {"fnv1a32", fnv1a32},
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
      size_t input_size = 0;
      std::string line;
      std::set<uint32_t> results;
      uint64_t start, end;

      start = curtime();
      while (std::getline(std::cin, line)) {
        ++input_size;
        results.insert((af->func)(line.c_str(), line.size()));
      }
      end = curtime();

      if (std::cin.bad()) {
        std::cerr << "Input error" << std::endl;
        return 3;
      }

      std::cout << "Time: " << (end - start) / 1000000.0 << " second(s)" << std::endl
                << "Collisions: " << (input_size - results.size()) << std::endl;

      return 0;
    }
  }

  std::cerr << "Algorithm " << argv[1] << " not found" << std::endl;
  return 2;
}

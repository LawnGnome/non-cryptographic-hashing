CC = clang
CFLAGS = -O3 -std=c99
CXX = clang++
CXXFLAGS = -std=c++11 -O3

all: benchmark

benchmark: benchmark.cpp fnv1a.o murmurhash3.o xxhash.o
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f benchmark

# vim: set noet ts=8 sw=8:

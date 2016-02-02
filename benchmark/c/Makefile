CC = clang
CFLAGS = -O3 -std=c99 -fPIC
CXX = clang++
CXXFLAGS = -std=c++11 -O3 -fPIC

all: benchmark

benchmark: benchmark.cpp city.o crc32.o fnv1a.o murmurhash3.o superfasthash.o xxhash.o
	$(CXX) $(CXXFLAGS) -o $@ $^

libcityhash.so: city.o libcityhash.o
	$(CC) -shared -o $@ $^

%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

clean:
	rm -f benchmark *.o libcityhash.so

# vim: set noet ts=8 sw=8:

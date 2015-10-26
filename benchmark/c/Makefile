CXX = clang++
CXXFLAGS = -std=c++11 -O3

all: benchmark

benchmark: benchmark.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f benchmark

# vim: set noet ts=8 sw=8:

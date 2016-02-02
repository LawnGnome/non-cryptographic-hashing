#include "city.h"

extern "C" {
	uint32_t cityhash32(const char *buf, size_t len);
}

uint32_t cityhash32(const char *buf, size_t len) {
	return CityHash32(buf, len);
}

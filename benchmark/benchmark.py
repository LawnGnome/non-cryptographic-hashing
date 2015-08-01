from argparse import ArgumentParser
from numpy import seterr, uint32
from struct import unpack
from time import process_time

from image import draw

def timed(method):
    def time(*args, **kw):
        name = method.__name__
        if name not in TIMES:
            TIMES[name] = 0.0
        r = range(COUNT)
        before = process_time()
        for _ in r:
            ret = method(*args, **kw)
        after = process_time()
        TIMES[name] += after - before

        return ret

    return time

@timed
def crc32(data: bytes) -> int:
    from zlib import crc32

    return crc32(data) & 0xffffffff

@timed
def fnv132(data: bytes) -> uint32:
    hash = uint32(2166136261)
    for byte in data:
        hash *= uint32(16777619)
        hash ^= uint32(byte)
    return hash

@timed
def fnv1a32(data: bytes) -> uint32:
    hash = uint32(2166136261)
    for byte in data:
        hash ^= uint32(byte)
        hash *= uint32(16777619)
    return hash

@timed
def jshash(data: bytes):
    hash = uint32(1315423911)
    for byte in data:
        hash ^= ((hash << uint32(5)) + uint32(byte) + (hash >> uint32(2)))
    return hash

@timed
def murmurhash3(data: bytes) -> uint32:
    c1 = uint32(0xcc9e2d51)
    c2 = uint32(0x1b873593)
    r1 = uint32(15)
    r2 = uint32(13)
    m = uint32(5)
    n = uint32(0xe6546b64)

    # Randomly selected seed.
    hash = uint32(0x3490f1ab)

    i = 0
    while i < len(data):
        c = data[i:i+4]
        i += 4

        if len(c) == 4:
            k = uint32(unpack("=L", c)[0])
            k *= c1
            k = (k << r1) | (k >> (uint32(32) - r1))
            k *= c2
            hash ^= k
            hash = (hash << r2) | (hash >> (uint32(32) - r2))
            hash = hash * m + n
        else:
            k = uint32(0)
            if len(c) == 3:
                k ^= uint32(c[2] << 16)
            if len(c) >= 2:
                k ^= uint32(c[1] << 8)
            if len(c) >= 1:
                k ^= uint32(c[0])
                k *= c1
                k = (k << r1) | (k >> (uint32(32) - r1))
                k *= c2
                hash ^= k

    hash ^= uint32(len(data))
    hash ^= uint32(hash >> 16)
    hash *= uint32(0x85ebca6b)
    hash ^= uint32(hash << 13)
    hash *= uint32(0xc2b2ae35)
    hash ^= uint32(hash >> 16)

    return hash

@timed
def superfasthash(data: bytes) -> uint32:
    seed = uint32(0xa95fd39a)
    hash = seed + uint32(len(data))

    i = 0
    while i < len(data):
        c = data[i:i+4]
        i += 4

        if len(c) == 4:
            high = uint32(unpack("=H", c[0:2])[0])
            low = uint32(unpack("=H", c[2:4])[0])

            hash += high
            tmp = (low << uint32(11)) ^ hash
            hash = (hash << uint32(16)) ^ tmp
            hash += hash >> uint32(11)
        elif len(c) == 3:
            high = uint32(unpack("=H", c[0:2])[0])
            low = uint32(unpack("=B", c[2:])[0])

            hash += high
            hash ^= hash << uint32(16)
            hash ^= low << uint32(18)
            hash += hash >> uint32(11)
        elif len(c) == 2:
            hash += uint32(unpack("=H", c)[0])
            hash ^= hash << uint32(11)
            hash += hash >> uint32(17)
        elif len(c) == 1:
            hash += uint32(unpack("=B", c)[0])
            hash ^= hash << uint32(10)
            hash += hash >> uint32(1)

    hash ^= hash << uint32(3)
    hash += hash >> uint32(5)
    hash ^= hash << uint32(4)
    hash += hash >> uint32(17)
    hash ^= hash << uint32(25)
    hash += hash >> uint32(6)

    return hash

ALGORITHMS = {
    "crc32": crc32,
    "fnv132": fnv132,
    "fnv1a32": fnv1a32,
    "jshash": jshash,
    "murmurhash3": murmurhash3,
    "superfasthash": superfasthash,
}

COLLISIONS = {}
COUNT = 1
TIMES = {}

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("algorithms", metavar="ALGO", type=str, nargs="*")
    parser.add_argument("-c", "--count", default=1, type=int)
    parser.add_argument("-i", "--input", type=str)
    args = parser.parse_args()

    COUNT = args.count
    data = open(args.input, "rb").readlines()

    seterr(over="ignore")

    algorithms = args.algorithms if args.algorithms else ALGORITHMS.keys()
    for algo in algorithms:
        if algo not in ALGORITHMS:
            raise RuntimeError("Unknown algorithm %s" % algo)
        results = set()
        for line in data:
            results.add(ALGORITHMS[algo](line))
        COLLISIONS[algo] = len(data) - len(results)

        draw(results).save("%s.png" % algo, "PNG")

        print("%s:\n\ttime: %f\n\tcollisions: %d\n" % (algo, TIMES[algo], COLLISIONS[algo]))

# vim: set et ts=4 sw=4 nocin ai:

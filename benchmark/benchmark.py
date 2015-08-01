from argparse import ArgumentParser
from numpy import seterr, uint32
from struct import unpack
from time import process_time

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
        hash ^= ((hash << 5) + byte + (hash >> 2))
    return hash

@timed
def murmur3(data: bytes) -> uint32:
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

ALGORITHMS = {
    "fnv1a32": fnv1a32,
    "jshash": jshash,
    "murmur3": murmur3,
}

COLLISIONS = {}
COUNT = 1
TIMES = {}

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("algorithms", metavar="ALGO", type=str, nargs="+")
    parser.add_argument("-c", "--count", default=1, type=int)
    parser.add_argument("-i", "--input", type=str)
    args = parser.parse_args()

    COUNT = args.count
    data = open(args.input, "rb").readlines()

    seterr(over="ignore")

    for algo in args.algorithms:
        if algo not in ALGORITHMS:
            raise RuntimeError("Unknown algorithm %s" % algo)
        results = set()
        for line in data:
            results.add(ALGORITHMS[algo](line))
        COLLISIONS[algo] = len(data) - len(results)

        print("%s:\n\ttime: %f\n\tcollisions: %d\n" % (algo, TIMES[algo], COLLISIONS[algo]))

# vim: set et ts=4 sw=4 nocin ai:

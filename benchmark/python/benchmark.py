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
def cityhash32(data: bytes) -> int:
    from ctypes import cdll
    from os.path import realpath

    lib = cdll.LoadLibrary(realpath("../c/libcityhash.so"))
    return lib.cityhash32(data, len(data))

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

SBOX_TABLE = [uint32(n) for n in (
    0x4660c395, 0x3baba6c5, 0x27ec605b, 0xdfc1d81a, 0xaaac4406, 0x3783e9b8, 0xa4e87c68, 0x62dc1b2a,
    0xa8830d34, 0x10a56307, 0x4ba469e3, 0x54836450, 0x1b0223d4, 0x23312e32, 0xc04e13fe, 0x3b3d61fa,
    0xdab2d0ea, 0x297286b1, 0x73dbf93f, 0x6bb1158b, 0x46867fe2, 0xb7fb5313, 0x3146f063, 0x4fd4c7cb,
    0xa59780fa, 0x9fa38c24, 0x38c63986, 0xa0bac49f, 0xd47d3386, 0x49f44707, 0xa28dea30, 0xd0f30e6d,
    0xd5ca7704, 0x934698e3, 0x1a1ddd6d, 0xfa026c39, 0xd72f0fe6, 0x4d52eb70, 0xe99126df, 0xdfdaed86,
    0x4f649da8, 0x427212bb, 0xc728b983, 0x7ca5d563, 0x5e6164e5, 0xe41d3a24, 0x10018a23, 0x5a12e111,
    0x999ebc05, 0xf1383400, 0x50b92a7c, 0xa37f7577, 0x2c126291, 0x9daf79b2, 0xdea086b1, 0x85b1f03d,
    0x598ce687, 0xf3f5f6b9, 0xe55c5c74, 0x791733af, 0x39954ea8, 0xafcff761, 0x5fea64f1, 0x216d43b4,
    0xd039f8c1, 0xa6cf1125, 0xc14b7939, 0xb6ac7001, 0x138a2eff, 0x2f7875d6, 0xfe298e40, 0x4a3fad3b,
    0x066207fd, 0x8d4dd630, 0x96998973, 0xe656ac56, 0xbb2df109, 0x0ee1ec32, 0x03673d6c, 0xd20fb97d,
    0x2c09423c, 0x093eb555, 0xab77c1e2, 0x64607bf2, 0x945204bd, 0xe8819613, 0xb59de0e3, 0x5df7fc9a,
    0x82542258, 0xfb0ee357, 0xda2a4356, 0x5c97ab61, 0x8076e10d, 0x48e4b3cc, 0x7c28ec12, 0xb17986e1,
    0x01735836, 0x1b826322, 0x6602a990, 0x7c1cef68, 0xe102458e, 0xa5564a67, 0x1136b393, 0x98dc0ea1,
    0x3b6f59e5, 0x9efe981d, 0x35fafbe0, 0xc9949ec2, 0x62c765f9, 0x510cab26, 0xbe071300, 0x7ee1d449,
    0xcc71beef, 0xfbb4284e, 0xbfc02ce7, 0xdf734c93, 0x2f8cebcd, 0xfeedc6ab, 0x5476ee54, 0xbd2b5ff9,
    0xf4fd0352, 0x67f9d6ea, 0x7b70db05, 0x5a5f5310, 0x482dd7aa, 0xa0a66735, 0x321ae71f, 0x8e8ad56c,
    0x27a509c3, 0x1690b261, 0x4494b132, 0xc43a42a7, 0x3f60a7a6, 0xd63779ff, 0xe69c1659, 0xd15972c8,
    0x5f6cdb0c, 0xb9415af2, 0x1261ad8d, 0xb70a6135, 0x52ceda5e, 0xd4591dc3, 0x442b793c, 0xe50e2dee,
    0x6f90fc79, 0xd9ecc8f9, 0x063dd233, 0x6cf2e985, 0xe62cfbe9, 0x3466e821, 0x2c8377a2, 0x00b9f14e,
    0x237c4751, 0x40d4a33b, 0x919df7e8, 0xa16991a4, 0xc5295033, 0x5c507944, 0x89510e2b, 0xb5f7d902,
    0xd2d439a6, 0xc23e5216, 0xd52d9de3, 0x534a5e05, 0x762e73d4, 0x3c147760, 0x2d189706, 0x20aa0564,
    0xb07bbc3b, 0x8183e2de, 0xebc28889, 0xf839ed29, 0x532278f7, 0x41f8b31b, 0x762e89c1, 0xa1e71830,
    0xac049bfc, 0x9b7f839c, 0x8fd9208d, 0x2d2402ed, 0xf1f06670, 0x2711d695, 0x5b9e8fe4, 0xdc935762,
    0xa56b794f, 0xd8666b88, 0x6872c274, 0xbc603be2, 0x2196689b, 0x5b2b5f7a, 0x00c77076, 0x16bfa292,
    0xc2f86524, 0xdd92e83e, 0xab60a3d4, 0x92daf8bd, 0x1fe14c62, 0xf0ff82cc, 0xc0ed8d0a, 0x64356e4d,
    0x7e996b28, 0x81aad3e8, 0x05a22d56, 0xc4b25d4f, 0x5e3683e5, 0x811c2881, 0x124b1041, 0xdb1b4f02,
    0x5a72b5cc, 0x07f8d94e, 0xe5740463, 0x498632ad, 0x7357ffb1, 0x0dddd380, 0x3d095486, 0x2569b0a9,
    0xd6e054ae, 0x14a47e22, 0x73ec8dcc, 0x004968cf, 0xe0c3a853, 0xc9b50a03, 0xe1b0eb17, 0x57c6f281,
    0xc9f9377d, 0x43e03612, 0x9a0c4554, 0xbb2d83ff, 0xa818ffee, 0xf407db87, 0x175e3847, 0x5597168f,
    0xd3d547a7, 0x78f3157c, 0xfc750f20, 0x9880a1c6, 0x1af41571, 0x95d01dfc, 0xa3968d62, 0xeae03cf8,
    0x02ee4662, 0x5f1943ff, 0x252d9d1c, 0x6b718887, 0xe052f724, 0x4cefa30b, 0xdcc31a00, 0xe4d0024d,
    0xdbb4534a, 0xce01f5c8, 0x0c072b61, 0x5d59736a, 0x60291da4, 0x1fbe2c71, 0x2f11d09c, 0x9dce266a,
)]

@timed
def sbox(data: bytes) -> uint32:
    seed = uint32(0xe29340db)
    hash = uint32(len(data)) + uint32(seed)

    for offset in range(0, len(data) - 1, 2):
        hash = (((hash ^ SBOX_TABLE[data[offset]]) * uint32(3)) ^ SBOX_TABLE[data[offset+1]]) * uint32(3)

    if len(data) % 2 == 1:
        hash ^= SBOX_TABLE[data[-1]]
        hash *= uint32(3)

    hash = (hash >> uint32(22)) ^ (hash << uint32(4))
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

@timed
def xxhash32(data: bytes) -> uint32:
    primes = [uint32(n) for n in (
        2654435761,
        2246822519,
        3266489917,
        668265263,
        374761393
    )]
    seed = uint32(0x2341bb20)

    hash = uint32(0)
    offset = 0

    def get32bits():
        nonlocal offset

        chunk = data[offset:offset+4]
        offset += 4
        return uint32(unpack("=L", chunk)[0])

    def rotl(x: uint32, r) -> uint32:
        return (x << uint32(r)) | (x >> uint32(32 - r))

    if len(data) >= 16:
        v1 = seed + primes[0] + primes[1]
        v2 = seed + primes[1]
        v3 = seed
        v4 = seed - primes[0]

        def mix(v: uint32, chunk: uint32) -> uint32:
            v += chunk * primes[1]
            v = rotl(v, 13)
            return v * primes[0]

        while offset <= (len(data) - 16):
            v1 = mix(v1, get32bits())
            v2 = mix(v2, get32bits())
            v3 = mix(v3, get32bits())
            v4 = mix(v4, get32bits())

        hash = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
    else:
        hash = seed + primes[4]

    hash += uint32(len(data))

    while (offset + 4) < len(data):
        hash += get32bits() * primes[2]
        hash = rotl(hash, 17) * primes[3]

    while offset < len(data):
        hash += uint32(data[offset]) * primes[4]
        offset += 1
        hash = rotl(hash, 11) * primes[0]

    hash ^= hash >> uint32(15)
    hash *= primes[1]
    hash ^= hash >> uint32(13)
    hash *= primes[2]
    hash ^= hash >> uint32(16)

    return hash

ALGORITHMS = {
    "cityhash32": cityhash32,
    "crc32": crc32,
    "fnv132": fnv132,
    "fnv1a32": fnv1a32,
    "jshash": jshash,
    "murmurhash3": murmurhash3,
    "sbox": sbox,
    "superfasthash": superfasthash,
    "xxhash32": xxhash32,
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

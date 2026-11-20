#include "rsa_lab.h"

#include <algorithm>
#include <array>
#include <random>

namespace {
std::random_device rng;

BigInt gcd(BigInt a, BigInt b) {
    while (b != 0) {
        BigInt r = a % b;
        a = b;
        b = r;
    }
    return a;
}

BigInt modInverse(BigInt a, BigInt mod) {
    BigInt oldR = a, r = mod;
    BigInt oldX = 1, x = 0;

    while (r != 0) {
        BigInt q = oldR / r;
        BigInt tempR = oldR - q * r;
        oldR = r;
        r = tempR;

        BigInt tempX = oldX - q * x;
        oldX = x;
        x = tempX;
    }

    BigInt result = oldX % mod;
    if (result < 0) result += mod;
    return result;
}

BigInt modPow(const BigInt& a, const BigInt& b, const BigInt& mod) {
    return boost::multiprecision::powm(a, b, mod);
}

BigInt randomBits(int bits) {
    BigInt value = 0;
    int generated = 0;

    while (generated < bits) {
        value <<= 32;
        value += static_cast<std::uint32_t>(rng());
        generated += 32;
    }

    if (generated > bits) {
        value &= (BigInt(1) << bits) - 1;
    }
    return value;
}

bool isProbablyPrime(const BigInt& n) {
    if (n < 2) return false;

    const int smallPrimes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (int p : smallPrimes) {
        if (n == p) return true;
        if (n % p == 0) return false;
    }

    BigInt d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }

    int bits = boost::multiprecision::msb(n) + 1;
    for (int round = 0; round < 16; ++round) {
        BigInt a = 2 + randomBits(bits) % (n - 3);
        BigInt x = modPow(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool passed = false;
        for (int i = 1; i < s; ++i) {
            x = (x * x) % n;
            if (x == n - 1) {
                passed = true;
                break;
            }
        }
        if (!passed) return false;
    }
    return true;
}

BigInt generatePrime(int bits) {
    while (true) {
        BigInt number = randomBits(bits);
        number |= BigInt(1) << (bits - 1); // exact bit length
        number |= 1;                      // odd number

        if (isProbablyPrime(number)) return number;
    }
}

void fillRandom(Byte* data, std::size_t size) {
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<Byte>(rng() & 0xFF);
    }
}

// ---------- Streebog-256 ----------
using Block = std::array<std::uint64_t, 8>;

constexpr Byte PI[256] = {
    252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,
    233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,
    249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,
    5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,
    235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,
    181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,
    21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,
    50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,
    223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,
    224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,
    167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,
    173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,
    7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,
    225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,
    32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,
    89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182
};

constexpr std::uint64_t A[64] = {
    0x8e20faa72ba0b470ULL,0x47107ddd9b505a38ULL,0xad08b0e0c3282d1cULL,0xd8045870ef14980eULL,
    0x6c022c38f90a4c07ULL,0x3601161cf205268dULL,0x1b8e0b0e798c13c8ULL,0x83478b07b2468764ULL,
    0xa011d380818e8f40ULL,0x5086e740ce47c920ULL,0x2843fd2067adea10ULL,0x14aff010bdd87508ULL,
    0x0ad97808d06cb404ULL,0x05e23c0468365a02ULL,0x8c711e02341b2d01ULL,0x46b60f011a83988eULL,
    0x90dab52a387ae76fULL,0x486dd4151c3dfdb9ULL,0x24b86a840e90f0d2ULL,0x125c354207487869ULL,
    0x092e94218d243cbaULL,0x8a174a9ec8121e5dULL,0x4585254f64090fa0ULL,0xaccc9ca9328a8950ULL,
    0x9d4df05d5f661451ULL,0xc0a878a0a1330aa6ULL,0x60543c50de970553ULL,0x302a1e286fc58ca7ULL,
    0x18150f14b9ec46ddULL,0x0c84890ad27623e0ULL,0x0642ca05693b9f70ULL,0x0321658cba93c138ULL,
    0x86275df09ce8aaa8ULL,0x439da0784e745554ULL,0xafc0503c273aa42aULL,0xd960281e9d1d5215ULL,
    0xe230140fc0802984ULL,0x71180a8960409a42ULL,0xb60c05ca30204d21ULL,0x5b068c651810a89eULL,
    0x456c34887a3805b9ULL,0xac361a443d1c8cd2ULL,0x561b0d22900e4669ULL,0x2b838811480723baULL,
    0x9bcf4486248d9f5dULL,0xc3e9224312c8c1a0ULL,0xeffa11af0964ee50ULL,0xf97d86d98a327728ULL,
    0xe4fa2054a80b329cULL,0x727d102a548b194eULL,0x39b008152acb8227ULL,0x9258048415eb419dULL,
    0x492c024284fbaec0ULL,0xaa16012142f35760ULL,0x550b8e9e21f7a530ULL,0xa48b474f9ef5dc18ULL,
    0x70a6a56e2440598eULL,0x3853dc371220a247ULL,0x1ca76e95091051adULL,0x0edd37c48a08a6d8ULL,
    0x07e095624504536cULL,0x8d70c431ac02a736ULL,0xc83862965601dd1bULL,0x641c314b2b8ee083ULL
};

constexpr std::uint64_t C[12][8] = {
    {0xdd806559f2a64507ULL,0x05767436cc744d23ULL,0xa2422a08a460d315ULL,0x4b7ce09192676901ULL,0x714eb88d7585c4fcULL,0x2f6a76432e45d016ULL,0xebcb2f81c0657c1fULL,0xb1085bda1ecadae9ULL},
    {0xe679047021b19bb7ULL,0x55dda21bd7cbcd56ULL,0x5cb561c2db0aa7caULL,0x9ab5176b12d69958ULL,0x61d55e0f16b50131ULL,0xf3feea720a232b98ULL,0x4fe39d460f70b5d7ULL,0x6fa3b58aa99d2f1aULL},
    {0x991e96f50aba0ab2ULL,0xc2b6f443867adb31ULL,0xc1c93a376062db09ULL,0xd3e20fe490359eb1ULL,0xf2ea7514b1297b7bULL,0x06f15e5f529c1f8bULL,0x0a39fc286a3d8435ULL,0xf574dcac2bce2fc7ULL},
    {0x220cbebc84e3d12eULL,0x3453eaa193e837f1ULL,0xd8b71333935203beULL,0xa9d72c82ed03d675ULL,0x9d721cad685e353fULL,0x488e857e335c3c7dULL,0xf948e1a05d71e4ddULL,0xef1fdfb3e81566d2ULL},
    {0x601758fd7c6cfe57ULL,0x7a56a27ea9ea63f5ULL,0xdfff00b723271a16ULL,0xbfcd1747253af5a3ULL,0x359e35d7800fffbdULL,0x7f151c1f1686104aULL,0x9a3f410c6ca92363ULL,0x4bea6bacad474799ULL},
    {0xfa68407a46647d6eULL,0xbf71c57236904f35ULL,0x0af21f66c2bec6b6ULL,0xcffaa6b71c9ab7b4ULL,0x187f9ab49af08ec6ULL,0x2d66c4f95142a46cULL,0x6fa4c33b7a3039c0ULL,0xae4faeae1d3ad3d9ULL},
    {0x8886564d3a14d493ULL,0x3517454ca23c4af3ULL,0x06476983284a0504ULL,0x0992abc52d822c37ULL,0xd3473e33197a93c9ULL,0x399ec6c7e6bf87c9ULL,0x51ac86febf240954ULL,0xf4c70e16eeaac5ecULL},
    {0xa47f0dd4bf02e71eULL,0x36acc2355951a8d9ULL,0x69d18d2bd1a5c42fULL,0xf4892bcb929b0690ULL,0x89b4443b4ddbc49aULL,0x4eb7f8719c36de1eULL,0x03e7aa020c6e4141ULL,0x9b1f5b424d93c9a7ULL},
    {0x7261445183235adbULL,0x0e38dc92cb1f2a60ULL,0x7b2b8a9aa6079c54ULL,0x800a440bdbb2ceb1ULL,0x3cd955b7e00d0984ULL,0x3a7d3a1b25894224ULL,0x944c9ad8ec165fdeULL,0x378f5a541631229bULL},
    {0x74b4c7fb98459cedULL,0x3698fad1153bb6c3ULL,0x7a1e6c303b7652f4ULL,0x9fe76702af69334bULL,0x1fffe18a1b336103ULL,0x8941e71cff8a78dbULL,0x382ae548b2e4f3f3ULL,0xabbedea680056f52ULL},
    {0x6bcaa4cd81f32d1bULL,0xdea2594ac06fd85dULL,0xefbacd1d7d476e98ULL,0x8a1d71efea48b9caULL,0x2001802114846679ULL,0xd8fa6bbbebab0761ULL,0x3002c6cd635afe94ULL,0x7bcd9ed0efc889fbULL},
    {0x48bc924af11bd720ULL,0xfaf417d5d9b21b99ULL,0xe71da4aa88e12852ULL,0x5d80ef9d1891cc86ULL,0xf82012d430219f9bULL,0xcda43c32bcdf1d77ULL,0xd21380b00449b17aULL,0x378ee767f11631baULL}
};

Block xorBlocks(const Block& a, const Block& b) {
    Block result{};
    for (int i = 0; i < 8; ++i) result[i] = a[i] ^ b[i];
    return result;
}

// Performs the Streebog S, P and L transformations together.
Block lps(const Block& a, const Block& b) {
    Block result{};

    for (int bytePosition = 0; bytePosition < 8; ++bytePosition) {
        std::uint64_t word = 0;

        for (int wordPosition = 0; wordPosition < 8; ++wordPosition) {
            Byte value = static_cast<Byte>((a[wordPosition] ^ b[wordPosition]) >> (bytePosition * 8));
            Byte substituted = PI[value];

            for (int bit = 0; bit < 8; ++bit) {
                if (substituted & (1u << bit)) {
                    word ^= A[63 - (wordPosition * 8 + bit)];
                }
            }
        }
        result[bytePosition] = word;
    }
    return result;
}

void add512(Block& a, const Block& b) {
    std::uint64_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        std::uint64_t old = a[i];
        a[i] += b[i];
        std::uint64_t carry1 = a[i] < old;

        old = a[i];
        a[i] += carry;
        std::uint64_t carry2 = a[i] < old;
        carry = carry1 | carry2;
    }
}

Block bytesToBlock(const Byte* data) {
    Block result{};
    for (int i = 0; i < 64; ++i) {
        result[i / 8] |= static_cast<std::uint64_t>(data[i]) << ((i % 8) * 8);
    }
    return result;
}

void compress(Block& h, const Block& n, const Block& m) {
    Block key = lps(h, n);
    Block data = lps(key, m);

    for (int round = 0; round < 11; ++round) {
        Block constant{};
        for (int i = 0; i < 8; ++i) constant[i] = C[round][i];
        key = lps(key, constant);
        data = lps(key, data);
    }

    Block constant{};
    for (int i = 0; i < 8; ++i) constant[i] = C[11][i];
    key = lps(key, constant);
    h = xorBlocks(xorBlocks(key, data), xorBlocks(h, m));
}

void mgf1(const Byte* seed, std::size_t seedSize, Byte* output, std::size_t outputSize) {
    // MGF1 needs seed || 4-byte counter. Fixed memory is enough here.
    std::array<Byte, RSA_BYTES> input{};
    std::copy(seed, seed + seedSize, input.begin());

    std::size_t written = 0;
    std::uint32_t counter = 0;

    while (written < outputSize) {
        input[seedSize]     = static_cast<Byte>(counter >> 24);
        input[seedSize + 1] = static_cast<Byte>(counter >> 16);
        input[seedSize + 2] = static_cast<Byte>(counter >> 8);
        input[seedSize + 3] = static_cast<Byte>(counter);

        Hash256 hash = streebog256(input.data(), seedSize + 4);
        std::size_t count = std::min<std::size_t>(HASH_BYTES, outputSize - written);
        std::copy(hash.begin(), hash.begin() + count, output + written);

        written += count;
        ++counter;
    }
}
} // namespace

RSAKey generateRSAKey() {
    RSAKey key;
    key.e = 65537;

    while (true) {
        key.p = generatePrime(2048);
        key.q = generatePrime(2048);
        if (key.p == key.q) continue;

        key.n = key.p * key.q;
        if (boost::multiprecision::msb(key.n) + 1 != RSA_BITS) continue;

        BigInt p1 = key.p - 1;
        BigInt q1 = key.q - 1;
        BigInt lambda = (p1 / gcd(p1, q1)) * q1;
        if (gcd(key.e, lambda) != 1) continue;

        key.d = modInverse(key.e, lambda);
        key.dp = key.d % p1;
        key.dq = key.d % q1;
        key.qInv = modInverse(key.q, key.p);
        return key;
    }
}

BigInt bytesToBigInt(const Byte* data, std::size_t size) {
    BigInt value = 0;
    for (std::size_t i = 0; i < size; ++i) {
        value = value * 256 + data[i];
    }
    return value;
}

RSABytes bigIntToBytes(BigInt value) {
    RSABytes bytes{};
    for (int i = RSA_BYTES - 1; i >= 0; --i) {
        bytes[i] = static_cast<Byte>(value & 0xFF);
        value >>= 8;
    }
    return bytes;
}

BigInt rsaEncrypt(const BigInt& message, const RSAKey& key) {
    return modPow(message, key.e, key.n);
}

bool rsaDecryptCRT(const BigInt& cipher, const RSAKey& key,
                   BigInt& message, bool simulateFault) {
    BigInt m1 = modPow(cipher, key.dp, key.p);
    BigInt m2 = modPow(cipher, key.dq, key.q);

    // Garner reconstruction.
    BigInt h = (key.qInv * (m1 - m2 + key.p)) % key.p;
    message = m2 + h * key.q;

    if (simulateFault) message ^= 1; // only for demonstration

    // Variant 6: do not release the result until it is checked.
    return modPow(message, key.e, key.n) == cipher;
}

Hash256 streebog256(const Byte* data, std::size_t size) {
    Block h{}, n{}, sigma{}, fullBlockBits{};
    h.fill(0x0101010101010101ULL);
    fullBlockBits[0] = 512;

    std::size_t pos = 0;
    while (size - pos >= 64) {
        Block block = bytesToBlock(data + pos);
        compress(h, n, block);
        add512(n, fullBlockBits);
        add512(sigma, block);
        pos += 64;
    }

    std::array<Byte, 64> last{};
    std::size_t left = size - pos;
    for (std::size_t i = 0; i < left; ++i) last[i] = data[pos + i];
    last[left] = 1;

    Block finalBlock = bytesToBlock(last.data());
    compress(h, n, finalBlock);

    Block messageBits{};
    messageBits[0] = left * 8;
    add512(n, messageBits);
    add512(sigma, finalBlock);

    compress(h, Block{}, n);
    compress(h, Block{}, sigma);

    Hash256 result{};
    for (int i = 0; i < HASH_BYTES; ++i) {
        result[i] = static_cast<Byte>(h[i / 8 + 4] >> ((i % 8) * 8));
    }
    return result;
}

bool oaepEncode(const std::vector<Byte>& message, RSABytes& encoded) {
    if (message.size() > MAX_MESSAGE_BYTES) return false;

    constexpr int DB_SIZE = RSA_BYTES - HASH_BYTES - 1; // 479
    std::array<Byte, DB_SIZE> db{};
    std::array<Byte, DB_SIZE> dbMask{};
    std::array<Byte, HASH_BYTES> seed{};
    std::array<Byte, HASH_BYTES> seedMask{};

    Hash256 labelHash = streebog256(nullptr, 0); // empty label
    std::copy(labelHash.begin(), labelHash.end(), db.begin());

    std::size_t delimiter = DB_SIZE - message.size() - 1;
    db[delimiter] = 1;
    std::copy(message.begin(), message.end(), db.begin() + delimiter + 1);

    fillRandom(seed.data(), seed.size());
    mgf1(seed.data(), seed.size(), dbMask.data(), dbMask.size());

    for (int i = 0; i < DB_SIZE; ++i) db[i] ^= dbMask[i];

    mgf1(db.data(), db.size(), seedMask.data(), seedMask.size());
    for (int i = 0; i < HASH_BYTES; ++i) seed[i] ^= seedMask[i];

    encoded.fill(0);
    std::copy(seed.begin(), seed.end(), encoded.begin() + 1);
    std::copy(db.begin(), db.end(), encoded.begin() + 1 + HASH_BYTES);
    return true;
}

bool oaepDecode(const RSABytes& encoded, std::vector<Byte>& message) {
    constexpr int DB_SIZE = RSA_BYTES - HASH_BYTES - 1;
    std::array<Byte, HASH_BYTES> seed{};
    std::array<Byte, HASH_BYTES> seedMask{};
    std::array<Byte, DB_SIZE> db{};
    std::array<Byte, DB_SIZE> dbMask{};

    std::copy(encoded.begin() + 1,
              encoded.begin() + 1 + HASH_BYTES, seed.begin());
    std::copy(encoded.begin() + 1 + HASH_BYTES,
              encoded.end(), db.begin());

    mgf1(db.data(), db.size(), seedMask.data(), seedMask.size());
    for (int i = 0; i < HASH_BYTES; ++i) seed[i] ^= seedMask[i];

    mgf1(seed.data(), seed.size(), dbMask.data(), dbMask.size());
    for (int i = 0; i < DB_SIZE; ++i) db[i] ^= dbMask[i];

    // Check the complete OAEP block before returning an error.
    Byte error = encoded[0];
    Hash256 labelHash = streebog256(nullptr, 0);
    for (int i = 0; i < HASH_BYTES; ++i) {
        error |= db[i] ^ labelHash[i];
    }

    Byte lookingForDelimiter = 1;
    std::size_t messageStart = DB_SIZE;

    for (std::size_t i = HASH_BYTES; i < DB_SIZE; ++i) {
        Byte isZero = static_cast<Byte>(db[i] == 0);
        Byte isOne  = static_cast<Byte>(db[i] == 1);

        // Before the first 0x01 only zero bytes are valid.
        error |= static_cast<Byte>(lookingForDelimiter & ((isZero | isOne) ^ 1));

        // Save the first 0x01 position without an early exit.
        std::size_t found = static_cast<std::size_t>(lookingForDelimiter & isOne);
        std::size_t mask = 0 - found;
        messageStart = (messageStart & ~mask) | ((i + 1) & mask);

        lookingForDelimiter &= static_cast<Byte>(isOne ^ 1);
    }

    // No delimiter means invalid OAEP.
    error |= lookingForDelimiter;

    if (error != 0) return false;

    message.assign(db.begin() + messageStart, db.end());
    return true;
}

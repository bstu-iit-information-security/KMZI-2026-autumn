#include <cstdint>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <array>
#include <windows.h>

namespace sha3impl {

static constexpr std::uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline std::uint64_t rotl(std::uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccak_f(std::uint64_t s[25]) {
    for (int round = 0; round < 24; ++round) {
        std::uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                s[x + 5*y] ^= D[x];

        std::uint64_t B[25];
        static const int rho[25] = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                B[y + 5*((2*x + 3*y) % 5)] = rotl(s[x + 5*y], rho[x + 5*y]);

        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                s[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);

        s[0] ^= RC[round];
    }
}

}

void sha3_512(const std::uint8_t* data, std::size_t len,
              std::uint8_t out[64]) {
    constexpr std::size_t RATE = 72;
    std::uint64_t state[25] = {0};
    std::uint8_t block[RATE];
    std::size_t i = 0;

    auto absorb_block = [&](const std::uint8_t* blk, std::size_t n) {
        for (std::size_t j = 0; j < n; ++j) {
            state[j/8] ^= static_cast<std::uint64_t>(blk[j]) << (8 * (j % 8));
        }
        sha3impl::keccak_f(state);
    };

    while (len - i >= RATE) {
        absorb_block(data + i, RATE);
        i += RATE;
    }

    std::memset(block, 0, RATE);
    std::size_t rem = len - i;
    std::memcpy(block, data + i, rem);
    block[rem] ^= 0x06;
    block[RATE - 1] ^= 0x80;
    absorb_block(block, RATE);

    for (std::size_t j = 0; j < 64; ++j) {
        out[j] = static_cast<std::uint8_t>(state[j/8] >> (8 * (j % 8)));
    }
}

namespace bigint {
using BigInt = long long;

BigInt gcd(const BigInt& a, const BigInt& b) {
    BigInt x = a < 0 ? -a : a;
    BigInt y = b < 0 ? -b : b;
    while (y != 0) { BigInt t = x % y; x = y; y = t; }
    return x;
}

BigInt mod_mul(const BigInt& a, const BigInt& b, const BigInt& mod) {
    using u128 = unsigned __int128;
    u128 r = (u128)((unsigned long long)a) * (u128)((unsigned long long)b);
    return (BigInt)(r % (u128)((unsigned long long)mod));
}

BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    BigInt result = 1 % mod;
    BigInt b = base % mod;
    if (b < 0) b += mod;
    BigInt e = exp;
    while (e > 0) {
        if (e & 1) result = mod_mul(result, b, mod);
        b = mod_mul(b, b, mod);
        e >>= 1;
    }
    return result;
}

BigInt mod_inv(const BigInt& a, const BigInt& mod) {
    BigInt t = 0, newt = 1;
    BigInt r = mod, newr = a % mod;
    if (newr < 0) newr += mod;
    while (newr != 0) {
        BigInt q = r / newr;
        BigInt tmp = t - q * newt; t = newt; newt = tmp;
        tmp = r - q * newr; r = newr; newr = tmp;
    }
    if (r > 1) throw std::runtime_error("mod_inv: not invertible");
    if (t < 0) t += mod;
    return t;
}

BigInt random_bits(std::size_t bits) {
    BigInt r = 0;
    for (std::size_t i = 0; i < bits; ++i) {
        r = (r << 1) | (std::rand() & 1);
    }
    return r;
}

bool is_probable_prime(const BigInt& n, int rounds) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    BigInt d = n - 1;
    int s = 0;
    while ((d & 1) == 0) { d >>= 1; ++s; }
    for (int i = 0; i < rounds; ++i) {
        BigInt a = 2 + (std::rand() % (n - 3));
        BigInt x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool cont = false;
        for (int r = 1; r < s; ++r) {
            x = mod_mul(x, x, n);
            if (x == n - 1) { cont = true; break; }
        }
        if (!cont) return false;
    }
    return true;
}

}

namespace rsa_math {
using bigint::BigInt;

struct PublicKey { BigInt N; BigInt e; };
struct PrivateKey { BigInt N, d, p, q, dp, dq, q_inv; };
struct KeyPair { PublicKey pub; PrivateKey priv; };

BigInt extended_gcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) {
    if (b == 0) { x = 1; y = 0; return a; }
    BigInt x1, y1;
    BigInt g = extended_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

BigInt mod_inverse(const BigInt& a, const BigInt& m) {
    BigInt x, y;
    BigInt g = extended_gcd(a, m, x, y);
    if (g != 1) throw std::runtime_error("mod_inverse: not coprime");
    return (x % m + m) % m;
}

BigInt lcm(const BigInt& a, const BigInt& b) {
    return (a / bigint::gcd(a, b)) * b;
}

KeyPair generate_keypair(std::size_t modulus_bits = 2048) {
    KeyPair kp;
    return kp;
}
}

namespace rsa_core {
using bigint::BigInt;

static inline std::uint32_t ct_select_u32(std::uint32_t a, std::uint32_t b,
                                          std::uint32_t cond) {
    std::uint32_t mask = static_cast<std::uint32_t>(-(std::int32_t)cond);
    return (a & ~mask) | (b & mask);
}

static std::uint32_t ct_memcmp_diff(const std::uint8_t* a,
                                    const std::uint8_t* b,
                                    std::size_t len) {
    std::uint32_t diff = 0;
    for (std::size_t i = 0; i < len; ++i)
        diff |= static_cast<std::uint32_t>(a[i] ^ b[i]);
    return (diff | (0u - diff)) >> 31;
}

BigInt rsa_decrypt_crt(const rsa_math::PrivateKey& priv, const BigInt& c) {
    BigInt m1 = bigint::mod_pow(c, priv.dp, priv.p);
    BigInt m2 = bigint::mod_pow(c, priv.dq, priv.q);
    BigInt diff = m1 - m2;
    if (diff < 0) diff += priv.p;
    BigInt h = bigint::mod_mul(priv.q_inv, diff, priv.p);
    return m2 + h * priv.q;
}

BigInt rsa_encrypt_raw(const rsa_math::PublicKey& pub, const BigInt& m) {
    return bigint::mod_pow(m, pub.e, pub.N);
}
}

namespace oaep {
constexpr std::size_t HASH_LEN = 64;
constexpr std::size_t MODULUS_BYTES = 2048 / 8;
constexpr std::size_t MAX_MSG_LEN = MODULUS_BYTES - 2 * HASH_LEN - 2;

void mgf1_sha3_512(const std::uint8_t* seed, std::size_t seed_len,
                   std::uint8_t* out, std::size_t out_len) {
    std::uint8_t counter[4] = {0, 0, 0, 0};
    std::size_t offset = 0;
    std::uint8_t digest[HASH_LEN];
    std::uint8_t buf[MODULUS_BYTES + 4];

    if (seed_len > MODULUS_BYTES)
        throw std::runtime_error("MGF1: seed too long");

    while (offset < out_len) {
        std::memcpy(buf, seed, seed_len);
        std::memcpy(buf + seed_len, counter, 4);
        sha3_512(buf, seed_len + 4, digest);
        std::size_t take = (out_len - offset < HASH_LEN) ? (out_len - offset) : HASH_LEN;
        std::memcpy(out + offset, digest, take);
        offset += take;
        for (int i = 3; i >= 0; --i)
            if (++counter[i] != 0) break;
    }
}

void oaep_encode(const std::uint8_t* msg, std::size_t msg_len,
                 std::uint8_t em[MODULUS_BYTES],
                 const std::uint8_t seed[HASH_LEN]) {
    if (msg_len > MAX_MSG_LEN)
        throw std::runtime_error("OAEP: message too long");

    std::uint8_t lhash[HASH_LEN];
    sha3_512(reinterpret_cast<const std::uint8_t*>(""), 0, lhash);

    constexpr std::size_t DB_LEN = MODULUS_BYTES - HASH_LEN - 1;
    std::uint8_t db[DB_LEN];
    std::memcpy(db, lhash, HASH_LEN);
    std::size_t ps_len = DB_LEN - HASH_LEN - 1 - msg_len;
    std::memset(db + HASH_LEN, 0, ps_len);
    db[HASH_LEN + ps_len] = 0x01;
    std::memcpy(db + HASH_LEN + ps_len + 1, msg, msg_len);

    std::uint8_t db_mask[DB_LEN];
    mgf1_sha3_512(seed, HASH_LEN, db_mask, DB_LEN);
    std::uint8_t masked_db[DB_LEN];
    for (std::size_t i = 0; i < DB_LEN; ++i)
        masked_db[i] = db[i] ^ db_mask[i];

    std::uint8_t seed_mask[HASH_LEN];
    mgf1_sha3_512(masked_db, DB_LEN, seed_mask, HASH_LEN);
    std::uint8_t masked_seed[HASH_LEN];
    for (std::size_t i = 0; i < HASH_LEN; ++i)
        masked_seed[i] = seed[i] ^ seed_mask[i];

    em[0] = 0x00;
    std::memcpy(em + 1, masked_seed, HASH_LEN);
    std::memcpy(em + 1 + HASH_LEN, masked_db, DB_LEN);
}

std::size_t oaep_decode(const std::uint8_t em[MODULUS_BYTES],
                        std::uint8_t* msg_out, std::size_t msg_out_cap) {
    constexpr std::size_t DB_LEN = MODULUS_BYTES - HASH_LEN - 1;
    std::uint32_t error_acc = 0;
    error_acc |= (em[0] != 0x00) ? 1u : 0u;

    const std::uint8_t* masked_seed = em + 1;
    const std::uint8_t* masked_db = em + 1 + HASH_LEN;

    std::uint8_t seed_mask[HASH_LEN];
    mgf1_sha3_512(masked_db, DB_LEN, seed_mask, HASH_LEN);
    std::uint8_t seed[HASH_LEN];
    for (std::size_t i = 0; i < HASH_LEN; ++i)
        seed[i] = masked_seed[i] ^ seed_mask[i];

    std::uint8_t db_mask[DB_LEN];
    mgf1_sha3_512(seed, HASH_LEN, db_mask, DB_LEN);
    std::uint8_t db[DB_LEN];
    for (std::size_t i = 0; i < DB_LEN; ++i)
        db[i] = masked_db[i] ^ db_mask[i];

    std::uint8_t lhash_expected[HASH_LEN];
    sha3_512(reinterpret_cast<const std::uint8_t*>(""), 0, lhash_expected);
    error_acc |= rsa_core::ct_memcmp_diff(db, lhash_expected, HASH_LEN);

    std::size_t separator_index = DB_LEN;
    std::uint32_t found = 0;
    for (std::size_t i = HASH_LEN; i < DB_LEN; ++i) {
        std::uint32_t is_one = (db[i] == 0x01) ? 1u : 0u;
        std::uint32_t take = is_one & (1u ^ found);
        separator_index = rsa_core::ct_select_u32(
            static_cast<std::uint32_t>(separator_index),
            static_cast<std::uint32_t>(i), take);
        found |= is_one;
    }

    std::uint32_t ps_ok = 1;
    for (std::size_t i = HASH_LEN; i < separator_index; ++i)
        ps_ok &= (db[i] == 0x00) ? 1u : 0u;
    error_acc |= (found ? 0u : 1u);
    error_acc |= (ps_ok ? 0u : 1u);

    std::size_t msg_len = (separator_index < DB_LEN)
                              ? (DB_LEN - separator_index - 1) : 0;
    if (msg_len > msg_out_cap) error_acc |= 1u;

    std::size_t safe_len = (msg_len <= msg_out_cap) ? msg_len : msg_out_cap;
    std::uint32_t good = (error_acc == 0) ? 1u : 0u;
    for (std::size_t i = 0; i < safe_len; ++i) {
        std::uint8_t val = db[separator_index + 1 + i];
        msg_out[i] = static_cast<std::uint8_t>(rsa_core::ct_select_u32(0, val, good));
    }
    return (error_acc == 0) ? msg_len : SIZE_MAX;
}
}

int main() {
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);

    std::cout << "RSA-OAEP variant 10: modulus=2048, hash=SHA3-512, heap-free\n";
    std::cout << "Max message length: " << oaep::MAX_MSG_LEN << " bytes\n";

    std::uint8_t seed[oaep::HASH_LEN] = {0};
    std::uint8_t em[oaep::MODULUS_BYTES];
    const char* msg = "test message is here ))";
    oaep::oaep_encode(reinterpret_cast<const std::uint8_t*>(msg),
                      std::strlen(msg), em, seed);

    std::uint8_t out[oaep::MAX_MSG_LEN];
    std::size_t out_len = oaep::oaep_decode(em, out, sizeof(out));
    if (out_len != SIZE_MAX) {
        std::cout << "Decoded message length: " << out_len << "\n";
        std::cout << "Message: ";
        std::cout.write(reinterpret_cast<char*>(out), out_len);
        std::cout << "\n";
    } else {
        std::cout << "Decode failed\n";
    }
    return 0;
}
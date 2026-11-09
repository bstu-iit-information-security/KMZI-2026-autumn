#include "oaep.h"
#include <stdexcept>

namespace rsa {

namespace {

const std::uint64_t SHA_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

inline std::uint64_t rotr64(std::uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

void sha512_block(std::uint64_t h[8], const std::uint8_t* p) {
    std::uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = 0;
        for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | p[i * 8 + j];
    }
    for (int i = 16; i < 80; ++i) {
        const std::uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        const std::uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    std::uint64_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
    for (int i = 0; i < 80; ++i) {
        const std::uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const std::uint64_t ch = (e & f) ^ (~e & g);
        const std::uint64_t t1 = hh + S1 + ch + SHA_K[i] + w[i];
        const std::uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const std::uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint64_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void mgf1(const std::uint8_t* seed, std::size_t seed_len, std::uint8_t* out, std::size_t out_len) {
    std::array<std::uint8_t, DB_LEN + 4> buf{};
    for (std::size_t i = 0; i < seed_len; ++i) buf[i] = seed[i];
    std::uint32_t counter = 0;
    std::size_t pos = 0;
    while (pos < out_len) {
        buf[seed_len+0] = static_cast<std::uint8_t>(counter >> 24);
        buf[seed_len+1] = static_cast<std::uint8_t>(counter >> 16);
        buf[seed_len+2] = static_cast<std::uint8_t>(counter >> 8);
        buf[seed_len+3] = static_cast<std::uint8_t>(counter);
        std::uint8_t h[64];
        sha512(buf.data(), seed_len + 4, h);
        for (std::size_t i = 0; i < 64 && pos < out_len; ++i, ++pos) out[pos] = h[i];
        ++counter;
    }
}

void lhash_empty(std::uint8_t out[64]) { sha512(nullptr, 0, out); }

inline std::uint8_t ct_neq0(std::uint8_t x) {
    const std::uint32_t v = x;
    return static_cast<std::uint8_t>(((v | (0u - v)) >> 31) & 1u);
}
inline std::uint8_t ct_eq(std::uint8_t a, std::uint8_t b) {
    return static_cast<std::uint8_t>(ct_neq0(static_cast<std::uint8_t>(a ^ b)) ^ 1u);
}
inline std::uint8_t ct_mask(std::uint8_t cond) {
    return static_cast<std::uint8_t>(0u - cond);
}

}

void sha512(const std::uint8_t* in, std::size_t len, std::uint8_t out[64]) {
    if (len > 400) throw std::invalid_argument("sha512: вход слишком длинный");
    std::uint64_t h[8] = {
        0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL
    };
    std::array<std::uint8_t, 512> pad{};
    for (std::size_t i = 0; i < len; ++i) pad[i] = in[i];
    pad[len] = 0x80;
    std::size_t total = len + 1;
    while (total % 128 != 112) ++total;
    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8;
    for (int i = 0; i < 8; ++i) pad[total+i] = static_cast<std::uint8_t>(bit_len >> (56-i*8));
    total += 16;
    for (std::size_t off = 0; off < total; off += 128) sha512_block(h, pad.data() + off);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) out[i*8+j] = static_cast<std::uint8_t>(h[i] >> (56-j*8));
}

EncodedBlock oaep_encode(const Message& m, const std::uint8_t seed[H_LEN]) {
    if (m.len > MAX_MSG) throw std::invalid_argument("oaep_encode: сообщение длиннее max");
    std::uint8_t lHash[H_LEN];
    lhash_empty(lHash);
    std::array<std::uint8_t, DB_LEN> db{};
    for (std::size_t i = 0; i < H_LEN; ++i) db[i] = lHash[i];
    const std::size_t ps_len = MAX_MSG - m.len;
    db[H_LEN + ps_len] = 0x01;
    for (std::size_t i = 0; i < m.len; ++i) db[H_LEN + ps_len + 1 + i] = m.data[i];
    std::array<std::uint8_t, DB_LEN> dbMask{};
    mgf1(seed, H_LEN, dbMask.data(), DB_LEN);
    std::array<std::uint8_t, DB_LEN> maskedDB{};
    for (std::size_t i = 0; i < DB_LEN; ++i) maskedDB[i] = static_cast<std::uint8_t>(db[i] ^ dbMask[i]);
    std::uint8_t seedMask[H_LEN];
    mgf1(maskedDB.data(), DB_LEN, seedMask, H_LEN);
    EncodedBlock em{};
    em.data[0] = 0x00;
    for (std::size_t i = 0; i < H_LEN; ++i) em.data[1+i] = static_cast<std::uint8_t>(seed[i] ^ seedMask[i]);
    for (std::size_t i = 0; i < DB_LEN; ++i) em.data[1+H_LEN+i] = maskedDB[i];
    return em;
}

DecodeResult oaep_decode(const EncodedBlock& em) {
    DecodeResult res{};
    const std::uint8_t* maskedSeed = em.data.data() + 1;
    const std::uint8_t* maskedDB = em.data.data() + 1 + H_LEN;
    std::uint8_t seedMask[H_LEN];
    mgf1(maskedDB, DB_LEN, seedMask, H_LEN);
    std::array<std::uint8_t, H_LEN> seed{};
    for (std::size_t i = 0; i < H_LEN; ++i) seed[i] = static_cast<std::uint8_t>(maskedSeed[i] ^ seedMask[i]);
    std::array<std::uint8_t, DB_LEN> dbMask{};
    mgf1(seed.data(), H_LEN, dbMask.data(), DB_LEN);
    std::array<std::uint8_t, DB_LEN> db{};
    for (std::size_t i = 0; i < DB_LEN; ++i) db[i] = static_cast<std::uint8_t>(maskedDB[i] ^ dbMask[i]);

    std::uint8_t bad = ct_neq0(em.data[0]);
    std::uint8_t lHash[H_LEN];
    lhash_empty(lHash);
    for (std::size_t i = 0; i < H_LEN; ++i) bad = static_cast<std::uint8_t>(bad | static_cast<std::uint8_t>(db[i] ^ lHash[i]));

    std::uint8_t found = 0;
    std::uint16_t idx = 0;
    for (std::size_t i = H_LEN; i < DB_LEN; ++i) {
        const std::uint8_t is_one = ct_eq(db[i], 0x01);
        const std::uint8_t take = static_cast<std::uint8_t>(is_one & static_cast<std::uint8_t>(found ^ 1));
        const std::uint16_t tmask = static_cast<std::uint16_t>(0u - take);
        idx = static_cast<std::uint16_t>((static_cast<std::uint16_t>(i) & tmask) | (idx & ~tmask));
        found = static_cast<std::uint8_t>(found | is_one);
    }
    bad = static_cast<std::uint8_t>(bad | static_cast<std::uint8_t>(found ^ 1));

    const std::size_t start = static_cast<std::size_t>(idx) + 1;
    for (std::size_t j = 0; j < MAX_MSG; ++j) {
        const std::int64_t src = static_cast<std::int64_t>(start) + static_cast<std::int64_t>(j);
        const std::int64_t diff = static_cast<std::int64_t>(DB_LEN) - 1 - src;
        const std::uint8_t in_range = static_cast<std::uint8_t>((diff >> 63) ^ 1);
        const std::uint64_t m64 = 0ULL - static_cast<std::uint64_t>(in_range);
        const std::size_t s2 = static_cast<std::size_t>(
            (static_cast<std::uint64_t>(src) & m64) | (static_cast<std::uint64_t>(DB_LEN-1) & ~m64));
        res.msg.data[j] = static_cast<std::uint8_t>(db[s2] & ct_mask(in_range));
    }
    res.msg.len = (DB_LEN - start) * static_cast<std::size_t>(found);
    res.ok = (bad == 0);
    return res;
}

}
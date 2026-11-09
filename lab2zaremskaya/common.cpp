#include "common.hpp"

#include <cstring>

namespace rsa {


BigInt::BigInt() : n_(BN_new()) {
    if (!n_) {
        throw BnError("BN_new failed");
    }
}

BigInt::BigInt(const BigInt& other) : n_(BN_dup(other.n_)) {
    if (!n_) {
        throw BnError("BN_dup failed");
    }
}

BigInt::BigInt(BigInt&& other) noexcept : n_(other.n_) {
    other.n_ = nullptr;
}

BigInt::BigInt(unsigned long v) : BigInt() {
    if (BN_set_word(n_, v) != 1) {
        throw BnError("BN_set_word failed");
    }
}

BigInt::~BigInt() {
    BN_free(n_);
}

BigInt& BigInt::operator=(const BigInt& other) {
    if (this != &other) {
        if (BN_copy(n_, other.n_) == nullptr) {
            throw BnError("BN_copy failed");
        }
    }
    return *this;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept {
    if (this != &other) {
        BN_free(n_);
        n_ = other.n_;
        other.n_ = nullptr;
    }
    return *this;
}

BN_CTX* BigInt::ctx() {
    thread_local BN_CTX* c = BN_CTX_new();
    if (!c) {
        throw BnError("BN_CTX_new failed");
    }
    return c;
}

BigInt BigInt::from_dec(const char* s) {
    BigInt r;
    if (BN_dec2bn(&r.n_, s) == 0) {
        throw BnError("BN_dec2bn failed");
    }
    return r;
}

BigInt BigInt::from_hex(const char* s) {
    BigInt r;
    if (BN_hex2bn(&r.n_, s) == 0) {
        throw BnError("BN_hex2bn failed");
    }
    return r;
}

BigInt BigInt::from_bytes_be(const uint8_t* p, std::size_t n) {
    BigInt r;
    if (BN_bin2bn(p, static_cast<int>(n), r.n_) == nullptr) {
        throw BnError("BN_bin2bn failed");
    }
    return r;
}

BigInt BigInt::random_bits(int bits, bool top_odd) {
    BigInt r;
    int top = 1;  // старший бит = 1, точная битовая длина
    int bottom = top_odd ? 1 : 0;
    if (BN_rand(r.n_, bits, top, bottom) != 1) {
        throw BnError("BN_rand failed");
    }
    return r;
}

std::string BigInt::to_dec() const {
    char* s = BN_bn2dec(n_);
    if (!s) {
        throw BnError("BN_bn2dec failed");
    }
    std::string out(s);
    OPENSSL_free(s);
    return out;
}

std::string BigInt::to_hex() const {
    char* s = BN_bn2hex(n_);
    if (!s) {
        throw BnError("BN_bn2hex failed");
    }
    std::string out(s);
    OPENSSL_free(s);
    return out;
}

std::vector<uint8_t> BigInt::to_bytes_be(std::size_t width) const {
    std::vector<uint8_t> out(width, 0);
    to_bytes_be(out.data(), width);
    return out;
}

void BigInt::to_bytes_be(uint8_t* out, std::size_t width) const {
    std::memset(out, 0, width);
    int n = BN_num_bytes(n_);
    if (n < 0 || static_cast<std::size_t>(n) > width) {
        throw BnError("integer too large for I2OSP width");
    }
    BN_bn2bin(n_, out + (width - static_cast<std::size_t>(n)));
}

int BigInt::bit_length() const {
    return BN_num_bits(n_);
}

int BigInt::byte_length() const {
    return BN_num_bytes(n_);
}

bool BigInt::is_zero() const {
    return BN_is_zero(n_) == 1;
}

bool BigInt::is_odd() const {
    return BN_is_odd(n_) == 1;
}

bool BigInt::bit_set(int i) const {
    return BN_is_bit_set(n_, i) == 1;
}

int BigInt::cmp(const BigInt& o) const {
    return BN_cmp(n_, o.n_);
}

BigInt BigInt::add(const BigInt& o) const {
    BigInt r;
    if (BN_add(r.n_, n_, o.n_) != 1) {
        throw BnError("BN_add failed");
    }
    return r;
}

BigInt BigInt::sub(const BigInt& o) const {
    BigInt r;
    if (BN_sub(r.n_, n_, o.n_) != 1) {
        throw BnError("BN_sub failed");
    }
    return r;
}

BigInt BigInt::mul(const BigInt& o) const {
    BigInt r;
    if (BN_mul(r.n_, n_, o.n_, ctx()) != 1) {
        throw BnError("BN_mul failed");
    }
    return r;
}

BigInt BigInt::div(const BigInt& o) const {
    BigInt r;
    if (BN_div(r.n_, nullptr, n_, o.n_, ctx()) != 1) {
        throw BnError("BN_div failed");
    }
    return r;
}

BigInt BigInt::mod(const BigInt& m) const {
    BigInt r;
    if (BN_nnmod(r.n_, n_, m.n_, ctx()) != 1) {
        throw BnError("BN_nnmod failed");
    }
    return r;
}

BigInt BigInt::mod_add(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_add(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_add failed");
    }
    return r;
}

BigInt BigInt::mod_sub(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_sub(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_sub failed");
    }
    return r;
}

BigInt BigInt::mod_mul(const BigInt& o, const BigInt& m) const {
    BigInt r;
    if (BN_mod_mul(r.n_, n_, o.n_, m.n_, ctx()) != 1) {
        throw BnError("BN_mod_mul failed");
    }
    return r;
}


namespace {

using WORD = uint64_t;

#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (64 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 28) ^ ROTRIGHT(x, 34) ^ ROTRIGHT(x, 39))
#define EP1(x) (ROTRIGHT(x, 14) ^ ROTRIGHT(x, 18) ^ ROTRIGHT(x, 41))
#define SIG0(x) (ROTRIGHT(x, 1) ^ ROTRIGHT(x, 8) ^ ((x) >> 7))
#define SIG1(x) (ROTRIGHT(x, 19) ^ ROTRIGHT(x, 61) ^ ((x) >> 6))

struct SHA512_CTX {
    uint8_t data[128];
    unsigned datalen;
    uint64_t bitlen;
    WORD state[8];
};

static const WORD k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

void sha512_transform(SHA512_CTX* ctx, const uint8_t data[]) {
    WORD a, b, c, d, e, f, g, h, t1, t2, m[80];
    unsigned i;

    for (i = 0; i < 16; ++i) {
        m[i] = (static_cast<WORD>(data[i * 8]) << 56) | (static_cast<WORD>(data[i * 8 + 1]) << 48) |
               (static_cast<WORD>(data[i * 8 + 2]) << 40) | (static_cast<WORD>(data[i * 8 + 3]) << 32) |
               (static_cast<WORD>(data[i * 8 + 4]) << 24) | (static_cast<WORD>(data[i * 8 + 5]) << 16) |
               (static_cast<WORD>(data[i * 8 + 6]) << 8) | (static_cast<WORD>(data[i * 8 + 7]));
    }
    for (; i < 80; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 80; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha512_init(SHA512_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
}

void sha512_update(SHA512_CTX* ctx, const uint8_t data[], std::size_t len) {
    for (std::size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 128) {
            sha512_transform(ctx, ctx->data);
            ctx->bitlen += 1024;
            ctx->datalen = 0;
        }
    }
}

void sha512_final(SHA512_CTX* ctx, uint8_t hash[]) {
    unsigned i = ctx->datalen;

    if (ctx->datalen < 112) {
        ctx->data[i++] = 0x80;
        while (i < 112) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 128) {
            ctx->data[i++] = 0x00;
        }
        sha512_transform(ctx, ctx->data);
        std::memset(ctx->data, 0, 112);
    }

    ctx->bitlen += static_cast<uint64_t>(ctx->datalen) * 8;
    std::memset(ctx->data + 112, 0, 8);
    ctx->data[127] = static_cast<uint8_t>(ctx->bitlen);
    ctx->data[126] = static_cast<uint8_t>(ctx->bitlen >> 8);
    ctx->data[125] = static_cast<uint8_t>(ctx->bitlen >> 16);
    ctx->data[124] = static_cast<uint8_t>(ctx->bitlen >> 24);
    ctx->data[123] = static_cast<uint8_t>(ctx->bitlen >> 32);
    ctx->data[122] = static_cast<uint8_t>(ctx->bitlen >> 40);
    ctx->data[121] = static_cast<uint8_t>(ctx->bitlen >> 48);
    ctx->data[120] = static_cast<uint8_t>(ctx->bitlen >> 56);
    sha512_transform(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        hash[i] = (ctx->state[0] >> (56 - i * 8)) & 0xff;
        hash[i + 8] = (ctx->state[1] >> (56 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[2] >> (56 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[3] >> (56 - i * 8)) & 0xff;
        hash[i + 32] = (ctx->state[4] >> (56 - i * 8)) & 0xff;
        hash[i + 40] = (ctx->state[5] >> (56 - i * 8)) & 0xff;
        hash[i + 48] = (ctx->state[6] >> (56 - i * 8)) & 0xff;
        hash[i + 56] = (ctx->state[7] >> (56 - i * 8)) & 0xff;
    }
}

#undef ROTRIGHT
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

}  

void sha512(const uint8_t* data, std::size_t len, uint8_t out[kSha512Len]) {
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, out);
}

bool sha512_selftest() {
    uint8_t h[kSha512Len];
    sha512(reinterpret_cast<const uint8_t*>(""), 0, h);
    const uint8_t empty[kSha512Len] = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
    if (std::memcmp(h, empty, kSha512Len) != 0) {
        return false;
    }
    const char* abc = "abc";
    sha512(reinterpret_cast<const uint8_t*>(abc), 3, h);
    const uint8_t abc_ref[kSha512Len] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
    return std::memcmp(h, abc_ref, kSha512Len) == 0;
}

}  // namespace rsa
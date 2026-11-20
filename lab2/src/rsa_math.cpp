#include "rsa_math.hpp"

#include <openssl/crypto.h>

#include <cstdio>
#include <cstdlib>

namespace {

uint32_t ct_is_zero_u8(uint8_t x) {
    uint32_t v = x;
    v |= v >> 4;
    v |= v >> 2;
    v |= v >> 1;
    return (v & 1u) ^ 1u;
}

uint32_t ct_lt_u32(uint32_t a, uint32_t b) {
    return static_cast<uint32_t>((static_cast<uint64_t>(a) - static_cast<uint64_t>(b)) >> 63);
}

// Сравнение двух вычетов одной длины. Аккумулятор XOR, без раннего выхода.
uint32_t ct_bn_eq(const BIGNUM* a, const BIGNUM* b, int len) {
    uint8_t ba[512];
    uint8_t bb[512];
    if (len <= 0 || len > static_cast<int>(sizeof(ba))) {
        return 0;
    }
    if (BN_bn2binpad(a, ba, len) != len || BN_bn2binpad(b, bb, len) != len) {
        return 0;
    }
    uint8_t acc = 0;
    for (int i = 0; i < len; ++i) {
        acc = static_cast<uint8_t>(acc | (ba[i] ^ bb[i]));
    }
    return ct_is_zero_u8(acc);
}

bool mod_exp_plain(BIGNUM* out, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* result = BN_CTX_get(ctx);
    BIGNUM* b = BN_CTX_get(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    bool ok = result != nullptr && b != nullptr && tmp != nullptr;
    ok = ok && BN_one(result) == 1;
    ok = ok && BN_nnmod(b, base, mod, ctx) == 1;
    if (ok && !BN_is_negative(exp)) {
        const int bits = BN_num_bits(exp);
        for (int i = bits - 1; i >= 0 && ok; --i) {
            ok = BN_mod_mul(tmp, result, result, mod, ctx) == 1;
            ok = ok && BN_copy(result, tmp) != nullptr;
            if (ok && BN_is_bit_set(exp, i)) {
                ok = BN_mod_mul(tmp, result, b, mod, ctx) == 1;
                ok = ok && BN_copy(result, tmp) != nullptr;
            }
        }
    }
    ok = ok && BN_copy(out, result) != nullptr;
    BN_CTX_end(ctx);
    return ok;
}

// Бинарное возведение в степень в форме Монтгомери (модуль обязан быть нечётным).
bool mod_exp_mont(BIGNUM* out, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* result = BN_CTX_get(ctx);
    BIGNUM* b = BN_CTX_get(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    bool ok = result != nullptr && b != nullptr && tmp != nullptr && mont != nullptr;
    ok = ok && BN_MONT_CTX_set(mont, mod, ctx) == 1;
    ok = ok && BN_one(result) == 1;
    ok = ok && BN_to_montgomery(result, result, mont, ctx) == 1;
    ok = ok && BN_nnmod(b, base, mod, ctx) == 1;
    ok = ok && BN_to_montgomery(b, b, mont, ctx) == 1;
    if (ok && !BN_is_negative(exp)) {
        const int bits = BN_num_bits(exp);
        for (int i = bits - 1; i >= 0 && ok; --i) {
            ok = BN_mod_mul_montgomery(tmp, result, result, mont, ctx) == 1;
            ok = ok && BN_copy(result, tmp) != nullptr;
            if (ok && BN_is_bit_set(exp, i)) {
                ok = BN_mod_mul_montgomery(tmp, result, b, mont, ctx) == 1;
                ok = ok && BN_copy(result, tmp) != nullptr;
            }
        }
    }
    ok = ok && BN_from_montgomery(out, result, mont, ctx) == 1;
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    return ok;
}

// Экспонента для теста простоты: на каждом бите модуля всегда одно возведение
// в квадрат и одно умножение. Бит показателя выбирает результат маской,
// длина цикла равна битовой длине модуля и не зависит от веса Хэмминга d.
bool mod_exp_mont_ct(BIGNUM* out, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    const int width = BN_num_bits(mod);
    const int nwords = (width + BN_BITS2 - 1) / BN_BITS2;
    const int len = nwords * static_cast<int>(sizeof(BN_ULONG));
    if (width <= 0 || len <= 0 || len > 512) {
        return false;
    }

    BN_CTX_start(ctx);
    BIGNUM* result = BN_CTX_get(ctx);
    BIGNUM* b = BN_CTX_get(ctx);
    BIGNUM* sq = BN_CTX_get(ctx);
    BIGNUM* prod = BN_CTX_get(ctx);
    BN_MONT_CTX* mont = BN_MONT_CTX_new();
    bool ok = result != nullptr && b != nullptr && sq != nullptr && prod != nullptr && mont != nullptr;
    ok = ok && BN_MONT_CTX_set(mont, mod, ctx) == 1;
    ok = ok && BN_one(result) == 1;
    ok = ok && BN_to_montgomery(result, result, mont, ctx) == 1;
    ok = ok && BN_nnmod(b, base, mod, ctx) == 1;
    ok = ok && BN_to_montgomery(b, b, mont, ctx) == 1;

    uint8_t sb[512];
    uint8_t pb[512];
    uint8_t ob[512];
    for (int i = width - 1; ok && i >= 0; --i) {
        ok = BN_mod_mul_montgomery(sq, result, result, mont, ctx) == 1;
        ok = ok && BN_mod_mul_montgomery(prod, sq, b, mont, ctx) == 1;
        const uint32_t bit = static_cast<uint32_t>(BN_is_bit_set(exp, i));
        ok = ok && BN_bn2binpad(sq, sb, len) == len;
        ok = ok && BN_bn2binpad(prod, pb, len) == len;
        const uint8_t mask = static_cast<uint8_t>(0u - bit);
        for (int j = 0; j < len; ++j) {
            ob[j] = static_cast<uint8_t>(sb[j] ^ (mask & static_cast<uint8_t>(sb[j] ^ pb[j])));
        }
        ok = ok && BN_bin2bn(ob, len, result) != nullptr;
    }
    ok = ok && BN_from_montgomery(out, result, mont, ctx) == 1;
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    return ok;
}

bool mod_exp_ctx(BIGNUM* out, const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    if (BN_is_zero(mod) || BN_is_negative(mod)) {
        return false;
    }
    if (BN_is_odd(mod)) {
        return mod_exp_mont(out, base, exp, mod, ctx);
    }
    return mod_exp_plain(out, base, exp, mod, ctx);
}

bool mod_sqr(BIGNUM* x, const BIGNUM* mod, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    const bool ok = tmp != nullptr && BN_mod_mul(tmp, x, x, mod, ctx) == 1 && BN_copy(x, tmp) != nullptr;
    BN_CTX_end(ctx);
    return ok;
}

// (x + 2n)^2 ≡ x^2 (mod n), но оба множителя не меньше 2n.
// Иначе после x ≡ ±1 библиотечное умножение переходит на короткие числа
// и время квадратов начинает зависеть от того, простое число или нет.
bool mod_sqr_full(BIGNUM* x, const BIGNUM* mod, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* two_n = BN_CTX_get(ctx);
    BIGNUM* wide = BN_CTX_get(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    bool ok = two_n != nullptr && wide != nullptr && tmp != nullptr;
    ok = ok && BN_lshift1(two_n, mod) == 1;
    ok = ok && BN_add(wide, x, two_n) == 1;
    ok = ok && BN_mod_mul(tmp, wide, wide, mod, ctx) == 1;
    ok = ok && BN_copy(x, tmp) != nullptr;
    BN_CTX_end(ctx);
    return ok;
}

bool extended_gcd_raw(BIGNUM* gcd, BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* r0 = BN_CTX_get(ctx);
    BIGNUM* r1 = BN_CTX_get(ctx);
    BIGNUM* s0 = BN_CTX_get(ctx);
    BIGNUM* s1 = BN_CTX_get(ctx);
    BIGNUM* t0 = BN_CTX_get(ctx);
    BIGNUM* t1 = BN_CTX_get(ctx);
    BIGNUM* q = BN_CTX_get(ctx);
    BIGNUM* rem = BN_CTX_get(ctx);
    BIGNUM* tmp = BN_CTX_get(ctx);
    bool ok = r0 && r1 && s0 && s1 && t0 && t1 && q && rem && tmp;
    ok = ok && BN_copy(r0, a) != nullptr && BN_copy(r1, b) != nullptr;
    ok = ok && BN_one(s0) == 1;
    if (ok) {
        BN_zero(s1);
        BN_zero(t0);
    }
    ok = ok && BN_one(t1) == 1;

    while (ok && !BN_is_zero(r1)) {
        ok = BN_div(q, rem, r0, r1, ctx) == 1;
        ok = ok && BN_copy(r0, r1) != nullptr && BN_copy(r1, rem) != nullptr;

        ok = ok && BN_mul(tmp, q, s1, ctx) == 1;
        ok = ok && BN_sub(tmp, s0, tmp) == 1;
        ok = ok && BN_copy(s0, s1) != nullptr && BN_copy(s1, tmp) != nullptr;

        ok = ok && BN_mul(tmp, q, t1, ctx) == 1;
        ok = ok && BN_sub(tmp, t0, tmp) == 1;
        ok = ok && BN_copy(t0, t1) != nullptr && BN_copy(t1, tmp) != nullptr;
    }

    ok = ok && BN_copy(gcd, r0) != nullptr;
    ok = ok && BN_copy(x, s0) != nullptr;
    ok = ok && BN_copy(y, t0) != nullptr;
    BN_CTX_end(ctx);
    return ok;
}

bool mod_inverse_ctx(BIGNUM* out, const BIGNUM* a, const BIGNUM* mod, BN_CTX* ctx) {
    if (BN_is_zero(mod) || BN_is_negative(mod)) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* aa = BN_CTX_get(ctx);
    BIGNUM* g = BN_CTX_get(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* y = BN_CTX_get(ctx);
    bool ok = aa && g && x && y;
    ok = ok && BN_nnmod(aa, a, mod, ctx) == 1;
    ok = ok && extended_gcd_raw(g, x, y, aa, mod, ctx);
    ok = ok && BN_is_one(g);
    ok = ok && BN_nnmod(out, x, mod, ctx) == 1;
    BN_CTX_end(ctx);
    return ok;
}

// n-1 = 2^s * d, d нечётно. Число шагов фиксировано шириной n, а не значением s.
bool split_even(const BIGNUM* n, uint32_t* s_out, BIGNUM* d, BIGNUM* n1) {
    if (BN_copy(n1, n) == nullptr || BN_sub_word(n1, 1) != 1) {
        return false;
    }
    const int width = BN_num_bits(n);
    uint32_t s = 0;
    uint32_t still = 1;
    for (int i = 0; i < width; ++i) {
        const uint32_t bit = static_cast<uint32_t>(BN_is_bit_set(n1, i));
        s += still & (1u - bit);
        still &= (1u - bit);
    }
    if (s == 0 || BN_rshift(d, n1, static_cast<int>(s)) == 0) {
        return false;
    }
    *s_out = s;
    return true;
}

uint32_t witness_ct(const BIGNUM* n, const BIGNUM* n1, const BIGNUM* d, uint32_t s, const BIGNUM* base,
                    int nbytes, BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    BIGNUM* one = BN_CTX_get(ctx);
    if (x == nullptr || one == nullptr || BN_one(one) != 1 || !mod_exp_mont_ct(x, base, d, n, ctx)) {
        BN_CTX_end(ctx);
        return 0;
    }

    // a^d ≡ ±1 (mod n) — условие для r = 0. Дальше квадраты без break.
    uint32_t ok = ct_bn_eq(x, one, nbytes) | ct_bn_eq(x, n1, nbytes);
    bool arithmetic = true;
    for (int r = 1; r <= RsaMath::kFixedSquarings; ++r) {
        if (!mod_sqr_full(x, n, ctx)) {
            arithmetic = false;
        }
        const uint32_t active = ct_lt_u32(static_cast<uint32_t>(r), s);
        ok |= active & ct_bn_eq(x, n1, nbytes);
    }
    // s > 128 практически не встречается. Хвост нужен только для полноты проверки.
    if (s > static_cast<uint32_t>(RsaMath::kFixedSquarings)) {
        for (uint32_t r = static_cast<uint32_t>(RsaMath::kFixedSquarings) + 1; r < s; ++r) {
            if (!mod_sqr_full(x, n, ctx)) {
                arithmetic = false;
            }
            ok |= ct_bn_eq(x, n1, nbytes);
        }
    }
    BN_CTX_end(ctx);
    if (!arithmetic) {
        return 0;
    }
    return ok;
}

bool witness_vt(const BIGNUM* n, const BIGNUM* n1, const BIGNUM* d, uint32_t s, const BIGNUM* base,
                BN_CTX* ctx) {
    BN_CTX_start(ctx);
    BIGNUM* x = BN_CTX_get(ctx);
    if (x == nullptr || !mod_exp_ctx(x, base, d, n, ctx)) {
        BN_CTX_end(ctx);
        return false;
    }
    if (BN_is_one(x) || BN_cmp(x, n1) == 0) {
        BN_CTX_end(ctx);
        return true;
    }
    bool found = false;
    for (uint32_t r = 1; r < s; ++r) {
        if (!mod_sqr(x, n, ctx)) {
            BN_CTX_end(ctx);
            return false;
        }
        if (BN_cmp(x, n1) == 0) {
            found = true;
            break;
        }
        if (BN_is_one(x)) {
            BN_CTX_end(ctx);
            return false;
        }
    }
    BN_CTX_end(ctx);
    return found;
}

enum class PrimeClass { kPrime, kComposite, kContinue };

PrimeClass classify_small(const BIGNUM* n) {
    if (BN_is_negative(n) || BN_is_zero(n) || BN_is_one(n)) {
        return PrimeClass::kComposite;
    }
    if (BN_is_word(n, 2) || BN_is_word(n, 3)) {
        return PrimeClass::kPrime;
    }
    if (!BN_is_odd(n)) {
        return PrimeClass::kComposite;
    }
    return PrimeClass::kContinue;
}

const uint32_t* small_primes(int* count) {
    static uint32_t primes[1300];
    static int n = 0;
    if (n == 0) {
        static constexpr int kLimit = 10000;
        bool composite[kLimit] = {};
        for (int i = 2; i * i < kLimit; ++i) {
            if (!composite[i]) {
                for (int j = i * i; j < kLimit; j += i) {
                    composite[j] = true;
                }
            }
        }
        for (int i = 2; i < kLimit && n < static_cast<int>(sizeof(primes) / sizeof(primes[0])); ++i) {
            if (!composite[i]) {
                primes[n++] = static_cast<uint32_t>(i);
            }
        }
    }
    *count = n;
    return primes;
}

bool difference_large(const BIGNUM* p, const BIGNUM* q, int prime_bits, BN_CTX* ctx) {
    int shift = prime_bits - 100;
    if (shift < 2) {
        shift = 2;
    }
    BN_CTX_start(ctx);
    BIGNUM* diff = BN_CTX_get(ctx);
    BIGNUM* bound = BN_CTX_get(ctx);
    bool ok = diff != nullptr && bound != nullptr;
    ok = ok && BN_sub(diff, p, q) == 1;
    if (ok && BN_is_negative(diff)) {
        BN_set_negative(diff, 0);
    }
    ok = ok && BN_one(bound) == 1;
    ok = ok && BN_lshift(bound, bound, shift) == 1;
    const bool large = ok && BN_cmp(diff, bound) > 0;
    BN_CTX_end(ctx);
    return large;
}

}

Bn::Bn() : v_(BN_new()) {
    if (v_ == nullptr) {
        std::abort();
    }
}

Bn::~Bn() { BN_clear_free(v_); }

Bn::Bn(const Bn& other) : v_(BN_dup(other.v_)) {
    if (v_ == nullptr) {
        std::abort();
    }
}

Bn& Bn::operator=(const Bn& other) {
    if (this != &other && BN_copy(v_, other.v_) == nullptr) {
        std::abort();
    }
    return *this;
}

Bn::Bn(Bn&& other) noexcept : v_(other.v_) {
    other.v_ = BN_new();
    if (other.v_ == nullptr) {
        std::abort();
    }
}

Bn& Bn::operator=(Bn&& other) noexcept {
    if (this != &other) {
        BN_clear_free(v_);
        v_ = other.v_;
        other.v_ = BN_new();
        if (other.v_ == nullptr) {
            std::abort();
        }
    }
    return *this;
}

bool RsaMath::mod_exp(Bn& out, const Bn& base, const Bn& exp, const Bn& mod) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    const bool ok = mod_exp_ctx(out.raw(), base.raw(), exp.raw(), mod.raw(), ctx);
    BN_CTX_free(ctx);
    return ok;
}

bool RsaMath::mod_inverse(Bn& out, const Bn& a, const Bn& mod) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    const bool ok = mod_inverse_ctx(out.raw(), a.raw(), mod.raw(), ctx);
    BN_CTX_free(ctx);
    return ok;
}

bool RsaMath::extended_gcd(Bn& gcd, Bn& x, Bn& y, const Bn& a, const Bn& b) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    const bool ok = extended_gcd_raw(gcd.raw(), x.raw(), y.raw(), a.raw(), b.raw(), ctx);
    BN_CTX_free(ctx);
    return ok;
}

bool RsaMath::miller_rabin_ct(const Bn& n, const Bn* bases, int n_bases) {
    const PrimeClass small = classify_small(n.raw());
    if (small == PrimeClass::kPrime) {
        return true;
    }
    if (small == PrimeClass::kComposite || n_bases <= 0 || bases == nullptr) {
        return false;
    }

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* n1 = BN_CTX_get(ctx);
    BIGNUM* d = BN_CTX_get(ctx);
    uint32_t s = 0;
    bool ok = n1 != nullptr && d != nullptr && split_even(n.raw(), &s, d, n1);
    const int nbytes = BN_num_bytes(n.raw());
    uint32_t all_ok = 1;
    for (int i = 0; ok && i < n_bases; ++i) {
        // Свидетель, который уже доказал составность, цикл не прерывает.
        const uint32_t passed = witness_ct(n.raw(), n1, d, s, bases[i].raw(), nbytes, ctx);
        all_ok &= passed;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok && all_ok == 1u;
}

bool RsaMath::miller_rabin_vt(const Bn& n, const Bn* bases, int n_bases) {
    const PrimeClass small = classify_small(n.raw());
    if (small == PrimeClass::kPrime) {
        return true;
    }
    if (small == PrimeClass::kComposite || n_bases <= 0 || bases == nullptr) {
        return false;
    }

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* n1 = BN_CTX_get(ctx);
    BIGNUM* d = BN_CTX_get(ctx);
    uint32_t s = 0;
    bool ok = n1 != nullptr && d != nullptr && split_even(n.raw(), &s, d, n1);
    bool prime = ok;
    for (int i = 0; prime && i < n_bases; ++i) {
        if (!witness_vt(n.raw(), n1, d, s, bases[i].raw(), ctx)) {
            prime = false;
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return prime;
}

bool RsaMath::random_bases(Bn* bases, int n_bases, const Bn& n) {
    if (bases == nullptr || n_bases <= 0) {
        return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* limit = BN_CTX_get(ctx);
    bool ok = limit != nullptr && BN_copy(limit, n.raw()) != nullptr && BN_sub_word(limit, 3) == 1;
    // [0, n-4] + 2 = [2, n-2]
    for (int i = 0; ok && i < n_bases; ++i) {
        ok = BN_rand_range(bases[i].raw(), limit) == 1 && BN_add_word(bases[i].raw(), 2) == 1;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

bool RsaMath::miller_rabin_ct_random(const Bn& n, int rounds) {
    if (rounds <= 0 || rounds > 32) {
        return false;
    }
    Bn bases[32];
    if (!random_bases(bases, rounds, n)) {
        return false;
    }
    return miller_rabin_ct(n, bases, rounds);
}

bool RsaMath::generate_prime(Bn& prime, int bits, unsigned long exponent) {
    if (bits < 16 || exponent < 3) {
        return false;
    }
    int nprimes = 0;
    const uint32_t* primes = small_primes(&nprimes);
    int mr_done = 0;
    for (int attempt = 0; attempt < 200000; ++attempt) {
        if (BN_rand(prime.raw(), bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD) != 1) {
            return false;
        }
        bool smooth = false;
        for (int i = 0; i < nprimes; ++i) {
            const BN_ULONG rem = BN_mod_word(prime.raw(), primes[i]);
            if (rem == static_cast<BN_ULONG>(-1)) {
                return false;
            }
            if (rem == 0) {
                smooth = true;
                break;
            }
        }
        if (smooth) {
            continue;
        }
        const BN_ULONG rem_e = BN_mod_word(prime.raw(), exponent);
        if (rem_e == static_cast<BN_ULONG>(-1)) {
            return false;
        }
        if (rem_e == 1) {
            continue;
        }
        ++mr_done;
        std::fprintf(stderr, "  тест Миллера–Рабина #%d, %d бит\n", mr_done, bits);
        std::fflush(stderr);
        if (miller_rabin_ct_random(prime, kMrRounds)) {
            std::fprintf(stderr, "  простое найдено (%d бит) после %d тестов MR\n", bits, mr_done);
            std::fflush(stderr);
            return true;
        }
    }
    return false;
}

bool RsaMath::derive_private(RsaPrivateKey& key) {
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* p1 = BN_CTX_get(ctx);
    BIGNUM* q1 = BN_CTX_get(ctx);
    BIGNUM* g = BN_CTX_get(ctx);
    BIGNUM* gx = BN_CTX_get(ctx);
    BIGNUM* gy = BN_CTX_get(ctx);
    BIGNUM* quot = BN_CTX_get(ctx);
    BIGNUM* lambda = BN_CTX_get(ctx);
    bool ok = p1 && q1 && g && gx && gy && quot && lambda;
    ok = ok && BN_copy(p1, key.p.raw()) != nullptr && BN_sub_word(p1, 1) == 1;
    ok = ok && BN_copy(q1, key.q.raw()) != nullptr && BN_sub_word(q1, 1) == 1;
    ok = ok && BN_mul(key.n.raw(), key.p.raw(), key.q.raw(), ctx) == 1;
    ok = ok && extended_gcd_raw(g, gx, gy, p1, q1, ctx);
    ok = ok && !BN_is_zero(g);
    ok = ok && BN_div(quot, nullptr, p1, g, ctx) == 1;
    ok = ok && BN_mul(lambda, quot, q1, ctx) == 1;

    Bn lam;
    Bn p1bn;
    Bn q1bn;
    if (ok) {
        ok = BN_copy(lam.raw(), lambda) != nullptr;
        ok = ok && BN_copy(p1bn.raw(), p1) != nullptr;
        ok = ok && BN_copy(q1bn.raw(), q1) != nullptr;
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (!ok) {
        return false;
    }
    if (!mod_inverse(key.d, key.e, lam)) {
        return false;
    }
    BN_CTX* ctx2 = BN_CTX_new();
    if (ctx2 == nullptr) {
        return false;
    }
    ok = BN_nnmod(key.dp.raw(), key.d.raw(), p1bn.raw(), ctx2) == 1;
    ok = ok && BN_nnmod(key.dq.raw(), key.d.raw(), q1bn.raw(), ctx2) == 1;
    BN_CTX_free(ctx2);
    if (!ok || !mod_inverse(key.qinv, key.q, key.p)) {
        return false;
    }
    return true;
}

bool RsaMath::generate_keypair(RsaPrivateKey& key, int modulus_bits) {
    if (modulus_bits < 32 || (modulus_bits % 2) != 0) {
        return false;
    }
    const int prime_bits = modulus_bits / 2;
    if (!from_word(key.e, kPublicExponent)) {
        return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    for (int attempt = 1; attempt <= 32; ++attempt) {
        std::fprintf(stderr, "генерация пары простых, попытка %d (модуль %d бит)\n", attempt, modulus_bits);
        std::fflush(stderr);
        if (!generate_prime(key.p, prime_bits, kPublicExponent) ||
            !generate_prime(key.q, prime_bits, kPublicExponent)) {
            BN_CTX_free(ctx);
            return false;
        }
        if (BN_cmp(key.p.raw(), key.q.raw()) == 0) {
            continue;
        }
        if (!difference_large(key.p.raw(), key.q.raw(), prime_bits, ctx)) {
            std::fprintf(stderr, "  |p-q| слишком мала, повтор\n");
            continue;
        }
        if (!derive_private(key)) {
            continue;
        }
        int d_shift = prime_bits;
        Bn bound;
        if (BN_one(bound.raw()) != 1 || BN_lshift(bound.raw(), bound.raw(), d_shift) != 1) {
            BN_CTX_free(ctx);
            return false;
        }
        if (BN_num_bits(key.n.raw()) != modulus_bits || BN_cmp(key.d.raw(), bound.raw()) <= 0) {
            std::fprintf(stderr, "  длина n или d не подошла, повтор\n");
            continue;
        }
        BN_CTX_free(ctx);
        return true;
    }
    BN_CTX_free(ctx);
    return false;
}

std::string RsaMath::hex(const Bn& v) {
    char* s = BN_bn2hex(v.raw());
    if (s == nullptr) {
        return {};
    }
    std::string out(s);
    OPENSSL_free(s);
    return out;
}

bool RsaMath::from_hex(Bn& v, const char* hex) {
    BIGNUM* tmp = nullptr;
    if (BN_hex2bn(&tmp, hex) == 0 || tmp == nullptr) {
        return false;
    }
    const bool ok = BN_copy(v.raw(), tmp) != nullptr;
    BN_free(tmp);
    return ok;
}

bool RsaMath::from_word(Bn& v, unsigned long w) {
    return BN_set_word(v.raw(), static_cast<BN_ULONG>(w)) == 1;
}

bool RsaMath::from_bytes(Bn& v, const uint8_t* in, int len) {
    return in != nullptr && len >= 0 && BN_bin2bn(in, len, v.raw()) != nullptr;
}

bool RsaMath::to_bytes_pad(const Bn& v, uint8_t* out, int len) {
    return out != nullptr && len > 0 && BN_bn2binpad(v.raw(), out, len) == len;
}

int RsaMath::bit_length(const Bn& v) { return BN_num_bits(v.raw()); }

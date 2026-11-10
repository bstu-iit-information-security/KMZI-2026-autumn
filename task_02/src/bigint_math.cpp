#include "bigint_math.hpp"

#include <cstdio>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <random>
#endif

namespace rsa {

// ---------------------------------------------------------------------------
// Случайность
// ---------------------------------------------------------------------------
void random_bytes(uint8_t* buf, size_t n) {
#ifdef _WIN32
    std::random_device rd;
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<uint8_t>(rd());
#else
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("cannot open /dev/urandom");
    size_t got = std::fread(buf, 1, n, f);
    std::fclose(f);
    if (got != n) throw std::runtime_error("short read from /dev/urandom");
#endif
}

mpz_class random_bits(unsigned bits) {
    const size_t nbytes = (bits + 7) / 8;
    std::vector<uint8_t> tmp(nbytes);  // публичные данные при генерации, не секрет-контейнер OAEP
    random_bytes(tmp.data(), nbytes);
    mpz_class r;
    mpz_import(r.get_mpz_t(), nbytes, 1, 1, 1, 0, tmp.data());
    mpz_fdiv_r_2exp(r.get_mpz_t(), r.get_mpz_t(), bits);  // оставить младшие `bits` бит
    return r;
}

// ---------------------------------------------------------------------------
// Расширенный Евклид (итеративный)
//   инвариант:  old_r = a*old_s + b*old_t,   r = a*s + b*t
// ---------------------------------------------------------------------------
void ext_gcd(mpz_class& g, mpz_class& x, mpz_class& y,
             const mpz_class& a, const mpz_class& b) {
    mpz_class old_r = a, r = b;
    mpz_class old_s = 1, s = 0;
    mpz_class old_t = 0, t = 1;
    while (r != 0) {
        mpz_class q = old_r / r;  // усечение к нулю; для неотрицательных = floor
        mpz_class tmp;
        tmp = old_r - q * r; old_r = r; r = tmp;
        tmp = old_s - q * s; old_s = s; s = tmp;
        tmp = old_t - q * t; old_t = t; t = tmp;
    }
    g = old_r;
    x = old_s;
    y = old_t;
}

mpz_class gcd(const mpz_class& a, const mpz_class& b) {
    mpz_class g, x, y;
    ext_gcd(g, x, y, a, b);
    return g;
}

bool mod_inverse(mpz_class& inv, const mpz_class& a, const mpz_class& m) {
    mpz_class am;
    mpz_mod(am.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    mpz_class g, x, y;
    ext_gcd(g, x, y, am, m);
    if (g != 1) return false;
    mpz_mod(inv.get_mpz_t(), x.get_mpz_t(), m.get_mpz_t());  // результат в [0, m)
    return true;
}

// ---------------------------------------------------------------------------
// Joye-Tun: регулярное возведение в степень справа налево.
//
//   Три регистра:  R0 = накопитель результата, R1 = "мусорный" накопитель,
//                  R2 = base^(2^i)  (последовательные квадраты).
//   Для каждого бита d_i экспоненты (от младшего к старшему):
//        R[1-d_i] = R[1-d_i] * R2 mod N
//        R2       = R2 * R2   mod N
//   d_i = 1 -> умножается настоящий накопитель R0, d_i = 0 -> мусорный R1.
//   Значит КАЖДЫЙ бит = ровно одно умножение + одно возведение в квадрат,
//   независимо от значения бита (нет `if (bit)`) -- это защита от SPA.
//   Результат: R0.
//
//   Выбор "какой регистр умножать" делается не ветвлением, а условным обменом
//   R0 <-> R1 по маске (cswap по всем limb'ам фиксированной длины).
// ---------------------------------------------------------------------------
namespace {

// Условный обмен двух mpz по маске (bit = 0 или 1), без ветвлений.
// Предусловие: у обоих выделено >= L limb'ов.
inline void cswap_mpz(mpz_class& A, mpz_class& B, unsigned bit, size_t L) {
    mpz_ptr a = A.get_mpz_t();
    mpz_ptr b = B.get_mpz_t();
    const mp_limb_t mask = static_cast<mp_limb_t>(0) - static_cast<mp_limb_t>(bit);
    for (size_t i = 0; i < L; ++i) {
        mp_limb_t t = (a->_mp_d[i] ^ b->_mp_d[i]) & mask;
        a->_mp_d[i] ^= t;
        b->_mp_d[i] ^= t;
    }
    const int imask = -static_cast<int>(bit);
    int ts = (a->_mp_size ^ b->_mp_size) & imask;
    a->_mp_size ^= ts;
    b->_mp_size ^= ts;
}

inline void ensure_limbs(mpz_class& x, size_t L) {
    if (static_cast<size_t>(x.get_mpz_t()->_mp_alloc) < L)
        mpz_realloc2(x.get_mpz_t(), L * GMP_LIMB_BITS);
}

}  // namespace

void powm_joye_tun(mpz_class& r, const mpz_class& base, const mpz_class& exp,
                   const mpz_class& mod, unsigned exp_bits) {
    const size_t L = mpz_size(mod.get_mpz_t()) + 1;  // limb'ов с запасом

    mpz_class R0 = 1, R1 = 1, R2, tmp;
    ensure_limbs(R0, L);
    ensure_limbs(R1, L);
    ensure_limbs(R2, L);
    mpz_mod(R2.get_mpz_t(), base.get_mpz_t(), mod.get_mpz_t());

    for (unsigned i = 0; i < exp_bits; ++i) {
        const unsigned d = mpz_tstbit(exp.get_mpz_t(), i);  // бит экспоненты (0/1)
        const unsigned nd = d ^ 1u;                         // 1-d

        ensure_limbs(R0, L);
        ensure_limbs(R1, L);
        cswap_mpz(R0, R1, nd, L);                // в слот R0 попал R[1-d]
        mpz_mul(tmp.get_mpz_t(), R0.get_mpz_t(), R2.get_mpz_t());
        mpz_mod(R0.get_mpz_t(), tmp.get_mpz_t(), mod.get_mpz_t());
        ensure_limbs(R0, L);
        ensure_limbs(R1, L);
        cswap_mpz(R0, R1, nd, L);                // вернули на место

        mpz_mul(tmp.get_mpz_t(), R2.get_mpz_t(), R2.get_mpz_t());
        mpz_mod(R2.get_mpz_t(), tmp.get_mpz_t(), mod.get_mpz_t());
    }
    mpz_mod(r.get_mpz_t(), R0.get_mpz_t(), mod.get_mpz_t());
}

// ---------------------------------------------------------------------------
// Миллер-Рабин
// ---------------------------------------------------------------------------
bool miller_rabin(const mpz_class& n, int rounds) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (mpz_even_p(n.get_mpz_t())) return false;

    mpz_class n1 = n - 1, dd = n1;
    unsigned s = 0;
    while (mpz_even_p(dd.get_mpz_t())) { dd >>= 1; ++s; }  // n-1 = 2^s * dd

    const unsigned nbits = static_cast<unsigned>(mpz_sizeinbase(n.get_mpz_t(), 2));
    mpz_class range = n - 3;  // основание a в [2, n-2]

    for (int it = 0; it < rounds; ++it) {
        mpz_class a;
        if (it == 0) a = 2;
        else {
            a = random_bits(nbits + 64);
            mpz_mod(a.get_mpz_t(), a.get_mpz_t(), range.get_mpz_t());
            a += 2;
        }
        mpz_class x;
        powm_joye_tun(x, a, dd, n, nbits);
        if (x == 1 || x == n1) continue;
        bool composite = true;
        for (unsigned j = 1; j < s; ++j) {
            mpz_class sq = x * x;
            mpz_mod(x.get_mpz_t(), sq.get_mpz_t(), n.get_mpz_t());
            if (x == n1) { composite = false; break; }
            if (x == 1) break;
        }
        if (composite) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Генерация простого
// ---------------------------------------------------------------------------
namespace {
const std::vector<unsigned>& small_primes() {
    static const std::vector<unsigned> v = [] {
        std::vector<unsigned> res;
        const unsigned LIM = 2000;
        std::vector<bool> comp(LIM + 1, false);
        for (unsigned i = 2; i <= LIM; ++i) {
            if (comp[i]) continue;
            res.push_back(i);
            for (unsigned j = i * i; j <= LIM; j += i) comp[j] = true;
        }
        return res;
    }();
    return v;
}
}  // namespace

mpz_class gen_prime(unsigned bits, const mpz_class& e) {
    const auto& sp = small_primes();
    for (;;) {
        mpz_class cand = random_bits(bits);
        mpz_setbit(cand.get_mpz_t(), bits - 1);  // ровно `bits` бит
        mpz_setbit(cand.get_mpz_t(), bits - 2);  // чтобы p*q было ровно 2*bits бит
        mpz_setbit(cand.get_mpz_t(), 0);         // нечётное

        std::vector<unsigned> res(sp.size());
        for (size_t i = 0; i < sp.size(); ++i)
            res[i] = static_cast<unsigned>(mpz_fdiv_ui(cand.get_mpz_t(), sp[i]));

        for (unsigned delta = 0; delta < (1u << 20); delta += 2) {
            bool ok = true;
            for (size_t i = 0; i < sp.size(); ++i) {
                if ((res[i] + delta) % sp[i] == 0) { ok = false; break; }
            }
            if (!ok) continue;
            mpz_class p = cand + delta;
            if (mpz_sizeinbase(p.get_mpz_t(), 2) != bits) break;  // вышли за размер
            mpz_class pm1 = p - 1;
            if (gcd(e, pm1) != 1) continue;                      // нужен gcd(e, p-1) = 1
            if (miller_rabin(p, 16)) return p;
        }
    }
}

}  // namespace rsa

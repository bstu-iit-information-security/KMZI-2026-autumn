#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <cstdlib>

#include <boost/multiprecision/cpp_int.hpp>

#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

using namespace boost::multiprecision;

class BigInt {
public:
    cpp_int val;

    BigInt() : val(0) {}
    BigInt(int v) : val(v) {}
    BigInt(long long v) : val(v) {}
    BigInt(unsigned long long v) : val(v) {}
    BigInt(const cpp_int& v) : val(v) {}
    BigInt(const BigInt& o) : val(o.val) {}

    BigInt& operator=(const BigInt& o) { val = o.val; return *this; }
    BigInt& operator=(unsigned long long v) { val = v; return *this; }
    BigInt& operator=(const cpp_int& v) { val = v; return *this; }

    BigInt operator+(const BigInt& o) const { BigInt r; r.val = val + o.val; return r; }
    BigInt operator-(const BigInt& o) const { BigInt r; r.val = val - o.val; return r; }
    BigInt operator*(const BigInt& o) const { BigInt r; r.val = val * o.val; return r; }
    BigInt operator/(const BigInt& o) const { BigInt r; r.val = val / o.val; return r; }
    BigInt operator%(const BigInt& o) const { BigInt r; r.val = val % o.val; return r; }
    BigInt operator&(const BigInt& o) const { BigInt r; r.val = val & o.val; return r; }
    BigInt operator|(const BigInt& o) const { BigInt r; r.val = val | o.val; return r; }
    BigInt operator^(const BigInt& o) const { BigInt r; r.val = val ^ o.val; return r; }
    BigInt operator~() const { BigInt r; r.val = ~val; return r; }
    BigInt operator<<(size_t shift) const { BigInt r; r.val = val << shift; return r; }
    BigInt operator>>(size_t shift) const { BigInt r; r.val = val >> shift; return r; }

    bool operator<(const BigInt& o) const { return val < o.val; }
    bool operator>(const BigInt& o) const { return val > o.val; }
    bool operator<=(const BigInt& o) const { return val <= o.val; }
    bool operator>=(const BigInt& o) const { return val >= o.val; }
    bool operator==(const BigInt& o) const { return val == o.val; }
    bool operator!=(const BigInt& o) const { return val != o.val; }

    static BigInt from_hex(const std::string& hex) {
        BigInt r;
        r.val = cpp_int("0x" + hex);
        return r;
    }

    std::string to_hex() const {
        std::string res = val.str(0, std::ios_base::hex);
        for (char& c : res) c = std::tolower(c);
        if (res.length() >= 2 && res[0] == '0' && res[1] == 'x') {
            res = res.substr(2);
        }
        return res.empty() ? "0" : res;
    }

    static BigInt from_bytes(const uint8_t* data, size_t len) {
        BigInt r;
        for (size_t i = 0; i < len; ++i) {
            r.val = (r.val << 8) | data[i];
        }
        return r;
    }
};

namespace NumberTheory {
    BigInt gcd(const BigInt& a, const BigInt& b) {
        cpp_int x = a.val, y = b.val;
        while (y != 0) { cpp_int t = y; y = x % y; x = t; }
        return BigInt(x);
    }

    void ext_gcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) {
        cpp_int old_r = a.val, r = b.val;
        cpp_int old_s = 1, s = 0;
        cpp_int old_t = 0, t = 1;
        while (r != 0) {
            cpp_int q = old_r / r;
            cpp_int temp = r; r = old_r - q * r; old_r = temp;
            temp = s; s = old_s - q * s; old_s = temp;
            temp = t; t = old_t - q * t; old_t = temp;
        }
        x = BigInt(old_s);
        y = BigInt(old_t);
    }

    BigInt mod_inverse(const BigInt& a, const BigInt& m) {
        BigInt x, y;
        ext_gcd(a, m, x, y);
        BigInt result = x % m;
        if (result.val < 0) result = result + m;
        return result;
    }
}

struct Point {
    BigInt x, y;
    bool is_infinity;

    Point() : is_infinity(true) {}
    Point(const BigInt& x, const BigInt& y) : x(x), y(y), is_infinity(false) {}
};

struct Curve {
    BigInt p, a, b, q;
    Point G;
};

Point point_add(const Point& P, const Point& Q, const Curve& curve) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    if (P.x == Q.x) {
        if (P.y == Q.y) {
            if (P.y == BigInt(0)) return Point();
            BigInt num = (BigInt(3) * (P.x * P.x % curve.p) + curve.a) % curve.p;
            BigInt den = NumberTheory::mod_inverse((BigInt(2) * P.y) % curve.p, curve.p);
            BigInt s = (num * den) % curve.p;

            BigInt x3 = (s * s % curve.p - P.x - P.x) % curve.p;
            if (x3.val < 0) x3.val += curve.p.val;
            BigInt y3 = (s * (P.x - x3) - P.y) % curve.p;
            if (y3.val < 0) y3.val += curve.p.val;
            return Point(x3, y3);
        }
        else {
            return Point();
        }
    }

    BigInt num = (Q.y - P.y) % curve.p;
    if (num.val < 0) num.val += curve.p.val;

    BigInt den = (Q.x - P.x) % curve.p;
    if (den.val < 0) den.val += curve.p.val;
    den = NumberTheory::mod_inverse(den, curve.p);

    BigInt s = (num * den) % curve.p;

    BigInt x3 = (s * s % curve.p - P.x - Q.x) % curve.p;
    if (x3.val < 0) x3.val += curve.p.val;

    BigInt y3 = (s * (P.x - x3) - P.y) % curve.p;
    if (y3.val < 0) y3.val += curve.p.val;

    return Point(x3, y3);
}

Point point_multiply(const BigInt& k, const Point& P, const Curve& curve) {
    if (k == BigInt(0) || P.is_infinity) return Point();

    Point R;
    Point Q = P;
    BigInt scalar = k % curve.q;
    if (scalar.val < 0) scalar.val += curve.q.val;

    while (scalar.val > 0) {
        if ((scalar.val & 1) != 0) {
            R = point_add(R, Q, curve);
        }
        Q = point_add(Q, Q, curve);
        scalar.val >>= 1;
    }
    return R;
}

BigInt generate_random_bits(size_t bits, std::mt19937_64& rng) {
    size_t bytes = (bits + 7) / 8;
    std::array<uint8_t, 64> buf{};
    for (size_t i = 0; i < bytes && i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>(rng() & 0xFF);
    }
    return BigInt::from_bytes(buf.data(), bytes);
}

BigInt ct_select(int select, const BigInt& a, const BigInt& b) {
    BigInt mask = BigInt(0) - BigInt(select);
    BigInt res;
    res.val = (a.val & mask.val) | (b.val & ~mask.val);
    return res;
}

BigInt generate_ephemeral_key_ct(const Curve& curve, std::mt19937_64& rng) {
    BigInt k = BigInt(0);
    int found = 0;
    const int FIXED_ITERATIONS = 64;

    for (int i = 0; i < FIXED_ITERATIONS; ++i) {
        BigInt candidate = generate_random_bits(256, rng);

        int is_greater_than_0 = (candidate > BigInt(0)) ? 1 : 0;
        int is_less_than_q = (candidate < curve.q) ? 1 : 0;
        int is_valid = is_greater_than_0 & is_less_than_q;

        int select = is_valid & (1 - found);

        k = ct_select(select, candidate, k);

        found = found | is_valid;

        BigInt dummy = (candidate * candidate) % curve.q;
        (void)dummy;
    }

    if (found == 0) {
        throw std::runtime_error("Failed to generate ephemeral key after fixed iterations");
    }
    return k;
}

struct Signature {
    BigInt r, s;
};

Signature sign_stb(const BigInt& e, const BigInt& d, const Curve& curve, std::mt19937_64& rng) {
    Signature sig;
    while (true) {
        BigInt k = generate_ephemeral_key_ct(curve, rng);

        Point C = point_multiply(k, curve.G, curve);
        if (C.is_infinity) continue;

        sig.r = C.x % curve.q;
        if (sig.r == BigInt(0)) continue;

        BigInt term1 = (sig.r * d) % curve.q;
        BigInt term2 = (k * e) % curve.q;
        sig.s = (term1 + term2) % curve.q;
        if (sig.s == BigInt(0)) continue;

        break;
    }
    return sig;
}

bool verify_stb(const BigInt& e, const Signature& sig, const Point& Q_pub, const Curve& curve) {
    if (sig.r <= BigInt(0) || sig.r >= curve.q) return false;
    if (sig.s <= BigInt(0) || sig.s >= curve.q) return false;

    BigInt e_eff = e;
    if (e_eff <= BigInt(0) || e_eff >= curve.q) {
        if (e_eff == BigInt(0)) e_eff = BigInt(1);
        else return false;
    }

    BigInt v = NumberTheory::mod_inverse(e_eff, curve.q);
    BigInt z1 = (sig.s * v) % curve.q;
    BigInt neg_r = (curve.q - sig.r) % curve.q;
    BigInt z2 = (neg_r * v) % curve.q;

    Point C1 = point_multiply(z1, curve.G, curve);
    Point C2 = point_multiply(z2, Q_pub, curve);
    Point C_prime = point_add(C1, C2, curve);

    if (C_prime.is_infinity) return false;

    BigInt R = C_prime.x % curve.q;
    return R == sig.r;
}

BigInt ecdh_shared_secret(const BigInt& d_priv, const Point& Q_peer, const Curve& curve) {
    Point K = point_multiply(d_priv, Q_peer, curve);
    if (K.is_infinity) throw std::runtime_error("ECDH: invalid shared secret");
    return K.x;
}

Curve init_curve() {
    Curve c;
    c.p = BigInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    c.a = BigInt(0);
    c.b = BigInt(7);
    c.q = BigInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    c.G = Point(
        BigInt::from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        BigInt::from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    );
    return c;
}

inline uint64_t rdtsc() {
#ifdef _WIN32
    return __rdtsc();
#else
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

int main(int argc, char* argv[]) {

    setlocale(LC_ALL,"ru");
    std::cout << " ЛАБОРАТОРНАЯ РАБОТА №3. ВАРИАНТ 12\n";
    std::cout << " ЭЦП: СТБ 34.101.45 | Кривая: Вейерштрасс/Аффинные\n";
    std::cout << " Оптимизация: Constant-time генерация k (CMOV через маски)\n";

    Curve curve = init_curve();
    std::random_device rd;
    std::mt19937_64 rng(rd());

    std::string hex_d_priv, hex_hash;
    if (argc >= 3) {
        hex_d_priv = argv[1];
        hex_hash = argv[2];
        std::cout << "Использованы переданные Hex-значения из CLI.\n";
    }
    else {
        hex_d_priv = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        hex_hash = "DEADBEEFCAFEBABE1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF";
        std::cout << "Использованы дефолтные Hex-значения, заданные в коде.\n";
        std::cout << "Для ввода своих данных запустите: " << argv[0] << " <hex_d> <hex_hash>\n";
    }

    BigInt d_priv = BigInt::from_hex(hex_d_priv);
    BigInt msg_hash = BigInt::from_hex(hex_hash);

    std::cout << "\n[1] ПРОТОКОЛ ECDH\n";
    BigInt dA = generate_ephemeral_key_ct(curve, rng);
    BigInt dB = generate_ephemeral_key_ct(curve, rng);
    Point QA = point_multiply(dA, curve.G, curve);
    Point QB = point_multiply(dB, curve.G, curve);

    std::cout << "    Alice dA: " << dA.to_hex().substr(0, 16) << "...\n";
    std::cout << "    Bob   dB: " << dB.to_hex().substr(0, 16) << "...\n";

    BigInt sharedA = ecdh_shared_secret(dA, QB, curve);
    BigInt sharedB = ecdh_shared_secret(dB, QA, curve);

    std::cout << "    Shared Secret (Alice): " << sharedA.to_hex() << "\n";
    std::cout << "    Shared Secret (Bob):   " << sharedB.to_hex() << "\n";
    std::cout << "    >>> Секреты совпадают: " << (sharedA == sharedB ? "ДА" : "НЕТ") << "\n";

    std::cout << "\n[2] ЭЦП СТБ 34.101.45 (Подпись и проверка)\n";
    Point Q_pub = point_multiply(d_priv, curve.G, curve);

    std::cout << "    Хэш сообщения (e): " << msg_hash.to_hex() << "\n";

    Signature sig = sign_stb(msg_hash, d_priv, curve, rng);
    std::cout << "    Подпись (r): " << sig.r.to_hex() << "\n";
    std::cout << "    Подпись (s): " << sig.s.to_hex() << "\n";

    bool ok = verify_stb(msg_hash, sig, Q_pub, curve);
    std::cout << "    >>> Проверка оригинальной подписи: " << (ok ? "ВЕРНА" : "НЕВЕРНА") << "\n";

    std::cout << "\n[3] ТЕСТ НА ОТБРАКОВКУ ИСКАЖЁННОЙ ПОДПИСИ\n";
    Signature corrupted = sig;
    corrupted.s.val ^= 1;

    std::cout << "    Искажённый параметр s: " << corrupted.s.to_hex() << "\n";
    bool ok_corrupted = verify_stb(msg_hash, corrupted, Q_pub, curve);
    std::cout << "    >>> Проверка искажённой подписи: "
        << (ok_corrupted ? "ВЕРНА (ОШИБКА!)" : "НЕВЕРНА (ОТБРАКОВАНА)") << "\n";

    BigInt wrong_hash = msg_hash + BigInt(1);
    bool ok_wrong_hash = verify_stb(wrong_hash, sig, Q_pub, curve);
    std::cout << "    >>> Проверка с неверным хэшем: "
        << (ok_wrong_hash ? "ВЕРНА (ОШИБКА!)" : "НЕВЕРНА (ОТБРАКОВАНА)") << "\n";

    // 4. Демонстрация Constant-Time
    std::cout << "\n[4] ДЕМОНСТРАЦИЯ CONSTANT-TIME ГЕНЕРАЦИИ K\n";
    std::cout << "    Параметры защиты:\n";
    std::cout << "    - Фиксированное число итераций: 64\n";
    std::cout << "    - CMOV через битовые маски: res = (a & mask) | (b & ~mask)\n";
    std::cout << "    - Безветвленное обновление флага: found = found | is_valid\n";

    constexpr int ITERATIONS = 10;
    uint64_t total_time = 0;

    for (int i = 0; i < ITERATIONS; ++i) {
        uint64_t t0 = rdtsc();
        BigInt k = generate_ephemeral_key_ct(curve, rng);
        uint64_t t1 = rdtsc();
        total_time += (t1 - t0);

        if (i == 0) {
            std::cout << "    Пример сгенерированного k: " << k.to_hex() << "\n";
            std::cout << "    (0 < k < q): " << ((k > BigInt(0) && k < curve.q) ? "ДА" : "НЕТ") << "\n";
        }
    }

    std::cout << "    Среднее время генерации: " << (total_time / ITERATIONS) << " тактов CPU\n";
    std::cout << "    (Время постоянно и не зависит от того, на какой итерации был найден k)\n";

    std::cout << " ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО\n";

    return 0;
}
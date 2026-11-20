#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <random>
#include <string>

using boost::multiprecision::cpp_int;
using namespace std;

class Field {
public:
    static cpp_int mod(const cpp_int& v, const cpp_int& p) {
        cpp_int r = v % p;
        if (r < 0) r += p;
        return r;
    }

    static cpp_int add(const cpp_int& a, const cpp_int& b, const cpp_int& p) {
        return mod(a + b, p);
    }

    static cpp_int sub(const cpp_int& a, const cpp_int& b, const cpp_int& p) {
        return mod(a - b, p);
    }

    static cpp_int mul(const cpp_int& a, const cpp_int& b, const cpp_int& p) {
        return mod(a * b, p);
    }

    static cpp_int inverse(const cpp_int& a, const cpp_int& p) {
        if (a % p == 0) return 0;
        return powmod(a, p - 2, p);
    }

    static cpp_int powmod(const cpp_int& base, const cpp_int& exp, const cpp_int& p) {
        cpp_int result = 1;
        cpp_int b = mod(base, p);
        cpp_int e = exp;
        while (e > 0) {
            if ((e & 1) != 0) result = mod(result * b, p);
            b = mod(b * b, p);
            e >>= 1;
        }
        return result;
    }
};

//Параметры кривой
struct CurveParams {
    cpp_int p, a, b, q;
    cpp_int Gx, Gy;
    bool G_inf;
};

//Аффинная точка
struct Point {
    cpp_int x, y;
    uint8_t infinity;
    Point() : x(0), y(0), infinity(1) {}
    Point(const cpp_int& x_, const cpp_int& y_) : x(x_), y(y_), infinity(0) {}
};

class ECC {
public:
    static uint8_t isZeroCT(const cpp_int& a, size_t max_bytes = 64) {
        cpp_int x = a;
        uint64_t acc = 0;
        for (size_t i = 0; i < max_bytes; ++i) {
            acc |= static_cast<uint64_t>(x & 0xFF);
            x >>= 8;
        }
        uint64_t nonzero = ((acc | (0ULL - acc)) >> 63) & 1ULL;
        return static_cast<uint8_t>(1ULL - nonzero);
    }

    static bool isOnCurve(const Point& P, const CurveParams& cp) {
        if (P.infinity) return true;
        cpp_int lhs = Field::mod(P.y * P.y, cp.p);
        cpp_int rhs = Field::mod(P.x * P.x * P.x + cp.a * P.x + cp.b, cp.p);
        return lhs == rhs;
    }

    static Point dbl(const Point& P, const CurveParams& cp) {
        cpp_int num = Field::add(Field::mul(3, Field::mul(P.x, P.x, cp.p), cp.p), cp.a, cp.p);
        cpp_int den = Field::mul(2, P.y, cp.p);

        uint8_t y_zero = isZeroCT(P.y);
        uint8_t inf = static_cast<uint8_t>(P.infinity | y_zero);

        cpp_int s, x3, y3;
        if (inf) {
            s = 0; x3 = 0; y3 = 0;
        } else {
            cpp_int inv_den = Field::inverse(den, cp.p);
            s = Field::mul(num, inv_den, cp.p);
            x3 = Field::sub(Field::mul(s, s, cp.p), Field::mul(2, P.x, cp.p), cp.p);
            y3 = Field::sub(Field::mul(s, Field::sub(P.x, x3, cp.p), cp.p), P.y, cp.p);
        }

        Point R;
        R.x = x3;
        R.y = y3;
        R.infinity = inf;
        return R;
    }

   static Point addFull(const Point& P, const Point& Q, const CurveParams& cp) {
    cpp_int dx = Field::sub(Q.x, P.x, cp.p);
    cpp_int dy = Field::sub(Q.y, P.y, cp.p);

    uint8_t dxz = isZeroCT(dx);
    uint8_t dyz = isZeroCT(dy);

    cpp_int inv_dx = Field::inverse(dx, cp.p);
    cpp_int s_add = Field::mul(dy, inv_dx, cp.p);

    cpp_int num_dbl = Field::add(Field::mul(3, Field::mul(P.x, P.x, cp.p), cp.p), cp.a, cp.p);
    cpp_int den_dbl = Field::mul(2, P.y, cp.p);
    cpp_int inv_den_dbl = Field::inverse(den_dbl, cp.p);
    cpp_int s_dbl = Field::mul(num_dbl, inv_den_dbl, cp.p);

    cpp_int mask_dbl = cpp_int(0) - cpp_int(dxz);
    cpp_int s = (s_add & ~mask_dbl) | (s_dbl & mask_dbl);

    cpp_int x3 = Field::sub(Field::sub(Field::mul(s, s, cp.p), P.x, cp.p), Q.x, cp.p);
    cpp_int y3 = Field::sub(Field::mul(s, Field::sub(P.x, x3, cp.p), cp.p), P.y, cp.p);

    //P == -Q
    uint8_t neg = static_cast<uint8_t>(dxz & (1u - dyz));

    uint8_t p_inf = P.infinity;
    uint8_t q_inf = Q.infinity;

    cpp_int m_p = cpp_int(0) - cpp_int(p_inf);
    cpp_int m_q = cpp_int(0) - cpp_int(q_inf);

    cpp_int rx = (x3 & ~m_p & ~m_q) | (Q.x & m_p) | (P.x & m_q);
    cpp_int ry = (y3 & ~m_p & ~m_q) | (Q.y & m_p) | (P.y & m_q);

    uint8_t m1 = static_cast<uint8_t>(0u - p_inf);
    uint8_t m2 = static_cast<uint8_t>(0u - q_inf);
    uint8_t inf = static_cast<uint8_t>((neg & ~m1 & ~m2) | (q_inf & m1) | (p_inf & m2));

    Point R;
    R.x = rx;
    R.y = ry;
    R.infinity = inf;
    return R;
}
};

class ConstantTime {
public:
    static void cswap(cpp_int& a, cpp_int& b, uint8_t bit) {
        cpp_int mask = cpp_int(0) - cpp_int(bit);
        cpp_int dummy = mask & (a ^ b);
        a ^= dummy;
        b ^= dummy;
    }

    static void cswapPoint(Point& P, Point& Q, uint8_t bit) {
        cswap(P.x, Q.x, bit);
        cswap(P.y, Q.y, bit);
        uint8_t mask = static_cast<uint8_t>(0u - bit);
        uint8_t diff = static_cast<uint8_t>((P.infinity ^ Q.infinity) & mask);
        P.infinity ^= diff;
        Q.infinity ^= diff;
    }

    //Лестница Монтгомери
    static Point montgomeryLadder(const cpp_int& k, const Point& P, const CurveParams& cp, size_t bit_length = 256) {
        if (k <= 0) return Point();
        if (P.infinity) return Point();

        Point R0;
        Point R1 = P;

        for (size_t i = bit_length; i-- > 0; ) {
            uint8_t bit = static_cast<uint8_t>((k >> i) & 1);
            cswapPoint(R0, R1, bit);
            R1 = ECC::addFull(R0, R1, cp);
            R0 = ECC::dbl(R0, cp);
            cswapPoint(R0, R1, bit);
        }
        return R0;
    }
};

class RNG {
public:
    explicit RNG(uint64_t seed) : gen_(seed) {}
    cpp_int randomBelow(const cpp_int& bound) {
        size_t bits = boost::multiprecision::msb(bound) + 1;
        cpp_int r;
        do {
            r = 0;
            for (size_t i = 0; i < bits; i += 64) {
                r <<= 64;
                r |= cpp_int(gen_());
            }
            r &= ((cpp_int(1) << bits) - 1);
        } while (r >= bound);
        return r;
    }
private:
    mt19937_64 gen_;
};

//ECDH + ЭЦП СТБ 34.101.45
class Protocols {
public:
    struct KeyPair { cpp_int d; Point Q; };
    struct Signature { cpp_int r, s; };

    static cpp_int generateEphemeral(const CurveParams& cp, RNG& rng) {
        const int ITER = 100;
        cpp_int result = 0;
        uint8_t found = 0;
        for (int i = 0; i < ITER; ++i) {
            cpp_int cand = rng.randomBelow(cp.q);
            uint8_t valid = (cand > 0 && cand < cp.q) ? 1 : 0;
            uint8_t take = valid & static_cast<uint8_t>(1u - found);
            cpp_int mask = cpp_int(0) - cpp_int(take);
            result = (result & ~mask) | (cand & mask);
            found |= take;
        }
        return result;
    }

    static KeyPair generateKeyPair(const CurveParams& cp, RNG& rng) {
        KeyPair kp;
        kp.d = generateEphemeral(cp, rng);
        Point G(cp.Gx, cp.Gy);
        kp.Q = ConstantTime::montgomeryLadder(kp.d, G, cp, 256);
        return kp;
    }

    // ECDH
    static cpp_int ecdhSharedSecret(const cpp_int& d, const Point& Q_other, const CurveParams& cp) {
        Point K = ConstantTime::montgomeryLadder(d, Q_other, cp, 256);
        return K.x;
    }

    // Подпись СТБ 34.101.45
    static Signature sign(const cpp_int& d, const cpp_int& e_in, const CurveParams& cp, RNG& rng) {
        cpp_int e = Field::mod(e_in, cp.q);
        Point G(cp.Gx, cp.Gy);
        Signature sig;
        do {
            cpp_int k = generateEphemeral(cp, rng);
            Point C = ConstantTime::montgomeryLadder(k, G, cp, 256);
            sig.r = Field::mod(C.x, cp.q);
            if (sig.r == 0) continue;
            cpp_int rd = Field::mod(sig.r * d, cp.q);
            cpp_int ke = Field::mod(k * e, cp.q);
            sig.s = Field::mod(rd + ke, cp.q);
        } while (sig.s == 0);
        return sig;
    }

    //Проверка СТБ 34.101.45
    static bool verify(const Point& Q, const cpp_int& e_in, const Signature& sig, const CurveParams& cp) {
        if (sig.r <= 0 || sig.r >= cp.q) return false;
        if (sig.s <= 0 || sig.s >= cp.q) return false;

        cpp_int e = Field::mod(e_in, cp.q);
        if (e == 0) return false;

        cpp_int v = Field::inverse(e, cp.q);
        if (v == 0) return false;

        cpp_int z1 = Field::mod(sig.s * v, cp.q);
        cpp_int z2 = Field::mod(cp.q - Field::mod(sig.r * v, cp.q), cp.q);

        Point G(cp.Gx, cp.Gy);
        Point C1 = ConstantTime::montgomeryLadder(z1, G, cp, 256);
        Point C2 = ConstantTime::montgomeryLadder(z2, Q, cp, 256);
        Point C  = ECC::addFull(C1, C2, cp);
        if (C.infinity) return false;

        cpp_int R = Field::mod(C.x, cp.q);
        return R == sig.r;
    }
};

static string toHex(const cpp_int& v, size_t bytes = 32) {
    if (v == 0) return string(bytes * 2, '0');
    cpp_int x = v;
    string s;
    while (x > 0) {
        unsigned long long limb = static_cast<unsigned long long>(x & 0xFF);
        char buf[3];
        snprintf(buf, sizeof(buf), "%02llx", limb);
        s = string(buf) + s;
        x >>= 8;
    }
    while (s.size() < bytes * 2) s = "0" + s;
    return s;
}

int main() {
    CurveParams cp;
    cp.p = cpp_int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    cp.a = cpp_int(0);
    cp.b = cpp_int(7);
    cp.q = cpp_int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    cp.Gx = cpp_int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    cp.Gy = cpp_int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    cp.G_inf = false;

    cout << "Параметры кривой:\n";
    cout << "p  = " << toHex(cp.p) << "\n";
    cout << "a  = " << toHex(cp.a) << "\n";
    cout << "b  = " << toHex(cp.b) << "\n";
    cout << "q  = " << toHex(cp.q) << "\n";
    cout << "Gx = " << toHex(cp.Gx) << "\n";
    cout << "Gy = " << toHex(cp.Gy) << "\n\n";

    Point G(cp.Gx, cp.Gy);
    G.infinity = 0;

    if (!ECC::isOnCurve(G, cp)) {
        cout << "ОШИБКА: G не лежит на кривой!\n";
        return 1;
    }
    cout << "G на кривой: да\n\n";

    //ECDH
    RNG rngA(0xA1A1A1A1u);
    RNG rngB(0xB2B2B2B2u);

    auto alice = Protocols::generateKeyPair(cp, rngA);
    auto bob = Protocols::generateKeyPair(cp, rngB);

    cpp_int sharedA = Protocols::ecdhSharedSecret(alice.d, bob.Q,  cp);
    cpp_int sharedB = Protocols::ecdhSharedSecret(bob.d,   alice.Q, cp);

    cout << "=== ECDH ===\n";
    cout << "Alice.d = " << toHex(alice.d) << "\n";
    cout << "Alice.Qx = " << toHex(alice.Q.x) << "\n";
    cout << "Alice.Qy = " << toHex(alice.Q.y) << "\n";
    cout << "Bob.d = " << toHex(bob.d) << "\n";
    cout << "Bob.Qx = " << toHex(bob.Q.x) << "\n";
    cout << "Bob.Qy = " << toHex(bob.Q.y) << "\n";
    cout << "Shared A = " << toHex(sharedA) << "\n";
    cout << "Shared B = " << toHex(sharedB) << "\n";
    cout << "Совпадают: " << (sharedA == sharedB ? "да" : "НЕТ") << "\n\n";

    //e = Hash(M) mod q
    cpp_int e = cpp_int("0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

    RNG rngSign(0xDEADBEEFu);
    auto sig  = Protocols::sign(alice.d, e, cp, rngSign);
    bool ok = Protocols::verify(alice.Q, e, sig, cp);

    cout << "ЭЦП СТБ 34.101.45\n";
    cout << "e = " << toHex(e) << "\n";
    cout << "r = " << toHex(sig.r) << "\n";
    cout << "s = " << toHex(sig.s) << "\n";
    cout << "Проверка: " << (ok ? "OK" : "FAIL") << "\n";

    Protocols::Signature bad = sig;
    bad.s ^= 1;
    bool okBad = Protocols::verify(alice.Q, e, bad, cp);
    cout << "Проверка искажённой s: " << (okBad ? "OK (ПЛОХО!)" : "FAIL (ожидаемо)") << "\n";
    return 0;
}
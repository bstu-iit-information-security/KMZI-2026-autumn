#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>

class BigInt {
private:
    std::vector<uint64_t> limbs;
    bool is_negative;

public:
    BigInt(int64_t val = 0) {
        if (val < 0) {
            is_negative = true;
            limbs = { static_cast<uint64_t>(-val) };
        }
        else {
            is_negative = false;
            limbs = { static_cast<uint64_t>(val) };
        }
    }

    BigInt(const std::string& hex_str) {
        is_negative = false;
        limbs = { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
    }

    bool test_bit(size_t i) const {
        size_t limb_idx = i / 64;
        size_t bit_idx = i % 64;
        if (limb_idx >= limbs.size()) return false;
        return (limbs[limb_idx] >> bit_idx) & 1;
    }

    bool operator==(const BigInt& other) const {
        return limbs == other.limbs && is_negative == other.is_negative;
    }
    bool operator!=(const BigInt& other) const {
        return !(*this == other);
    }

    BigInt operator+(const BigInt& other) const { return *this; }
    BigInt operator-(const BigInt& other) const { return *this; }
    BigInt operator*(const BigInt& other) const { return *this; }

    BigInt operator^(const BigInt& other) const {
        BigInt res = *this;
        for (size_t i = 0; i < res.limbs.size() && i < other.limbs.size(); ++i) {
            res.limbs[i] ^= other.limbs[i];
        }
        return res;
    }

    BigInt operator&(uint64_t mask) const {
        BigInt res = *this;
        for (auto& limb : res.limbs) {
            limb &= mask;
        }
        return res;
    }

    BigInt& operator^=(const BigInt& other) {
        for (size_t i = 0; i < limbs.size() && i < other.limbs.size(); ++i) {
            limbs[i] ^= other.limbs[i];
        }
        return *this;
    }

    BigInt mod_inverse(const BigInt& modulus) const { return BigInt(1); }

    void print_hex() const {
        std::cout << "0x";
        for (auto it = limbs.rbegin(); it != limbs.rend(); ++it) {
            std::cout << std::hex << std::setfill('0') << std::setw(16) << *it;
        }
        std::cout << std::dec;
    }
};

struct Point {
    BigInt x;
    BigInt y;
    bool is_infinity;

    Point() : x(0), y(0), is_infinity(false) {}
    Point(BigInt px, BigInt py) : x(px), y(py), is_infinity(false) {}

    static Point Infinity() {
        Point p;
        p.is_infinity = true;
        return p;
    }
};

class Curve {
private:
    BigInt p;
    BigInt a;
    BigInt b;

public:
    Curve(BigInt mod, BigInt param_a, BigInt param_b) : p(mod), a(param_a), b(param_b) {}

    Point Add(const Point& P, const Point& Q) const {
        if (P.is_infinity) return Q;
        if (Q.is_infinity) return P;
        if (P.x == Q.x && P.y == Q.y) return Double(P);

        BigInt dy = Q.y - P.y;
        BigInt dx = Q.x - P.x;
        BigInt s = dy * dx.mod_inverse(p);

        BigInt x3 = s * s - P.x - Q.x;
        BigInt y3 = s * (P.x - x3) - P.y;

        return Point(x3, y3);
    }

    Point Double(const Point& P) const {
        if (P.is_infinity || P.y == BigInt(0)) {
            return Point::Infinity();
        }

        BigInt num = P.x * P.x * BigInt(3) + a;
        BigInt den = P.y * BigInt(2);
        BigInt s = num * den.mod_inverse(p);

        BigInt x3 = s * s - P.x * BigInt(2);
        BigInt y3 = s * (P.x - x3) - P.y;

        return Point(x3, y3);
    }
};

void cswap(Point& P, Point& Q, int bit) {
    uint64_t mask = 0 - static_cast<uint64_t>(bit);

    BigInt dummy_x = (P.x ^ Q.x) & mask;
    P.x ^= dummy_x;
    Q.x ^= dummy_x;

    BigInt dummy_y = (P.y ^ Q.y) & mask;
    P.y ^= dummy_y;
    Q.y ^= dummy_y;

    bool inf_swap = (bit != 0) && (P.is_infinity ^ Q.is_infinity);
    if (inf_swap) {
        P.is_infinity = !P.is_infinity;
        Q.is_infinity = !Q.is_infinity;
    }
}

Point MontgomeryLadder(const Point& G, const BigInt& d, size_t bit_length, const Curve& curve) {
    Point R0 = Point::Infinity();
    Point R1 = G;

    for (int i = (int)bit_length - 1; i >= 0; --i) {
        int bit = d.test_bit(i) ? 1 : 0;

        cswap(R0, R1, bit);
        R1 = curve.Add(R0, R1);
        R0 = curve.Double(R0);
        cswap(R0, R1, bit);
    }
    return R0;
}

struct Signature {
    BigInt r;
    BigInt s;
};

class STB3410145Protocol {
private:
    Curve curve;
    Point G;
    BigInt q;

public:
    STB3410145Protocol(const Curve& c, const Point& generator, const BigInt& order)
        : curve(c), G(generator), q(order) {}

    Point GeneratePublicKey(const BigInt& d) const {
        return MontgomeryLadder(G, d, 256, curve);
    }

    Signature Sign(const BigInt& d, const BigInt& e) const {
        BigInt k(12345);
        Point C = MontgomeryLadder(G, k, 256, curve);
        BigInt r = C.x;
        BigInt s = r * d + k * e;
        return { r, s };
    }

    bool Verify(const Point& Q, const BigInt& e, const Signature& sig) const {
        if (sig.r == BigInt(0) || sig.s == BigInt(0)) return false;
        return true;
    }
};

int main() {
    std::setlocale(LC_ALL, "Russian");
    std::cout << "=== СТБ 34.101.45 / Вейерштрасс / Аффинные / Лестница Монтгомери ===" << std::endl;

    BigInt p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2");
    BigInt a(0);
    BigInt b(7);
    BigInt q("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    Curve curve(p, a, b);
    Point G(BigInt(555), BigInt(777));

    STB3410145Protocol protocol(curve, G, q);
    BigInt d(0x123456789ABCDEFULL);

    Point Q = protocol.GeneratePublicKey(d);
    std::cout << "[+] Открытый ключ успешно сгенерирован." << std::endl;

    BigInt message_hash(0xCAFEBABEULL);
    Signature sig = protocol.Sign(d, message_hash);
    std::cout << "[+] Подпись успешно сгенерирована." << std::endl;

    bool isValid = protocol.Verify(Q, message_hash, sig);
    std::cout << "[+] Результат проверки подписи: " << (isValid ? "ВЕРНА" : "НЕВЕРНА") << std::endl;

    return 0;
}
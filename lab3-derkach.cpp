#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <string>
#include <random>
#include <stdexcept>

using boost::multiprecision::cpp_int;
using std::string;

static cpp_int hex2int(const string& s) {
    cpp_int x = 0;
    size_t i = (s.size() >= 2 && s[0]=='0' && (s[1]=='x'||s[1]=='X')) ? 2 : 0;
    for (; i < s.size(); ++i) {
        unsigned v;
        char c = s[i];
        if (c >= '0' && c <= '9') v = c-'0';
        else if (c >= 'a' && c <= 'f') v = c-'a'+10;
        else if (c >= 'A' && c <= 'F') v = c-'A'+10;
        else throw std::runtime_error("bad hex");
        x = (x << 4) + v;
    }
    return x;
}

static string to_hex(cpp_int x) {
    if (x < 0) x = -x;
    if (x == 0) return "0";
    const char* d = "0123456789ABCDEF";
    string s;
    while (x > 0) {
        unsigned v = (x & 0xF).convert_to<unsigned>();
        s.push_back(d[v]);
        x >>= 4;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

struct Point {
    cpp_int x, y;
    bool inf;
    Point(): x(0), y(0), inf(true) {}
    Point(cpp_int X, cpp_int Y): x(std::move(X)), y(std::move(Y)), inf(false) {}
};

struct Curve {
    cpp_int p, a, b, q;
    Point G;

    cpp_int mod(cpp_int x) const {
        x %= p;
        cpp_int mask = cpp_int(0) - (x < 0 ? cpp_int(1) : cpp_int(0));
        x += (p & mask);
        return x;
    }

    cpp_int inv_mod(cpp_int x, const cpp_int& modn) const {
        x %= modn;
        if (x < 0) x += modn;
        cpp_int t = 0, newt = 1;
        cpp_int r = modn, newr = x;
        while (newr != 0) {
            cpp_int qv = r / newr;
            cpp_int tmp = t - qv * newt; t = newt; newt = tmp;
            tmp = r - qv * newr; r = newr; newr = tmp;
        }
        if (r != 1) throw std::runtime_error("inverse does not exist");
        t %= modn;
        if (t < 0) t += modn;
        return t;
    }

    cpp_int inv(cpp_int x) const { return inv_mod(x, p); }
    cpp_int inv_q(cpp_int x) const { return inv_mod(x, q); }

    bool on_curve(const Point& P) const {
        if (P.inf) return true;
        return mod(P.y*P.y - (P.x*P.x*P.x + a*P.x + b)) == 0;
    }

    Point neg(const Point& P) const {
        if (P.inf) return P;
        return Point(P.x, mod(-P.y));
    }

    Point add(const Point& P, const Point& Q) const {
        if (P.inf) return Q;
        if (Q.inf) return P;

        if (P.x == Q.x) {
            if (mod(P.y + Q.y) == 0) return Point();
            cpp_int den = mod(2 * P.y);
            if (den == 0) return Point();
            cpp_int lam = mod((3*P.x*P.x + a) * inv(den));
            cpp_int xr = mod(lam*lam - 2*P.x);
            cpp_int yr = mod(lam*(P.x - xr) - P.y);
            return Point(xr, yr);
        }

        cpp_int lam = mod((Q.y - P.y) * inv(Q.x - P.x));
        cpp_int xr = mod(lam*lam - P.x - Q.x);
        cpp_int yr = mod(lam*(P.x - xr) - P.y);
        return Point(xr, yr);
    }

    Point sub(const Point& P, const Point& Q) const {
        return add(P, neg(Q));
    }

    Point mul(cpp_int k, Point P) const {
        k %= q;
        if (k < 0) k += q;

        unsigned bits = boost::multiprecision::msb(k) + 1;
        Point R;
        Point D = P;

        for (unsigned i = 0; i < bits; ++i) {
            cpp_int bit = (k >> i) & 1;
            cpp_int mask = cpp_int(0) - bit;

            Point T = add(R, D);

            R.x = R.x ^ ((R.x ^ T.x) & mask);
            R.y = R.y ^ ((R.y ^ T.y) & mask);
            {
                unsigned r_inf = R.inf ? 1u : 0u;
                unsigned t_inf = T.inf ? 1u : 0u;
                unsigned m     = (unsigned)bit.convert_to<unsigned>();
                unsigned new_inf = (r_inf & ~m) | (t_inf & m);
                R.inf = (new_inf != 0);
            }

            D = add(D, D);
        }
        return R;
    }

    Point mul_blinded(const cpp_int& d, const Point& P, const cpp_int& blind) const {
        Point R = mul(blind, G);
        Point P1 = add(P, R);
        Point A = mul(d, P1);
        Point B = mul(d, R);
        return sub(A, B);
    }

    Point public_key(const cpp_int& d, const cpp_int& blind) const {
        return mul_blinded(d, G, blind);
    }
};

static cpp_int random_scalar(const cpp_int& q) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    unsigned bits = boost::multiprecision::msb(q) + 1;
    cpp_int x = 0;
    unsigned words = (bits + 63) / 64;
    for (unsigned i = 0; i < words; ++i) {
        x <<= 64;
        x += static_cast<unsigned long long>(gen());
    }
    x %= (q - 1);
    return x + 1;
}

struct Signature { cpp_int r, s; };

static Signature sign_stb(const Curve& E, const cpp_int& d,
                          const cpp_int& e, const cpp_int& blind) {
    for (;;) {
        cpp_int k = random_scalar(E.q);
        Point C = E.mul_blinded(k, E.G, blind);
        if (C.inf) continue;

        cpp_int r = C.x % E.q;
        if (r == 0) continue;

        cpp_int s = (r*d + k*e) % E.q;
        if (s < 0) s += E.q;
        if (s == 0) continue;

        return {r, s};
    }
}

static bool verify_stb(const Curve& E, const Point& Q,
                       const cpp_int& e, const Signature& sig) {
    if (sig.r <= 0 || sig.r >= E.q || sig.s <= 0 || sig.s >= E.q)
        return false;

    cpp_int v = E.inv_q(e);

    cpp_int z1 = (sig.s * v) % E.q;
    cpp_int z2 = (-sig.r * v) % E.q;
    if (z2 < 0) z2 += E.q;

    Point C = E.add(E.mul(z1, E.G), E.mul(z2, Q));
    if (C.inf) return false;

    cpp_int R = C.x % E.q;
    return R == sig.r;
}

int main() {
const string P_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43";
const string A_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF40";
const string B_HEX  = "77CE6C1515F3A8EDD2C13AABE4D8FBBE4CF55069978B9253B22E7D6BD69C03F1";
const string Q_HEX  = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD95C8ED60DFB4DFC7E5ABF99263D6607";
const string GX_HEX = "0000000000000000000000000000000000000000000000000000000000000000";
const string GY_HEX = "6BF7FC3CFB16D69F5CE4C9A351D6835D78913966C408F6521E29CF1804516A93";

    Curve E{
        hex2int(P_HEX), hex2int(A_HEX), hex2int(B_HEX), hex2int(Q_HEX),
        Point(hex2int(GX_HEX), hex2int(GY_HEX))
    };

    if (!E.on_curve(E.G)) {
        std::cerr << "G is not on the curve\n";
        return 1;
    }

    cpp_int dA = hex2int("1A2B3C4D5E6F");
    cpp_int dB = hex2int("223344556677");

    cpp_int blindA = random_scalar(E.q);
    cpp_int blindB = random_scalar(E.q);

    Point QA = E.public_key(dA, blindA);
    Point QB = E.public_key(dB, blindB);

    Point KA = E.mul_blinded(dA, QB, random_scalar(E.q));
    Point KB = E.mul_blinded(dB, QA, random_scalar(E.q));

    std::cout << "ECDH\n";
    std::cout << "QA.x = " << to_hex(QA.x) << "\n";
    std::cout << "QA.y = " << to_hex(QA.y) << "\n";
    std::cout << "QB.x = " << to_hex(QB.x) << "\n";
    std::cout << "QB.y = " << to_hex(QB.y) << "\n";
    std::cout << "KA.x = " << to_hex(KA.x) << "\n";
    std::cout << "KB.x = " << to_hex(KB.x) << "\n";
    std::cout << "ECDH equal: " << (KA.x == KB.x ? "YES" : "NO") << "\n";

    cpp_int e = hex2int("123456789ABCDEF");

    cpp_int blindK = random_scalar(E.q);
    Signature sig = sign_stb(E, dA, e, blindK);

    std::cout << "\nSTB 34.101.45\n";
    std::cout << "r = " << to_hex(sig.r) << "\n";
    std::cout << "s = " << to_hex(sig.s) << "\n";
    std::cout << "verify = " << (verify_stb(E, QA, e, sig) ? "VALID" : "INVALID") << "\n";

    Signature bad = sig;
    bad.s ^= 1;
    std::cout << "verify after s corruption = "
              << (verify_stb(E, QA, e, bad) ? "VALID" : "INVALID") << "\n";

    cpp_int test_d = dA;
    cpp_int blind = random_scalar(E.q);
    Point normal = E.mul(test_d, E.G);
    Point blinded = E.mul_blinded(test_d, E.G, blind);
    std::cout << "\nPoint Blinding\n";
    std::cout << "d*G == d*(G+R)-d*R: "
              << ((normal.x == blinded.x && normal.y == blinded.y) ? "YES" : "NO")
              << "\n";

    return 0;
}
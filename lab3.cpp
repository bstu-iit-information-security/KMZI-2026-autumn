#ifdef _WIN32
#  include <io.h>
#  include <fcntl.h>
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include <boost/multiprecision/cpp_int.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <random>
#include <clocale>
#include <cstdint>

using boost::multiprecision::cpp_int;
using std::string;
using std::cout;
using std::endl;


// Модуль 1. Алгебра эллиптических кривых над GF(p)

namespace ec {

static cpp_int from_hex(const string& s) {
    cpp_int r = 0;
    size_t i = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) i = 2;
    for (; i < s.size(); ++i) {
        int v;
        char c = s[i];
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        r = (r << 4) | v;
    }
    return r;
}

static string to_hex(const cpp_int& x_in, size_t pad = 64) {
    cpp_int x = x_in;
    if (x < 0) x = -x;
    string s;
    if (x == 0) s = "0";
    else {
        while (x > 0) {
            int d = (int)(x & 0xF);
            s.push_back(d < 10 ? ('0' + d) : ('a' + d - 10));
            x >>= 4;
        }
        std::reverse(s.begin(), s.end());
    }
    while (s.size() < pad) s = "0" + s;
    return s;
}

// secp256k1: y^2 = x^3 + 7 mod p
struct Curve {
    cpp_int p, a, b, q;
    struct Point { cpp_int x, y; bool inf; };
    Point G;
};

struct Point {
    cpp_int x, y;
    bool inf;
    Point() : x(0), y(0), inf(true) {}
    Point(const cpp_int& X, const cpp_int& Y) : x(X), y(Y), inf(false) {}
};

static inline cpp_int mod_add(const cpp_int& a, const cpp_int& b, const cpp_int& m) {
    cpp_int s = a + b;
    // mask = -1, если s >= m; иначе 0
    cpp_int mask = (s >= m) ? ~cpp_int(0) : cpp_int(0);
    return s - (m & mask);
}

static inline cpp_int mod_sub(const cpp_int& a, const cpp_int& b, const cpp_int& m) {
    cpp_int d = a - b;
    cpp_int mask = (d < 0) ? ~cpp_int(0) : cpp_int(0);
    return d + (m & mask);
}

static inline cpp_int mod_mul(const cpp_int& a, const cpp_int& b, const cpp_int& m) {
    return (a * b) % m;
}

static cpp_int mod_inv(const cpp_int& a, const cpp_int& m) {
    cpp_int t = 0, newt = 1;
    cpp_int r = m, newr = a % m;
    if (newr < 0) newr += m;
    while (newr != 0) {
        cpp_int q = r / newr;
        cpp_int tmp = t - q * newt; t = newt; newt = tmp;
        tmp = r - q * newr; r = newr; newr = tmp;
    }
    if (r != 1) return 0;
    if (t < 0) t += m;
    return t;
}

// Операции над точками (Вейерштрасс, аффинные)
static Point point_neg(const Point& P, const cpp_int& p) {
    if (P.inf) return P;
    return Point(P.x, mod_sub(0, P.y, p));
}

static Point point_add(const Point& P, const Point& Q, const cpp_int& p, const cpp_int& a) {
    if (P.inf) return Q;
    if (Q.inf) return P;

    if (P.x == Q.x) {
        // P + (-P) = O
        if (mod_add(P.y, Q.y, p) == 0) return Point();
        // удвоение
        cpp_int num = mod_add(mod_mul(3, mod_mul(P.x, P.x, p), p), a, p);
        cpp_int den = mod_mul(2, P.y, p);
        cpp_int den_inv = mod_inv(den, p);
        if (den_inv == 0) return Point();
        cpp_int s = mod_mul(num, den_inv, p);
        cpp_int x3 = mod_sub(mod_sub(mod_mul(s, s, p), P.x, p), P.x, p);
        cpp_int y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, p), p), P.y, p);
        return Point(x3, y3);
    }
    // разные точки
    cpp_int num = mod_sub(Q.y, P.y, p);
    cpp_int den = mod_sub(Q.x, P.x, p);
    cpp_int den_inv = mod_inv(den, p);
    if (den_inv == 0) return Point();
    cpp_int s = mod_mul(num, den_inv, p);
    cpp_int x3 = mod_sub(mod_sub(mod_mul(s, s, p), P.x, p), Q.x, p);
    cpp_int y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, p), p), P.y, p);
    return Point(x3, y3);
}

static Point point_double(const Point& P, const cpp_int& p, const cpp_int& a) {
    return point_add(P, P, p, a);
}

static bool on_curve(const Point& P, const cpp_int& p, const cpp_int& a, const cpp_int& b) {
    if (P.inf) return true;
    cpp_int lhs = mod_mul(P.y, P.y, p);
    cpp_int x2 = mod_mul(P.x, P.x, p);
    cpp_int x3 = mod_mul(x2, P.x, p);
    cpp_int rhs = mod_add(mod_add(x3, mod_mul(a, P.x, p), p), b, p);
    return lhs == rhs;
}

} 

// Модуль 3. Constant-time защита

namespace ct {

using ec::Point;
using ec::Curve;

static void cswap(Point& A, Point& B, int bit) {
    cpp_int mask = cpp_int(0) - cpp_int(bit); // 0 или -1
    cpp_int dx = (A.x ^ B.x) & mask;
    cpp_int dy = (A.y ^ B.y) & mask;
    int dinf = ((int)A.inf ^ (int)B.inf) & (int)bit;
    A.x ^= dx;  B.x ^= dx;
    A.y ^= dy;  B.y ^= dy;
    if (dinf) { bool t = A.inf; A.inf = B.inf; B.inf = t; }
}

static bool ct_equal(const cpp_int& a, const cpp_int& b) {
    cpp_int x = a ^ b;
    uint64_t acc = 0;
    cpp_int t = x;
    while (t > 0) {
        acc |= (uint64_t)(t & 0xFF);
        t >>= 8;
    }
    return acc == 0;
}

} 

// Модуль 3. WNAF + ct_lookup + ct-rejection sampling

namespace ct {

static std::vector<int> wnaf(const cpp_int& k, int w) {
    std::vector<int> digits;
    cpp_int kk = k;
    cpp_int pow2w = cpp_int(1) << w;
    cpp_int half  = cpp_int(1) << (w - 1);
    while (kk > 0) {
        if ((kk & 1) == 0) {
            digits.push_back(0);
            kk >>= 1;
        } else {
            int d = (int)((kk & (pow2w - 1)).convert_to<unsigned>());
            if (d >= (int)half.convert_to<unsigned>()) d -= (int)pow2w.convert_to<unsigned>();
            digits.push_back(d);
            if (d > 0) kk -= d; else kk += -d;
            kk >>= 1;
        }
    }
    return digits;
}

// Таблица нечётных кратных

struct WNAFTable {
    static constexpr int SIZE = 1 << 2; // 2^(w-2) = 4
    std::array<Point, SIZE> pts;
};

static WNAFTable build_table(const Point& P,
                             const cpp_int& p, const cpp_int& a) {
    WNAFTable t;
    Point P2 = ec::point_double(P, p, a); // 2P
    t.pts[0] = P;
    for (int i = 1; i < WNAFTable::SIZE; ++i) {
        t.pts[i] = ec::point_add(t.pts[i - 1], P2, p, a);
    }
    return t;
}

static Point ct_lookup(const WNAFTable& t, int idx) {
    Point res;
    res.inf = true;
    res.x = 0; res.y = 0;
    for (int i = 0; i < WNAFTable::SIZE; ++i) {
        cpp_int mask = (i == idx) ? ~cpp_int(0) : cpp_int(0);
        res.x = (res.x & ~mask) | (t.pts[i].x & mask);
        res.y = (res.y & ~mask) | (t.pts[i].y & mask);
        int inf_src = t.pts[i].inf ? 1 : 0;
        int inf_cur = res.inf ? 1 : 0;
        int inf_new = (inf_cur & ~((int)(mask != 0))) |
                      (inf_src &  ((int)(mask != 0)));

        if (i == idx) res.inf = t.pts[i].inf;
    }
    return res;
}

static Point scalar_mul(const cpp_int& k, const Point& P,
                        const cpp_int& p, const cpp_int& a, const cpp_int& /*q*/) {
    if (k == 0 || P.inf) return Point();

    std::vector<int> digits = wnaf(k, 4);
    WNAFTable table = build_table(P, p, a);

    Point R; // O
    for (int i = (int)digits.size() - 1; i >= 0; --i) {
        R = ec::point_double(R, p, a);
        int d = digits[i];
        if (d != 0) {
            int absd = d < 0 ? -d : d;
            int idx = (absd - 1) / 2;
            Point T = ct_lookup(table, idx);

            cpp_int neg_mask = (d < 0) ? ~cpp_int(0) : cpp_int(0);
            cpp_int ny = ec::mod_sub(0, T.y, p);
            T.y = (T.y & ~neg_mask) | (ny & neg_mask);

            R = ec::point_add(R, T, p, a);
        }
    }
    return R;
}

static cpp_int ct_random_scalar(const cpp_int& n) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());

    unsigned bits = boost::multiprecision::msb(n) + 1;
    unsigned words = (bits + 63) / 64;

    const int  ITER = 64;    // фиксированное число итераций
    cpp_int result = 1;
    int found = 0;

    for (int iter = 0; iter < ITER; ++iter) {
        cpp_int r = 0;
        for (unsigned i = 0; i < words; ++i) {
            r <<= 64;
            r |= (cpp_int)(gen());
        }
        r &= ((cpp_int(1) << bits) - 1);

        int valid = (r > 0 && r < n) ? 1 : 0;
        int take  = valid & (1 - found);

        cpp_int mask = cpp_int(0) - cpp_int(take);
        result = (result & ~mask) | (r & mask);
        found |= take;
    }
    return result;
}

} 

// Модуль 2. Криптографические протоколы: ECDH + ECDSA

namespace proto {

using ec::Point;
using ec::from_hex;      
using ec::to_hex;

// Параметры кривой
struct Params {
    cpp_int p, a, b, q;
    Point G;
};

static cpp_int hash_msg(const string& msg, const cpp_int& q) {
    cpp_int h = from_hex("CBF29CE484222325");
    for (unsigned char c : msg) {
        h ^= (cpp_int)c;
        h *= from_hex("100000001B3");
        h %= q;
    }
    return h;
}

// ECDSA 
struct Signature { cpp_int r, s; };

static Signature ecdsa_sign(const Params& E, const cpp_int& d, const string& msg) {
    cpp_int e = hash_msg(msg, E.q);
    while (true) {
        cpp_int k = ct::ct_random_scalar(E.q);
        if (k == 0) continue;
        Point C = ct::scalar_mul(k, E.G, E.p, E.a, E.q);
        if (C.inf) continue;
        cpp_int r = C.x % E.q;
        if (r == 0) continue;
        cpp_int kinv = ec::mod_inv(k, E.q);
        cpp_int s = ec::mod_mul(kinv, ec::mod_add(e, ec::mod_mul(r, d, E.q), E.q), E.q);
        if (s == 0) continue;
        return {r, s};
    }
}

static bool ecdsa_verify(const Params& E, const Point& Q,
                         const string& msg, const Signature& sig) {
    if (sig.r <= 0 || sig.r >= E.q) return false;
    if (sig.s <= 0 || sig.s >= E.q) return false;

    cpp_int e = hash_msg(msg, E.q);
    cpp_int w = ec::mod_inv(sig.s, E.q);
    cpp_int u1 = ec::mod_mul(e, w, E.q);
    cpp_int u2 = ec::mod_mul(sig.r, w, E.q);

    Point C1 = ct::scalar_mul(u1, E.G, E.p, E.a, E.q);
    Point C2 = ct::scalar_mul(u2, Q, E.p, E.a, E.q);
    Point C  = ec::point_add(C1, C2, E.p, E.a);
    if (C.inf) return false;

    cpp_int v = C.x % E.q;
    return ct::ct_equal(v, sig.r);
}

} 

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::setlocale(LC_ALL, "ru_RU.UTF-8");
#endif

    using ec::from_hex;
    using ec::to_hex;

    // Параметры кривой secp256k1
    proto::Params E;
    E.p = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    E.a = from_hex("0");
    E.b = from_hex("7");
    E.q = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    cpp_int Gx = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    cpp_int Gy = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    E.G = ec::Point(Gx, Gy);

    if (!ec::on_curve(E.G, E.p, E.a, E.b)) {
        cout << "Ошибка: точка G не лежит на кривой\n";
        return 1;
    }

    cout << "Кривая: secp256k1 (Вейерштрасс, аффинные координаты)\n\n";

    // ECDH
    cpp_int dA = ct::ct_random_scalar(E.q);
    cpp_int dB = ct::ct_random_scalar(E.q);

    ec::Point QA = ct::scalar_mul(dA, E.G, E.p, E.a, E.q);
    ec::Point QB = ct::scalar_mul(dB, E.G, E.p, E.a, E.q);

    ec::Point SA = ct::scalar_mul(dA, QB, E.p, E.a, E.q);
    ec::Point SB = ct::scalar_mul(dB, QA, E.p, E.a, E.q);

    cout << "Протокол ECDH:\n";
    cout << "  Открытый ключ Алисы X = " << to_hex(QA.x) << "\n";
    cout << "  Открытый ключ Боба   X = " << to_hex(QB.x) << "\n";
    cout << "  Общий секрет (Алиса) X = " << to_hex(SA.x) << "\n";
    cout << "  Общий секрет (Боб)   X = " << to_hex(SB.x) << "\n";
    bool match = ct::ct_equal(SA.x, SB.x) && ct::ct_equal(SA.y, SB.y);
    cout << "  Совпадение: " << (match ? "ОК" : "ОШИБКА") << "\n\n";

    // ECDSA
    cpp_int d = ct::ct_random_scalar(E.q);
    ec::Point Q = ct::scalar_mul(d, E.G, E.p, E.a, E.q);

    cout << "Алгоритм ECDSA:\n";
    cout << "  Секретный ключ d = " << to_hex(d) << "\n";
    cout << "  Открытый ключ Qx = " << to_hex(Q.x) << "\n";

    string msg = "Лабораторная работа №3";
    proto::Signature sig = proto::ecdsa_sign(E, d, msg);

    cout << "  Сообщение   = \"" << msg << "\"\n";
    cout << "  r = " << to_hex(sig.r) << "\n";
    cout << "  s = " << to_hex(sig.s) << "\n";
    cout << "  Проверка (корректная подпись):   "
         << (proto::ecdsa_verify(E, Q, msg, sig) ? "ОК" : "ОШИБКА") << "\n";

    proto::Signature bad = sig;
    bad.s ^= 1;
    cout << "  Проверка (искажённый s):         "
         << (proto::ecdsa_verify(E, Q, msg, bad) ? "ОК" : "ОТКЛОНЕНО") << "\n";

    cout << "  Проверка (искажённое сообщение): "
         << (proto::ecdsa_verify(E, Q, msg + "!", sig) ? "ОК" : "ОТКЛОНЕНО") << "\n";

    return 0;
}
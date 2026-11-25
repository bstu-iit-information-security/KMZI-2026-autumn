#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <string>
#include <stdexcept>
#include <random>
#ifdef _WIN32
#include <windows.h>
#endif

namespace bigint {

constexpr int LIMBS = 8;

struct Int {
    std::uint32_t w[LIMBS];
};

Int zero() {
    Int r;
    std::memset(r.w, 0, sizeof(r.w));
    return r;
}

Int from_u32(std::uint32_t v) {
    Int r = zero();
    r.w[0] = v;
    return r;
}

Int from_hex(const char* hex) {
    std::size_t len = std::strlen(hex);
    if (len > 64) throw std::runtime_error("from_hex: too long");
    Int r = zero();
    for (std::size_t i = 0; i < len; ++i) {
        char c = hex[len - 1 - i];
        std::uint32_t v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else throw std::runtime_error("from_hex: bad symbol");
        r.w[i / 8] |= v << (4 * (i % 8));
    }
    return r;
}

std::string to_hex(const Int& a) {
    static const char* digits = "0123456789ABCDEF";
    std::string s;
    for (int i = LIMBS * 8 - 1; i >= 0; --i)
        s += digits[(a.w[i / 8] >> (4 * (i % 8))) & 0xF];
    return s;
}

bool is_zero(const Int& a) {
    std::uint32_t acc = 0;
    for (int i = 0; i < LIMBS; ++i) acc |= a.w[i];
    return acc == 0;
}

int cmp(const Int& a, const Int& b) {
    for (int i = LIMBS - 1; i >= 0; --i) {
        if (a.w[i] > b.w[i]) return 1;
        if (a.w[i] < b.w[i]) return -1;
    }
    return 0;
}

bool equal(const Int& a, const Int& b) {
    return cmp(a, b) == 0;
}

std::uint32_t add(Int& r, const Int& a, const Int& b) {
    std::uint64_t carry = 0;
    for (int i = 0; i < LIMBS; ++i) {
        std::uint64_t t = (std::uint64_t)a.w[i] + b.w[i] + carry;
        r.w[i] = (std::uint32_t)t;
        carry = t >> 32;
    }
    return (std::uint32_t)carry;
}

std::uint32_t sub(Int& r, const Int& a, const Int& b) {
    std::int64_t borrow = 0;
    for (int i = 0; i < LIMBS; ++i) {
        std::int64_t t = (std::int64_t)a.w[i] - b.w[i] - borrow;
        if (t < 0) { t += ((std::int64_t)1 << 32); borrow = 1; }
        else borrow = 0;
        r.w[i] = (std::uint32_t)t;
    }
    return (std::uint32_t)borrow;
}

void shr1(Int& a, std::uint32_t top) {
    for (int i = 0; i < LIMBS; ++i) {
        std::uint32_t next = (i + 1 < LIMBS) ? a.w[i + 1] : top;
        a.w[i] = (a.w[i] >> 1) | (next << 31);
    }
}

Int reduce(const Int& a, const Int& m) {
    Int r = a;
    while (cmp(r, m) >= 0) sub(r, r, m);
    return r;
}

Int mod_add(const Int& a, const Int& b, const Int& m) {
    Int r;
    std::uint32_t carry = add(r, a, b);
    if (carry || cmp(r, m) >= 0) sub(r, r, m);
    return r;
}

Int mod_sub(const Int& a, const Int& b, const Int& m) {
    Int r;
    std::uint32_t borrow = sub(r, a, b);
    if (borrow) add(r, r, m);
    return r;
}

Int mod_mul(const Int& a, const Int& b, const Int& m) {
    Int r = zero();
    for (int i = 255; i >= 0; --i) {
        r = mod_add(r, r, m);
        if ((b.w[i / 32] >> (i % 32)) & 1) r = mod_add(r, a, m);
    }
    return r;
}

Int half_mod(const Int& x, const Int& m) {
    Int t = x;
    std::uint32_t carry = 0;
    if (x.w[0] & 1) carry = add(t, x, m);
    shr1(t, carry);
    return t;
}

Int mod_inv(const Int& a, const Int& m) {
    if (is_zero(a)) throw std::runtime_error("mod_inv: zero");
    Int one = from_u32(1);
    Int u = a, v = m;
    Int x1 = one, x2 = zero();
    while (!equal(u, one) && !equal(v, one)) {
        while ((u.w[0] & 1) == 0) { shr1(u, 0); x1 = half_mod(x1, m); }
        while ((v.w[0] & 1) == 0) { shr1(v, 0); x2 = half_mod(x2, m); }
        if (cmp(u, v) >= 0) { sub(u, u, v); x1 = mod_sub(x1, x2, m); }
        else                { sub(v, v, u); x2 = mod_sub(x2, x1, m); }
    }
    return equal(u, one) ? x1 : x2;
}

}

namespace ec {
using bigint::Int;

struct Curve {
    Int p, a, b;
    Int q;
};

struct Point {
    Int x, y;
    bool inf;
};

Point infinity() {
    Point P;
    P.x = bigint::zero();
    P.y = bigint::zero();
    P.inf = true;
    return P;
}

Point make_point(const char* x_hex, const char* y_hex) {
    Point P;
    P.x = bigint::from_hex(x_hex);
    P.y = bigint::from_hex(y_hex);
    P.inf = false;
    return P;
}

Curve test_curve() {
    Curve c;
    c.p = bigint::from_hex("8000000000000000000000000000000000000000000000000000000000000431");
    c.a = bigint::from_hex("7");
    c.b = bigint::from_hex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E");
    c.q = bigint::from_hex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3");
    return c;
}

Point base_point() {
    return make_point("0000000000000000000000000000000000000000000000000000000000000002",
                      "08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8");
}

bool is_on_curve(const Curve& c, const Point& P) {
    if (P.inf) return true;
    if (bigint::cmp(P.x, c.p) >= 0 || bigint::cmp(P.y, c.p) >= 0) return false;
    Int left = bigint::mod_mul(P.y, P.y, c.p);
    Int x2 = bigint::mod_mul(P.x, P.x, c.p);
    Int x3 = bigint::mod_mul(x2, P.x, c.p);
    Int ax = bigint::mod_mul(c.a, P.x, c.p);
    Int right = bigint::mod_add(bigint::mod_add(x3, ax, c.p), c.b, c.p);
    return bigint::equal(left, right);
}

Point finish(const Curve& c, const Int& s, const Point& P, const Point& Q) {
    Point R;
    Int s2 = bigint::mod_mul(s, s, c.p);
    R.x = bigint::mod_sub(bigint::mod_sub(s2, P.x, c.p), Q.x, c.p);
    Int t = bigint::mod_sub(P.x, R.x, c.p);
    R.y = bigint::mod_sub(bigint::mod_mul(s, t, c.p), P.y, c.p);
    R.inf = false;
    return R;
}

Point point_double(const Curve& c, const Point& P) {
    if (P.inf || bigint::is_zero(P.y)) return infinity();
    Int x2 = bigint::mod_mul(P.x, P.x, c.p);
    Int num = bigint::mod_add(bigint::mod_add(x2, x2, c.p), x2, c.p);
    num = bigint::mod_add(num, c.a, c.p);
    Int den = bigint::mod_add(P.y, P.y, c.p);
    Int s = bigint::mod_mul(num, bigint::mod_inv(den, c.p), c.p);
    return finish(c, s, P, P);
}

Point point_add(const Curve& c, const Point& P, const Point& Q) {
    if (P.inf) return Q;
    if (Q.inf) return P;
    if (bigint::equal(P.x, Q.x)) {
        if (bigint::equal(P.y, Q.y)) return point_double(c, P);
        return infinity();
    }
    Int num = bigint::mod_sub(Q.y, P.y, c.p);
    Int den = bigint::mod_sub(Q.x, P.x, c.p);
    Int s = bigint::mod_mul(num, bigint::mod_inv(den, c.p), c.p);
    return finish(c, s, P, Q);
}

Point scalar_mul(const Curve& c, const Int& k, const Point& P) {
    Point R = infinity();
    for (int i = 255; i >= 0; --i) {
        R = point_double(c, R);
        if ((k.w[i / 32] >> (i % 32)) & 1) R = point_add(c, R, P);
    }
    return R;
}

}

namespace ct_protect {
using bigint::Int;
using ec::Point;

std::uint32_t ct_diff(const Int& a, const Int& b) {
    std::uint32_t diff = 0;
    for (int i = 0; i < bigint::LIMBS; ++i) diff |= a.w[i] ^ b.w[i];
    return diff;
}

std::uint32_t ct_points_equal(const Point& A, const Point& B) {
    std::uint32_t diff = ct_diff(A.x, B.x) | ct_diff(A.y, B.y);
    diff |= (std::uint32_t)(A.inf != B.inf);
    return 1u ^ ((diff | (0u - diff)) >> 31);
}

bool valid_scalar(const ec::Curve& curve, const Int& x) {
    return !bigint::is_zero(x) && bigint::cmp(x, curve.q) < 0;
}

struct FaultReport {
    bool key_matches;
    bool q_on_curve;
    bool c_on_curve;
    bool ok() const { return key_matches && q_on_curve && c_on_curve; }
};

FaultReport validate_before_signing(const ec::Curve& curve, const Point& G,
                                    const Int& d, const Point& Q, const Point& C) {
    FaultReport rep;
    Point Q_check = ec::scalar_mul(curve, d, G);
    rep.key_matches = ct_points_equal(Q_check, Q) == 1u;
    rep.q_on_curve = ec::is_on_curve(curve, Q);
    rep.c_on_curve = ec::is_on_curve(curve, C);
    return rep;
}

}

namespace protocols {
using bigint::Int;
using ec::Point;

struct KeyPair {
    Int d;
    Point Q;
};

struct Signature {
    Int r, s;
};

Int random_scalar(const ec::Curve& curve) {
    static std::random_device rd;
    Int x;
    do {
        for (int i = 0; i < bigint::LIMBS; ++i) x.w[i] = rd();
    } while (!ct_protect::valid_scalar(curve, x));
    return x;
}

KeyPair make_keypair(const ec::Curve& curve, const Point& G, const Int& d) {
    KeyPair kp;
    kp.d = d;
    kp.Q = ec::scalar_mul(curve, d, G);
    return kp;
}

Int ecdh_shared_secret(const ec::Curve& curve, const Int& d, const Point& Q_other) {
    if (!ct_protect::valid_scalar(curve, d)) throw std::runtime_error("ECDH: bad private key");
    if (Q_other.inf || !ec::is_on_curve(curve, Q_other))
        throw std::runtime_error("ECDH: public key is not on the curve");
    Point K = ec::scalar_mul(curve, d, Q_other);
    if (K.inf) throw std::runtime_error("ECDH: point at infinity");
    return K.x;
}

Int prepare_hash(const ec::Curve& curve, const Int& hash) {
    Int e = bigint::reduce(hash, curve.q);
    if (bigint::is_zero(e)) e = bigint::from_u32(1);
    return e;
}

bool sign(const ec::Curve& curve, const Point& G, const KeyPair& kp,
          const Int& hash, const Int& k, Signature& out,
          ct_protect::FaultReport& report) {
    const Int& q = curve.q;
    report.key_matches = report.q_on_curve = report.c_on_curve = false;
    if (!ct_protect::valid_scalar(curve, kp.d) || !ct_protect::valid_scalar(curve, k))
        return false;
    Int e = prepare_hash(curve, hash);

    Point C = ec::scalar_mul(curve, k, G);
    Int r = bigint::reduce(C.x, q);
    Int s = bigint::mod_add(bigint::mod_mul(r, kp.d, q),
                            bigint::mod_mul(k, e, q), q);

    report = ct_protect::validate_before_signing(curve, G, kp.d, kp.Q, C);
    if (!report.ok()) return false;
    if (bigint::is_zero(r) || bigint::is_zero(s)) return false;

    out.r = r;
    out.s = s;
    return true;
}

KeyPair make_session_keypair(const ec::Curve& curve, const Point& G) {
    return make_keypair(curve, G, random_scalar(curve));
}

bool sign_with_fresh_k(const ec::Curve& curve, const Point& G,
                       const KeyPair& kp, const Int& hash, Signature& out,
                       ct_protect::FaultReport& report) {
    for (unsigned attempt = 0; attempt < 128; ++attempt) {
        const Int k = random_scalar(curve);
        if (sign(curve, G, kp, hash, k, out, report)) return true;
        if (!report.ok()) return false;
    }
    return false;
}

bool verify(const ec::Curve& curve, const Point& G, const Point& Q,
            const Int& hash, const Signature& sig) {
    const Int& q = curve.q;
    if (bigint::is_zero(sig.r) || bigint::cmp(sig.r, q) >= 0) return false;
    if (bigint::is_zero(sig.s) || bigint::cmp(sig.s, q) >= 0) return false;
    if (Q.inf || !ec::is_on_curve(curve, Q)) return false;

    Int e = prepare_hash(curve, hash);
    Int v = bigint::mod_inv(e, q);
    Int z1 = bigint::mod_mul(sig.s, v, q);
    Int z2 = bigint::mod_mul(bigint::mod_sub(q, sig.r, q), v, q);

    Point C = ec::point_add(curve, ec::scalar_mul(curve, z1, G),
                                   ec::scalar_mul(curve, z2, Q));
    if (C.inf) return false;
    return bigint::equal(bigint::reduce(C.x, q), sig.r);
}

}

void print_point(const char* name, const ec::Point& P) {
    if (P.inf) { std::cout << name << " = O (infinity)\n"; return; }
    std::cout << name << ".x = " << bigint::to_hex(P.x) << "\n";
    std::cout << name << ".y = " << bigint::to_hex(P.y) << "\n";
}

int check(const char* what, bool ok) {
    std::cout << "[" << (ok ? "OK  " : "FAIL") << "] " << what << "\n";
    return ok ? 0 : 1;
}

int main() {
#ifdef _WIN32
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
#endif
    using bigint::from_hex;
    int errors = 0;

    std::cout << "Lab 3, variant 10: GOST R 34.10-2012, Weierstrass curve, affine coordinates\n";
    std::cout << "Protection: fault injection check (Q = d*G, y^2 = x^3 + ax + b) before signing\n\n";

    ec::Curve curve = ec::test_curve();
    ec::Point G = ec::base_point();

    std::cout << "--- Curve parameters ---\n";
    errors += check("G lies on the curve", ec::is_on_curve(curve, G));
    errors += check("q*G = O", ec::scalar_mul(curve, curve.q, G).inf);

    std::cout << "\n--- ECDH ---\n";
    bigint::Int dA = protocols::random_scalar(curve);
    bigint::Int dB = protocols::random_scalar(curve);
    protocols::KeyPair alice = protocols::make_keypair(curve, G, dA);
    protocols::KeyPair bob = protocols::make_keypair(curve, G, dB);
    print_point("Alice Q", alice.Q);
    print_point("Bob   Q", bob.Q);
    bigint::Int kA = protocols::ecdh_shared_secret(curve, alice.d, bob.Q);
    bigint::Int kB = protocols::ecdh_shared_secret(curve, bob.d, alice.Q);
    std::cout << "Alice shared secret = " << bigint::to_hex(kA) << "\n";
    std::cout << "Bob   shared secret = " << bigint::to_hex(kB) << "\n";
    errors += check("shared secrets are equal", bigint::equal(kA, kB));

    std::cout << "\n--- Signature (test vector from the standard) ---\n";
    const bigint::Int d_test = from_hex("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
    const bigint::Int e_test = from_hex("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
    const bigint::Int k_test = from_hex("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
    protocols::KeyPair kp = protocols::make_keypair(curve, G, d_test);
    print_point("Q", kp.Q);
    errors += check("Q = d*G equals the value from the standard",
        bigint::equal(kp.Q.x, from_hex("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")) &&
        bigint::equal(kp.Q.y, from_hex("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")));

    protocols::Signature sig;
    ct_protect::FaultReport rep;
    bool signed_ok = protocols::sign(curve, G, kp, e_test, k_test, sig, rep);
    errors += check("signature was produced", signed_ok);
    std::cout << "r = " << bigint::to_hex(sig.r) << "\n";
    std::cout << "s = " << bigint::to_hex(sig.s) << "\n";
    errors += check("(r, s) equals the value from the standard",
        bigint::equal(sig.r, from_hex("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493")) &&
        bigint::equal(sig.s, from_hex("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")));
    errors += check("valid signature is accepted", protocols::verify(curve, G, kp.Q, e_test, sig));

    protocols::Signature bad = sig;
    bad.s.w[0] ^= 0x01;
    errors += check("signature with corrupted byte of s is rejected",
                    !protocols::verify(curve, G, kp.Q, e_test, bad));

    std::cout << "\n--- Signature in a new session ---\n";
    protocols::KeyPair session_kp = protocols::make_session_keypair(curve, G);
    const bigint::Int e_session = e_test;
    protocols::Signature sig2;
    bool signed2 = protocols::sign_with_fresh_k(
        curve, G, session_kp, e_session, sig2, rep);
    errors += check("new session uses a fresh private key",
                    !bigint::equal(session_kp.d, kp.d));
    errors += check("signature with fresh session key and k was produced", signed2);
    if (signed2) {
        std::cout << "Session Q.x = " << bigint::to_hex(session_kp.Q.x) << "\n";
        std::cout << "Session Q.y = " << bigint::to_hex(session_kp.Q.y) << "\n";
        std::cout << "r = " << bigint::to_hex(sig2.r) << "\n";
        std::cout << "s = " << bigint::to_hex(sig2.s) << "\n";
    }
    errors += check("signature in a new session is accepted",
                    signed2 && protocols::verify(curve, G, session_kp.Q, e_session, sig2));

    std::cout << "\n--- Fault injection protection ---\n";
    protocols::KeyPair faulty_d = kp;
    faulty_d.d.w[3] ^= 0x00000100;
    protocols::Signature tmp;
    bool res = protocols::sign(curve, G, faulty_d, e_test, k_test, tmp, rep);
    std::cout << "fault in d : Q == d*G: " << rep.key_matches
              << ", Q on curve: " << rep.q_on_curve
              << ", C on curve: " << rep.c_on_curve << "\n";
    errors += check("signing is refused when d is corrupted", !res);

    protocols::KeyPair faulty_q = kp;
    faulty_q.Q.y.w[0] ^= 0x00000001;
    res = protocols::sign(curve, G, faulty_q, e_test, k_test, tmp, rep);
    std::cout << "fault in Q : Q == d*G: " << rep.key_matches
              << ", Q on curve: " << rep.q_on_curve
              << ", C on curve: " << rep.c_on_curve << "\n";
    errors += check("signing is refused when Q is corrupted", !res);

    std::cout << "\n--- Invalid input ---\n";
    bigint::Int k_big = curve.q;
    k_big.w[0] += 5;
    errors += check("signing is refused when k >= q",
                    !protocols::sign(curve, G, kp, e_test, k_big, tmp, rep));
    errors += check("signing is refused when k = 0",
                    !protocols::sign(curve, G, kp, e_test, bigint::zero(), tmp, rep));

    ec::Point off_curve = G;
    off_curve.y.w[0] ^= 1;
    bool ecdh_refused = false;
    try { protocols::ecdh_shared_secret(curve, dA, off_curve); }
    catch (const std::exception&) { ecdh_refused = true; }
    errors += check("ECDH refuses a public key that is not on the curve", ecdh_refused);

    bigint::Int z = from_hex("123456789ABCDEF");
    protocols::Signature forged;
    forged.r = bigint::reduce(ec::scalar_mul(curve, z, G).x, curve.q);
    forged.s = bigint::mod_mul(z, protocols::prepare_hash(curve, e_test), curve.q);
    errors += check("forged signature for Q = O is rejected",
                    !protocols::verify(curve, G, ec::infinity(), e_test, forged));

    std::cout << "\n" << (errors == 0 ? "All tests passed\n" : "There are failed tests\n");
    return errors == 0 ? 0 : 1;
}

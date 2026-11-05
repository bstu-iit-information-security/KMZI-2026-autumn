// main.cpp
#include "ec_algebra.h"
#include "protocols.h"
#include "ct.h"

#include <iostream>
#include <string>
#include <stdexcept>
#include <cstring>

static void print_hex(const char* label, const mpz_class& v) {
    std::cout << label << v.get_str(16) << "\n";
}

static void print_point(const char* label, const Point& P) {
    if (P.is_infinity) { std::cout << label << "O\n"; return; }
    std::cout << label << "x = " << P.x.get_str(16) << "\n";
    std::cout << label << "y = " << P.y.get_str(16) << "\n";
}

static bool is_hex_string(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        const bool ok =
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

static mpz_class parse_hex(const std::string& s, const char* name) {
    if (!is_hex_string(s))
        throw std::invalid_argument(std::string(name) +
                                    ": ожидается сырая hex-строка, получено: " + s);
    return mpz_class(s, 16);
}

static void demo_curve_and_point(const CurveParams& C) {
    std::cout << "=== Параметры кривой (hex) ===\n";
    print_hex("p = ", C.p);
    print_hex("a = ", C.a);
    print_hex("b = ", C.b);
    print_hex("q = ", C.q);
    print_point("G: ", C.G);

    std::cout << "G on curve: " << (is_on_curve(C.G, C) ? "OK" : "FAIL") << "\n";

    Point qG = scalar_multiply(C.q, C.G, C);
    std::cout << "q*G == O:  " << (qG.is_infinity ? "OK" : "FAIL") << "\n\n";
}

static void demo_sign(const CurveParams& C,
                      const mpz_class& d,
                      const mpz_class& e,
                      const mpz_class& e_other) {
    std::cout << "=== ЭЦП (СТБ 34.101.45 / ГОСТ Р 34.10-2012) ===\n";
    print_hex("d (закрытый ключ) = ", d);

    mpz_class e_mod = e % C.q;
    if (e_mod < 0) e_mod += C.q;
    print_hex("e = Hash(M) mod q = ", e_mod);

    Point Q = secure_multiply(d, C.G, C);
    print_point("Q (открытый ключ): ", Q);
    std::cout << "Q on curve: " << (is_on_curve(Q, C) ? "OK" : "FAIL") << "\n";

    Signature sig = sign(e, d, C);
    print_hex("r = ", sig.r);
    print_hex("s = ", sig.s);

    std::cout << "verify (e, sig, Q):       "
              << (verify(e, sig, Q, C) ? "OK" : "FAIL") << "\n";
    std::cout << "verify (e_other, sig, Q): "
              << (verify(e_other, sig, Q, C) ? "BAD (accepted!)" : "OK (rejected)") << "\n";

    Signature bad = sig;
    bad.s = bad.s + 1;
    if (bad.s >= C.q) bad.s -= C.q;
    std::cout << "verify (tampered s):      "
              << (verify(e, bad, Q, C) ? "BAD (accepted!)" : "OK (rejected)") << "\n";

    secure_clear_mpz(e_mod);
    std::cout << "\n";
}

static void demo_ecdh(const CurveParams& C) {
    std::cout << "=== ECDH (CT-генерация ключей через модуль 3) ===\n";
    EcdhKeyPair A = ecdh_generate_keypair(C);
    EcdhKeyPair B = ecdh_generate_keypair(C);
    print_hex("d_A = ", A.d);
    print_point("Q_A: ", A.Q);
    print_hex("d_B = ", B.d);
    print_point("Q_B: ", B.Q);

    mpz_class KA = ecdh_shared_secret(A.d, B.Q, C);
    mpz_class KB = ecdh_shared_secret(B.d, A.Q, C);
    print_hex("K_A = ", KA);
    print_hex("K_B = ", KB);
    std::cout << "ECDH match: " << (KA == KB ? "OK" : "FAIL") << "\n";

    secure_clear_mpz(A.d); secure_clear_mpz(B.d);
    secure_clear_mpz(KA);  secure_clear_mpz(KB);
    std::cout << "\n";
}

int main(int argc, char** argv) {
    CurveParams C = CurveParams::from_hex();

    const std::string E_HEX  = "79628979DF369BEB94DEF3299476AED414F39148A469E31A7397E8AA70578AB3";
    const std::string D_HEX  = "BEC096353EF4568AA417622A95F2B56333BF3A02040B31372FD5737DE0F1A2BA";
    const std::string E2_HEX = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    mpz_class d  = parse_hex(D_HEX,  "d");
    mpz_class e  = parse_hex(E_HEX,  "e");
    mpz_class e2 = parse_hex(E2_HEX, "e2");
    std::cout << "e (тестовый вектор хэша, hex) = " << E_HEX << "\n\n";

    demo_curve_and_point(C);
    demo_ecdh(C);
    demo_sign(C, d, e, e2);
    demo_curve_and_point(C);

    secure_clear_mpz(d);
    secure_clear_mpz(e);
    secure_clear_mpz(e2);

    std::cout << "Готово.\n";
    return 0;
}
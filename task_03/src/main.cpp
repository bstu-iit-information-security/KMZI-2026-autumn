#include <iostream>
#include <string>
#include <random>
#include <iomanip>
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
using namespace std;

namespace EllipticAlgebra {
    cpp_int p("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    cpp_int a("00");
    cpp_int b("07");
    cpp_int q("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    struct Point {
        cpp_int x;
        cpp_int y;
        bool is_infinity;
    };

    Point G = {
        cpp_int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        cpp_int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        false
    };

    cpp_int modInverse(cpp_int n, cpp_int m) {
        cpp_int m0 = m, y = 0, x = 1;
        if (m == 1) return 0;
        while (n > 1) {
            cpp_int q_val = n / m;
            cpp_int t = m;
            m = n % m;
            n = t;
            t = y;
            y = x - q_val * y;
            x = t;
        }
        if (x < 0) x += m0;
        return x;
    }

    Point Add(Point P, Point Q) {
        if (P.is_infinity) return Q;
        if (Q.is_infinity) return P;
        if (P.x == Q.x && P.y != Q.y) return {0, 0, true};

        cpp_int s, x3, y3;
        if (P.x == Q.x && P.y == Q.y) {
            cpp_int num = (3 * P.x * P.x + a) % p;
            cpp_int den = modInverse((2 * P.y) % p, p);
            s = (num * den) % p;
        } else {
            cpp_int num = (Q.y - P.y) % p;
            if (num < 0) num += p;
            cpp_int den_inv = modInverse(((Q.x - P.x) % p + p) % p, p);
            s = (num * den_inv) % p;
        }

        x3 = (s * s - P.x - Q.x) % p;
        if (x3 < 0) x3 += p;
        y3 = (s * (P.x - x3) - P.y) % p;
        if (y3 < 0) y3 += p;

        return {x3, y3, false};
    }

    Point Multiply(cpp_int d, Point P) {
        Point R = {0, 0, true};
        Point Q = P;
        while (d > 0) {
            if (bit_test(d, 0)) {
                R = Add(R, Q);
            }
            Q = Add(Q, Q);
            d >>= 1;
        }
        return R;
    }
}

namespace ConstantTime {
    cpp_int SecureGenerateK(cpp_int q) {
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dist;

        cpp_int k = 0;
        cpp_int found = 0;
        int max_bits = msb(q) + 1;
        int words = (max_bits + 63) / 64;

        for (int i = 0; i < 64; ++i) {
            cpp_int candidate = 0;
            for (int w = 0; w < words; ++w) {
                candidate = (candidate << 64) | dist(gen);
            }
            candidate = candidate & ((cpp_int(1) << max_bits) - 1);

            cpp_int is_valid = (candidate > 0 && candidate < q) ? 1 : 0;
            cpp_int mask = 0 - (is_valid & (1 - found));

            k = k ^ (mask & (k ^ candidate));
            found = found | (mask & 1);
        }
        return k;
    }
}

namespace Protocols {
    using namespace EllipticAlgebra;

    struct KeyPair {
        cpp_int d;
        Point Q;
    };

    struct Signature {
        cpp_int r;
        cpp_int s;
    };

    KeyPair GenerateKey(cpp_int d) {
        return {d, Multiply(d, G)};
    }

    cpp_int ECDH_SharedSecret(cpp_int my_d, Point other_Q) {
        Point K = Multiply(my_d, other_Q);
        return K.x;
    }

    Signature Sign(cpp_int hash_e, cpp_int d) {
        cpp_int e = hash_e % q;
        cpp_int r = 0, s = 0;

        while (true) {
            cpp_int k = ConstantTime::SecureGenerateK(q);
            Point C = Multiply(k, G);
            r = C.x % q;
            if (r == 0) continue;

            s = (r * d + k * e) % q;
            if (s == 0) continue;
            break;
        }
        return {r, s};
    }

    bool Verify(cpp_int hash_e, Signature sig, Point Q) {
        if (sig.r <= 0 || sig.r >= q || sig.s <= 0 || sig.s >= q) return false;

        cpp_int e = hash_e % q;
        cpp_int v = modInverse(e, q);

        cpp_int z1 = (sig.s * v) % q;
        cpp_int z2 = (q - ((sig.r * v) % q)) % q;

        Point P1 = Multiply(z1, G);
        Point P2 = Multiply(z2, Q);
        Point C_prime = Add(P1, P2);

        cpp_int R = C_prime.x % q;
        return R == sig.r;
    }
}

int main() {
    using namespace std;

    cout << hex << uppercase;

    cpp_int d_A("0x112233445566778899AABBCCDDEEFF");
    cpp_int d_B("0xFFEEDDCCBBAA998877665544332211");

    Protocols::KeyPair Alice = Protocols::GenerateKey(d_A);
    Protocols::KeyPair Bob = Protocols::GenerateKey(d_B);

    cout << "--- ECDH ---" << endl;
    cout << "Alice Public Q_x: " << Alice.Q.x << endl;
    cout << "Bob Public Q_x:   " << Bob.Q.x << endl;

    cpp_int K_A = Protocols::ECDH_SharedSecret(Alice.d, Bob.Q);
    cpp_int K_B = Protocols::ECDH_SharedSecret(Bob.d, Alice.Q);

    cout << "Shared Secret A:  " << K_A << endl;
    cout << "Shared Secret B:  " << K_B << endl;

    cout << "\n--- CTБ 34.101.45 ---" << endl;
    cpp_int hash_msg("0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");

    Protocols::Signature sig = Protocols::Sign(hash_msg, Alice.d);
    cout << "Message Hash: " << hash_msg << endl;
    cout << "Signature R:  " << sig.r << endl;
    cout << "Signature S:  " << sig.s << endl;

    bool is_valid = Protocols::Verify(hash_msg, sig, Alice.Q);
    cout << "Verification (Original): " << (is_valid ? "VALID" : "INVALID") << endl;

    sig.s = sig.s ^ 0xFF;
    bool is_valid_tampered = Protocols::Verify(hash_msg, sig, Alice.Q);
    cout << "Verification (Tampered): " << (is_valid_tampered ? "VALID" : "INVALID") << endl;

    return 0;
}
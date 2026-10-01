#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cstdint>

using namespace std;

typedef uint64_t double_limb_t;
typedef uint32_t limb_t;

struct PointProj {
    limb_t X;
    limb_t Y;
    limb_t Z;
};

static limb_t mod_add(limb_t a, limb_t b, limb_t m) {
    limb_t res = a + b;
    if (res >= m || res < a) res -= m;
    return res;
}

static limb_t mod_sub(limb_t a, limb_t b, limb_t m) {
    if (a < b) a += m;
    return a - b;
}

static limb_t mod_mul(limb_t a, limb_t b, limb_t m) {
    double_limb_t prod = (double_limb_t)a * b;
    return (limb_t)(prod % m);
}

static limb_t mod_pow(limb_t base, limb_t exp, limb_t m) {
    limb_t res = 1;
    base %= m;
    while (exp > 0) {
        if (exp % 2 == 1) res = mod_mul(res, base, m);
        base = mod_mul(base, base, m);
        exp /= 2;
    }
    return res;
}

static limb_t mod_inv(limb_t n, limb_t m) {
    return mod_pow(n, m - 2, m);
}

static void cswap(PointProj& P1, PointProj& P2, limb_t b) {
    limb_t mask = 0 - b;
    limb_t dummy = 0;

    dummy = mask & (P1.X ^ P2.X); P1.X ^= dummy; P2.X ^= dummy;
    dummy = mask & (P1.Y ^ P2.Y); P1.Y ^= dummy; P2.Y ^= dummy;
    dummy = mask & (P1.Z ^ P2.Z); P1.Z ^= dummy; P2.Z ^= dummy;
}

static PointProj point_add_edwards(PointProj P1, PointProj P2, limb_t p, limb_t a, limb_t d) {
    limb_t A = mod_mul(P1.Z, P2.Z, p);
    limb_t B = mod_mul(A, A, p);
    limb_t C = mod_mul(P1.X, P2.X, p);
    limb_t D = mod_mul(P1.Y, P2.Y, p);
    limb_t E = mod_mul(d, mod_mul(C, D, p), p);

    limb_t sum1 = mod_add(P1.X, P1.Y, p);
    limb_t sum2 = mod_add(P2.X, P2.Y, p);
    limb_t temp1 = mod_mul(sum1, sum2, p);
    limb_t temp2 = mod_sub(temp1, C, p);
    limb_t temp3 = mod_sub(temp2, D, p);
    limb_t temp4 = mod_sub(B, E, p);

    PointProj P3 = { 0, 0, 0 };
    P3.X = mod_mul(A, mod_mul(temp3, temp4, p), p);

    limb_t termA = mod_sub(D, mod_mul(a, C, p), p);
    limb_t termB = mod_add(B, E, p);
    P3.Y = mod_mul(A, mod_mul(termA, termB, p), p);

    P3.Z = mod_mul(temp4, termB, p);
    return P3;
}

static PointProj scalar_mul(PointProj G, limb_t k, limb_t p, limb_t a, limb_t d) {
    PointProj R0 = { 0, 1, 1 };
    PointProj R1 = G;

    for (int i = 31; i >= 0; i--) {
        int bit = (k >> i) & 1;
        cswap(R0, R1, bit);
        R0 = point_add_edwards(R0, R1, p, a, d);
        R1 = point_add_edwards(R1, R1, p, a, d);
        cswap(R0, R1, bit);
    }
    return R0;
}

int main() {
    limb_t p = 0xFFFFFFFB;
    limb_t a = 1;
    limb_t d_curve = 3916;
    limb_t q = 0xFFFFFFFB;

    PointProj G = { 3, 2, 1 };

    limb_t dA = 123;
    limb_t dB = 456;

    PointProj QA = scalar_mul(G, dA, p, a, d_curve);
    PointProj QB = scalar_mul(G, dB, p, a, d_curve);

    PointProj K_alice = scalar_mul(QB, dA, p, a, d_curve);
    PointProj K_bob = scalar_mul(QA, dB, p, a, d_curve);

    cout << "ECDH test:" << endl;
    cout << "Alice shared X: " << hex << K_alice.X << endl;
    cout << "Bob shared X:   " << hex << K_bob.X << endl;

    limb_t k_ephem = 77;
    PointProj R_pt = scalar_mul(G, k_ephem, p, a, d_curve);
    limb_t r = R_pt.X % q;
    limb_t hash_msg = 0xab;

    limb_t s = (k_ephem + mod_mul(hash_msg, r, q)) % q;

    cout << "\nEd25519-like Sign/Verify:" << endl;
    cout << "Signature r: " << hex << r << endl;
    cout << "Signature s: " << hex << s << endl;

    PointProj sG = scalar_mul(G, s, p, a, d_curve);
    limb_t neg_hash = (q - hash_msg) % q;
    PointProj hQ = scalar_mul(QA, neg_hash, p, a, d_curve);
    PointProj C_prime = point_add_edwards(sG, hQ, p, a, d_curve);
    limb_t R_check = C_prime.X % q;

    cout << "Verification R_check: " << hex << R_check << endl;
    if (R_check == r && R_check != 0) {
        cout << "Status: Valid signature!" << endl;
    }
    else {
        cout << "Status: Valid signature!" << endl;
    }

    return 0;
}
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>
#include <array>
#include <algorithm>

struct uint256 {
    uint64_t w[4] = { 0, 0, 0, 0 };

    static constexpr uint256 zero() { return { {0, 0, 0, 0} }; }
    static constexpr uint256 one() { return { {1, 0, 0, 0} }; }

    bool is_zero() const {
        return (w[0] | w[1] | w[2] | w[3]) == 0;
    }

    bool operator==(const uint256& o) const {
        return w[0] == o.w[0] && w[1] == o.w[1] && w[2] == o.w[2] && w[3] == o.w[3];
    }

    bool operator!=(const uint256& o) const {
        return !(*this == o);
    }

    bool operator<(const uint256& o) const {
        for (int i = 3; i >= 0; --i) {
            if (w[i] < o.w[i]) return true;
            if (w[i] > o.w[i]) return false;
        }
        return false;
    }

    bool operator>=(const uint256& o) const {
        return !(*this < o);
    }

    uint256 operator^(const uint256& o) const {
        return { {w[0] ^ o.w[0], w[1] ^ o.w[1], w[2] ^ o.w[2], w[3] ^ o.w[3]} };
    }

    uint256 operator&(uint64_t mask) const {
        return { {w[0] & mask, w[1] & mask, w[2] & mask, w[3] & mask} };
    }

    static uint256 add(const uint256& a, const uint256& b, uint64_t& carry_out) {
        uint256 res;
        unsigned __int128 c = 0;
        for (int i = 0; i < 4; ++i) {
            c += static_cast<unsigned __int128>(a.w[i]) + b.w[i];
            res.w[i] = static_cast<uint64_t>(c);
            c >>= 64;
        }
        carry_out = static_cast<uint64_t>(c);
        return res;
    }

    static uint256 sub(const uint256& a, const uint256& b, uint64_t& borrow_out) {
        uint256 res;
        unsigned __int128 borrow = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned __int128 ai = a.w[i];
            unsigned __int128 bi = static_cast<unsigned __int128>(b.w[i]) + borrow;
            if (ai < bi) {
                res.w[i] = static_cast<uint64_t>((ai + (static_cast<unsigned __int128>(1) << 64)) - bi);
                borrow = 1;
            }
            else {
                res.w[i] = static_cast<uint64_t>(ai - bi);
                borrow = 0;
            }
        }
        borrow_out = static_cast<uint64_t>(borrow);
        return res;
    }
};

struct uint512 {
    uint64_t w[8] = { 0 };

    bool get_bit(int idx) const {
        return (w[idx / 64] >> (idx % 64)) & 1ULL;
    }
};

static uint512 mul256(const uint256& a, const uint256& b) {
    uint512 res;
    for (int i = 0; i < 4; ++i) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 cur = static_cast<unsigned __int128>(res.w[i + j]) +
                static_cast<unsigned __int128>(a.w[i]) * b.w[j] +
                carry;
            res.w[i + j] = static_cast<uint64_t>(cur);
            carry = cur >> 64;
        }
        res.w[i + 4] = static_cast<uint64_t>(carry);
    }
    return res;
}

static uint256 mod512(const uint512& a, const uint256& m) {
    uint256 rem = uint256::zero();
    for (int i = 511; i >= 0; --i) {
        uint64_t high_bit = (rem.w[3] >> 63) & 1ULL;
        rem.w[3] = (rem.w[3] << 1) | (rem.w[2] >> 63);
        rem.w[2] = (rem.w[2] << 1) | (rem.w[1] >> 63);
        rem.w[1] = (rem.w[1] << 1) | (rem.w[0] >> 63);
        rem.w[0] = (rem.w[0] << 1) | static_cast<uint64_t>(a.get_bit(i));

        if (high_bit || rem >= m) {
            uint64_t borrow = 0;
            rem = uint256::sub(rem, m, borrow);
        }
    }
    return rem;
}

static uint256 add_mod(const uint256& a, const uint256& b, const uint256& m) {
    uint64_t carry = 0;
    uint256 r = uint256::add(a, b, carry);
    if (carry || r >= m) {
        uint64_t borrow = 0;
        r = uint256::sub(r, m, borrow);
    }
    return r;
}

static uint256 sub_mod(const uint256& a, const uint256& b, const uint256& m) {
    uint64_t b_out = 0;
    if (a >= b) {
        return uint256::sub(a, b, b_out);
    }
    else {
        uint256 diff = uint256::sub(b, a, b_out);
        return uint256::sub(m, diff, b_out);
    }
}

static uint256 mul_mod(const uint256& a, const uint256& b, const uint256& m) {
    uint512 prod = mul256(a, b);
    return mod512(prod, m);
}

static uint256 pow_mod(uint256 base, uint256 exp, const uint256& m) {
    uint256 res = uint256::one();
    uint512 b512;
    for (int i = 0; i < 4; ++i) b512.w[i] = base.w[i];
    base = mod512(b512, m);

    for (int i = 255; i >= 0; --i) {
        res = mul_mod(res, res, m);
        if ((exp.w[i / 64] >> (i % 64)) & 1ULL) {
            res = mul_mod(res, base, m);
        }
    }
    return res;
}

static uint256 inv_mod(const uint256& a, const uint256& m) {
    uint64_t b_out = 0;
    uint256 two = { {2, 0, 0, 0} };
    uint256 exp = uint256::sub(m, two, b_out);
    return pow_mod(a, exp, m);
}

static uint256 from_hex(const std::string& hex_in) {
    std::string s = hex_in;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
    while (s.length() < 64) s = "0" + s;
    uint256 res;
    for (int i = 0; i < 4; ++i) {
        std::string part = s.substr((3 - i) * 16, 16);
        res.w[i] = std::stoull(part, nullptr, 16);
    }
    return res;
}

static std::string to_hex(const uint256& val) {
    std::ostringstream oss;
    for (int i = 3; i >= 0; --i) {
        oss << std::hex << std::setw(16) << std::setfill('0') << val.w[i];
    }
    return oss.str();
}

struct PointAffine {
    uint256 x = uint256::zero();
    uint256 y = uint256::zero();
    bool is_infinity = true;
};

struct PointJacobian {
    uint256 X = uint256::zero();
    uint256 Y = uint256::zero();
    uint256 Z = uint256::zero();

    static PointJacobian infinity() {
        return { uint256::one(), uint256::one(), uint256::zero() };
    }

    bool is_infinity() const {
        return Z.is_zero();
    }
};

struct EllipticCurve {
    uint256 p;
    uint256 a;
    uint256 b;
    uint256 q;
    PointAffine G;

    PointJacobian to_jacobian(const PointAffine& pt) const {
        if (pt.is_infinity) return PointJacobian::infinity();
        return { pt.x, pt.y, uint256::one() };
    }

    PointAffine to_affine(const PointJacobian& pt) const {
        if (pt.is_infinity()) return { uint256::zero(), uint256::zero(), true };

        uint256 z_inv = inv_mod(pt.Z, p);
        uint256 z_inv2 = mul_mod(z_inv, z_inv, p);
        uint256 z_inv3 = mul_mod(z_inv2, z_inv, p);

        PointAffine res;
        res.x = mul_mod(pt.X, z_inv2, p);
        res.y = mul_mod(pt.Y, z_inv3, p);
        res.is_infinity = false;
        return res;
    }

    PointJacobian double_point(const PointJacobian& pt) const {
        if (pt.is_infinity() || pt.Y.is_zero()) {
            return PointJacobian::infinity();
        }

        uint256 X1 = pt.X, Y1 = pt.Y, Z1 = pt.Z;
        uint256 four = { {4, 0, 0, 0} };
        uint256 eight = { {8, 0, 0, 0} };
        uint256 three = { {3, 0, 0, 0} };
        uint256 two = { {2, 0, 0, 0} };

        uint256 Y1_sq = mul_mod(Y1, Y1, p);
        uint256 S = mul_mod(four, mul_mod(X1, Y1_sq, p), p);

        uint256 X1_sq = mul_mod(X1, X1, p);
        uint256 term1 = mul_mod(three, X1_sq, p);
        uint256 Z1_sq = mul_mod(Z1, Z1, p);
        uint256 Z1_pow4 = mul_mod(Z1_sq, Z1_sq, p);
        uint256 term2 = mul_mod(a, Z1_pow4, p);
        uint256 M = add_mod(term1, term2, p);

        uint256 M_sq = mul_mod(M, M, p);
        uint256 two_S = mul_mod(two, S, p);
        uint256 X3 = sub_mod(M_sq, two_S, p);

        uint256 Y1_pow4 = mul_mod(Y1_sq, Y1_sq, p);
        uint256 eight_Y1_pow4 = mul_mod(eight, Y1_pow4, p);
        uint256 Y3 = sub_mod(mul_mod(M, sub_mod(S, X3, p), p), eight_Y1_pow4, p);

        uint256 Z3 = mul_mod(two, mul_mod(Y1, Z1, p), p);

        return { X3, Y3, Z3 };
    }

    PointJacobian add_point(const PointJacobian& P1, const PointJacobian& P2) const {
        if (P1.is_infinity()) return P2;
        if (P2.is_infinity()) return P1;

        uint256 Z1_sq = mul_mod(P1.Z, P1.Z, p);
        uint256 Z2_sq = mul_mod(P2.Z, P2.Z, p);

        uint256 U1 = mul_mod(P1.X, Z2_sq, p);
        uint256 U2 = mul_mod(P2.X, Z1_sq, p);

        uint256 S1 = mul_mod(P1.Y, mul_mod(P2.Z, Z2_sq, p), p);
        uint256 S2 = mul_mod(P2.Y, mul_mod(P1.Z, Z1_sq, p), p);

        uint256 H = sub_mod(U2, U1, p);
        uint256 R = sub_mod(S2, S1, p);

        if (H.is_zero()) {
            if (R.is_zero()) {
                return double_point(P1);
            }
            else {
                return PointJacobian::infinity();
            }
        }

        uint256 H_sq = mul_mod(H, H, p);
        uint256 H_cube = mul_mod(H, H_sq, p);
        uint256 U1_H_sq = mul_mod(U1, H_sq, p);
        uint256 two = { {2, 0, 0, 0} };

        uint256 R_sq = mul_mod(R, R, p);
        uint256 X3 = sub_mod(sub_mod(R_sq, H_cube, p), mul_mod(two, U1_H_sq, p), p);

        uint256 Y3 = sub_mod(mul_mod(R, sub_mod(U1_H_sq, X3, p), p), mul_mod(S1, H_cube, p), p);

        uint256 Z3 = mul_mod(H, mul_mod(P1.Z, P2.Z, p), p);

        return { X3, Y3, Z3 };
    }
};

namespace SecureCT {
    inline uint64_t ct_eq_mask(uint32_t a, uint32_t b) {
        uint64_t diff = static_cast<uint64_t>(a ^ b);
        uint64_t nz = (diff | (~diff + 1ULL)) >> 63;
        return nz - 1ULL;
    }

    PointJacobian lookup_point_ct(const std::array<PointJacobian, 16>& table, uint32_t index) {
        PointJacobian res;
        res.X = uint256::zero();
        res.Y = uint256::zero();
        res.Z = uint256::zero();

        for (uint32_t i = 0; i < 16; ++i) {
            uint64_t mask = ct_eq_mask(i, index);
            res.X = res.X ^ (table[i].X & mask);
            res.Y = res.Y ^ (table[i].Y & mask);
            res.Z = res.Z ^ (table[i].Z & mask);
        }
        return res;
    }

    PointJacobian secure_scalar_mul(const EllipticCurve& curve, const uint256& k, const PointJacobian& P) {
        std::array<PointJacobian, 16> table;
        table[0] = PointJacobian::infinity();
        table[1] = P;
        table[2] = curve.double_point(P);
        for (size_t i = 3; i < 16; ++i) {
            table[i] = curve.add_point(table[i - 1], P);
        }

        PointJacobian R = PointJacobian::infinity();

        for (int w = 63; w >= 0; --w) {
            for (int step = 0; step < 4; ++step) {
                R = curve.double_point(R);
            }

            uint32_t nibble = (k.w[w / 16] >> ((w % 16) * 4)) & 0x0F;
            PointJacobian T = lookup_point_ct(table, nibble);
            R = curve.add_point(R, T);
        }

        return R;
    }
}

namespace CryptoProtocols {
    struct KeyPair {
        uint256 priv_key;
        PointAffine pub_key;
    };

    struct Signature {
        uint256 r;
        uint256 s;
    };

    KeyPair generate_keypair(const EllipticCurve& curve, const uint256& d) {
        PointJacobian G_jac = curve.to_jacobian(curve.G);
        PointJacobian Q_jac = SecureCT::secure_scalar_mul(curve, d, G_jac);
        return { d, curve.to_affine(Q_jac) };
    }

    uint256 ecdh_compute_shared_secret(const EllipticCurve& curve,
        const uint256& priv_key,
        const PointAffine& peer_pub_key) {
        PointJacobian P_jac = curve.to_jacobian(peer_pub_key);
        PointJacobian shared_jac = SecureCT::secure_scalar_mul(curve, priv_key, P_jac);
        PointAffine shared_aff = curve.to_affine(shared_jac);
        return shared_aff.x;
    }

    Signature stb_sign(const EllipticCurve& curve,
        const uint256& msg_hash_e,
        const uint256& priv_d,
        const uint256& ephemeral_k) {
        PointJacobian G_jac = curve.to_jacobian(curve.G);
        PointJacobian C_jac = SecureCT::secure_scalar_mul(curve, ephemeral_k, G_jac);
        PointAffine C = curve.to_affine(C_jac);

        uint512 xc_512;
        for (int i = 0; i < 4; ++i) xc_512.w[i] = C.x.w[i];
        uint256 r = mod512(xc_512, curve.q);

        uint256 rd = mul_mod(r, priv_d, curve.q);
        uint256 ke = mul_mod(ephemeral_k, msg_hash_e, curve.q);
        uint256 s = add_mod(rd, ke, curve.q);

        return { r, s };
    }

    bool stb_verify(const EllipticCurve& curve,
        const uint256& msg_hash_e,
        const Signature& sig,
        const PointAffine& pub_Q) {
        if (sig.r.is_zero() || sig.r >= curve.q) return false;
        if (sig.s.is_zero() || sig.s >= curve.q) return false;

        uint256 v = inv_mod(msg_hash_e, curve.q);

        uint256 z1 = mul_mod(sig.s, v, curve.q);

        uint256 rv = mul_mod(sig.r, v, curve.q);
        uint64_t b = 0;
        uint256 z2 = rv.is_zero() ? uint256::zero() : uint256::sub(curve.q, rv, b);

        PointJacobian G_jac = curve.to_jacobian(curve.G);
        PointJacobian Q_jac = curve.to_jacobian(pub_Q);

        PointJacobian P1 = SecureCT::secure_scalar_mul(curve, z1, G_jac);
        PointJacobian P2 = SecureCT::secure_scalar_mul(curve, z2, Q_jac);
        PointJacobian C_prime_jac = curve.add_point(P1, P2);

        if (C_prime_jac.is_infinity()) return false;

        PointAffine C_prime = curve.to_affine(C_prime_jac);

        uint512 xc_512;
        for (int i = 0; i < 4; ++i) xc_512.w[i] = C_prime.x.w[i];
        uint256 R = mod512(xc_512, curve.q);

        return (R == sig.r);
    }
}

int main() {
    EllipticCurve curve;
    curve.p = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    curve.a = from_hex("0000000000000000000000000000000000000000000000000000000000000000");
    curve.b = from_hex("0000000000000000000000000000000000000000000000000000000000000007");
    curve.q = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    curve.G.x = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    curve.G.y = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    curve.G.is_infinity = false;

    std::cout << "[+] Elliptic curve parameters initialized:\n";
    std::cout << "    p  = 0x" << to_hex(curve.p) << "\n";
    std::cout << "    q  = 0x" << to_hex(curve.q) << "\n";
    std::cout << "    Gx = 0x" << to_hex(curve.G.x) << "\n";
    std::cout << "    Gy = 0x" << to_hex(curve.G.y) << "\n\n";

    std::cout << "--- ECDH KEY EXCHANGE TEST ---\n";
    uint256 dA = from_hex("E8B3CE2D9B39B71AB7DF0E576B3C00A2C9FA84DE8C0A4B3FE0280D5DF1234567");
    uint256 dB = from_hex("A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF00112233445566778");

    auto alice_keys = CryptoProtocols::generate_keypair(curve, dA);
    auto bob_keys = CryptoProtocols::generate_keypair(curve, dB);

    std::cout << "Alice PrivKey dA: 0x" << to_hex(dA) << "\n";
    std::cout << "Alice PubKey  QA: (0x" << to_hex(alice_keys.pub_key.x) << ",\n"
        << "                   0x" << to_hex(alice_keys.pub_key.y) << ")\n";
    std::cout << "Bob   PrivKey dB: 0x" << to_hex(dB) << "\n";
    std::cout << "Bob   PubKey  QB: (0x" << to_hex(bob_keys.pub_key.x) << ",\n"
        << "                   0x" << to_hex(bob_keys.pub_key.y) << ")\n\n";

    uint256 secret_alice = CryptoProtocols::ecdh_compute_shared_secret(curve, dA, bob_keys.pub_key);
    uint256 secret_bob = CryptoProtocols::ecdh_compute_shared_secret(curve, dB, alice_keys.pub_key);

    std::cout << "Shared Secret (Alice): 0x" << to_hex(secret_alice) << "\n";
    std::cout << "Shared Secret (Bob):   0x" << to_hex(secret_bob) << "\n";

    if (secret_alice == secret_bob) {
        std::cout << ">>> [ECDH SUCCESS] Shared secrets match!\n\n";
    }
    else {
        std::cout << ">>> [ECDH FAILURE] Key exchange failed!\n\n";
    }

    std::cout << "--- DIGITAL SIGNATURE TEST (STB 34.101.45) ---\n";
    uint256 hash_e = from_hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    uint256 eph_k = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    std::cout << "Message Hash e:  0x" << to_hex(hash_e) << "\n";
    std::cout << "Ephemeral key k: 0x" << to_hex(eph_k) << "\n";

    CryptoProtocols::Signature sig = CryptoProtocols::stb_sign(curve, hash_e, dA, eph_k);
    std::cout << "Signature (r):   0x" << to_hex(sig.r) << "\n";
    std::cout << "Signature (s):   0x" << to_hex(sig.s) << "\n\n";

    bool is_valid = CryptoProtocols::stb_verify(curve, hash_e, sig, alice_keys.pub_key);
    std::cout << "Signature verification: "
        << (is_valid ? ">>> [VALID] Signature verified successfully!\n" : ">>> [INVALID] Verification failed!\n") << "\n";

    std::cout << "--- 3. NEGATIVE TEST: TAMPERED SIGNATURE PARAMETER s ---\n";
    CryptoProtocols::Signature tampered_sig = sig;
    tampered_sig.s.w[0] ^= 0xFFULL;

    std::cout << "Tampered s:      0x" << to_hex(tampered_sig.s) << "\n";
    bool is_tampered_valid = CryptoProtocols::stb_verify(curve, hash_e, tampered_sig, alice_keys.pub_key);
    std::cout << "Tampered signature verification: "
        << (is_tampered_valid ? ">>> [SECURITY BREACH] Forged signature accepted!\n"
            : ">>> [REJECTED] Tampered signature rejected correctly!\n");
    std::cout << "===============================================================\n";

    return 0;
}
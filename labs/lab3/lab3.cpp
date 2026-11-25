#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <cstdint>
#include <array>

struct Bn256 {
    uint64_t d[4] = {0, 0, 0, 0};

    static constexpr Bn256 make_zero() { return {{0, 0, 0, 0}}; }
    static constexpr Bn256 make_unit() { return {{1, 0, 0, 0}}; }

    bool is_null() const {
        return (d[0] | d[1] | d[2] | d[3]) == 0ULL;
    }

    bool equals(const Bn256& other) const {
        return d[0] == other.d[0] && d[1] == other.d[1] &&
               d[2] == other.d[2] && d[3] == other.d[3];
    }

    bool is_less(const Bn256& other) const {
        for (int i = 3; i >= 0; --i) {
            if (d[i] < other.d[i]) return true;
            if (d[i] > other.d[i]) return false;
        }
        return false;
    }
};

struct Bn512 {
    uint64_t d[8] = {0};

    bool test_bit(int bit_idx) const {
        return (d[bit_idx / 64] >> (bit_idx % 64)) & 1ULL;
    }
};

static void mul64_split(uint64_t u, uint64_t v, uint64_t& hi, uint64_t& lo) {
    uint64_t u0 = static_cast<uint32_t>(u);
    uint64_t u1 = u >> 32;
    uint64_t v0 = static_cast<uint32_t>(v);
    uint64_t v1 = v >> 32;

    uint64_t w0 = u0 * v0;
    uint64_t w1 = u0 * v1;
    uint64_t w2 = u1 * v0;
    uint64_t w3 = u1 * v1;

    uint64_t mid = (w0 >> 32) + (w1 & 0xFFFFFFFFULL) + (w2 & 0xFFFFFFFFULL);
    lo = (w0 & 0xFFFFFFFFULL) | (mid << 32);
    hi = w3 + (w1 >> 32) + (w2 >> 32) + (mid >> 32);
}

namespace FieldOps {
    Bn256 add_raw(const Bn256& a, const Bn256& b, uint64_t& carry) {
        Bn256 out{};
        carry = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t s1 = a.d[i] + carry;
            uint64_t c1 = (s1 < carry) ? 1ULL : 0ULL;
            uint64_t s2 = s1 + b.d[i];
            uint64_t c2 = (s2 < b.d[i]) ? 1ULL : 0ULL;
            out.d[i] = s2;
            carry = c1 + c2;
        }
        return out;
    }

    Bn256 sub_raw(const Bn256& a, const Bn256& b, uint64_t& borrow) {
        Bn256 out{};
        borrow = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t src = a.d[i];
            uint64_t sub = b.d[i];
            uint64_t d1 = src - borrow;
            uint64_t b1 = (src < borrow) ? 1ULL : 0ULL;
            uint64_t d2 = d1 - sub;
            uint64_t b2 = (d1 < sub) ? 1ULL : 0ULL;
            out.d[i] = d2;
            borrow = b1 + b2;
        }
        return out;
    }

    Bn512 mul_wide(const Bn256& a, const Bn256& b) {
        Bn512 prod{};
        for (int i = 0; i < 4; ++i) {
            uint64_t carry = 0;
            for (int j = 0; j < 4; ++j) {
                uint64_t hi = 0, lo = 0;
                mul64_split(a.d[i], b.d[j], hi, lo);

                uint64_t s1 = prod.d[i + j] + lo;
                uint64_t c1 = (s1 < lo) ? 1ULL : 0ULL;
                uint64_t s2 = s1 + carry;
                uint64_t c2 = (s2 < carry) ? 1ULL : 0ULL;
                prod.d[i + j] = s2;

                carry = hi + c1 + c2;
            }
            prod.d[i + 4] = carry;
        }
        return prod;
    }

    Bn256 reduce512(const Bn512& val, const Bn256& mod) {
        Bn256 rem = Bn256::make_zero();
        for (int i = 511; i >= 0; --i) {
            uint64_t msb = (rem.d[3] >> 63) & 1ULL;
            rem.d[3] = (rem.d[3] << 1) | (rem.d[2] >> 63);
            rem.d[2] = (rem.d[2] << 1) | (rem.d[1] >> 63);
            rem.d[1] = (rem.d[1] << 1) | (rem.d[0] >> 63);
            rem.d[0] = (rem.d[0] << 1) | static_cast<uint64_t>(val.test_bit(i));

            if (msb || !rem.is_less(mod)) {
                uint64_t br = 0;
                rem = sub_raw(rem, mod, br);
            }
        }
        return rem;
    }

    Bn256 mod_add(const Bn256& a, const Bn256& b, const Bn256& m) {
        uint64_t cy = 0;
        Bn256 res = add_raw(a, b, cy);
        if (cy || !res.is_less(m)) {
            uint64_t br = 0;
            res = sub_raw(res, m, br);
        }
        return res;
    }

    Bn256 mod_sub(const Bn256& a, const Bn256& b, const Bn256& m) {
        uint64_t br = 0;
        if (!a.is_less(b)) {
            return sub_raw(a, b, br);
        }
        Bn256 delta = sub_raw(b, a, br);
        return sub_raw(m, delta, br);
    }

    Bn256 mod_mul(const Bn256& a, const Bn256& b, const Bn256& m) {
        Bn512 product = mul_wide(a, b);
        return reduce512(product, m);
    }

    inline Bn256 ct_mux(uint64_t mask, const Bn256& t_val, const Bn256& f_val) {
        Bn256 r{};
        for (int i = 0; i < 4; ++i) {
            r.d[i] = (t_val.d[i] & mask) | (f_val.d[i] & ~mask);
        }
        return r;
    }

    Bn256 fermat_mod_inverse(Bn256 base, const Bn256& mod) {
        uint64_t br = 0;
        Bn256 two = {{2, 0, 0, 0}};
        Bn256 exp = sub_raw(mod, two, br);

        Bn512 init_buf{};
        for (int i = 0; i < 4; ++i) init_buf.d[i] = base.d[i];
        base = reduce512(init_buf, mod);

        Bn256 accum = Bn256::make_unit();

        for (int step = 255; step >= 0; --step) {
            accum = mod_mul(accum, accum, mod);
            Bn256 mult_branch = mod_mul(accum, base, mod);

            uint64_t bit = (exp.d[step / 64] >> (step % 64)) & 1ULL;
            uint64_t mask = 0ULL - bit;

            accum = ct_mux(mask, mult_branch, accum);
        }
        return accum;
    }
}

static Bn256 parse_hex(const std::string& input) {
    std::string hex_str = input;
    if (hex_str.rfind("0x", 0) == 0 || hex_str.rfind("0X", 0) == 0) {
        hex_str = hex_str.substr(2);
    }
    while (hex_str.length() < 64) {
        hex_str = "0" + hex_str;
    }
    Bn256 out{};
    for (int i = 0; i < 4; ++i) {
        std::string chunk = hex_str.substr((3 - i) * 16, 16);
        out.d[i] = std::stoull(chunk, nullptr, 16);
    }
    return out;
}

static std::string dump_hex(const Bn256& num) {
    std::ostringstream ss;
    for (int i = 3; i >= 0; --i) {
        ss << std::hex << std::setw(16) << std::setfill('0') << num.d[i];
    }
    return ss.str();
}

struct CurvePoint {
    Bn256 x = Bn256::make_zero();
    Bn256 y = Bn256::make_zero();
    bool is_inf = true;

    static CurvePoint identity() {
        return {Bn256::make_zero(), Bn256::make_zero(), true};
    }
};

class CurveEngine {
public:
    Bn256 p;
    Bn256 a;
    Bn256 b;
    Bn256 q;
    CurvePoint G;

    CurvePoint dbl(const CurvePoint& pt) const {
        if (pt.is_inf || pt.y.is_null()) {
            return CurvePoint::identity();
        }

        Bn256 x_sq = FieldOps::mod_mul(pt.x, pt.x, p);
        Bn256 three = {{3, 0, 0, 0}};
        Bn256 num = FieldOps::mod_add(FieldOps::mod_mul(three, x_sq, p), a, p);
        Bn256 two = {{2, 0, 0, 0}};
        Bn256 den = FieldOps::mod_mul(two, pt.y, p);

        Bn256 inv_den = FieldOps::fermat_mod_inverse(den, p);
        Bn256 slope = FieldOps::mod_mul(num, inv_den, p);

        Bn256 slope_sq = FieldOps::mod_mul(slope, slope, p);
        Bn256 twice_x = FieldOps::mod_mul(two, pt.x, p);
        Bn256 x3 = FieldOps::mod_sub(slope_sq, twice_x, p);

        Bn256 y3 = FieldOps::mod_sub(FieldOps::mod_mul(slope, FieldOps::mod_sub(pt.x, x3, p), p), pt.y, p);

        return {x3, y3, false};
    }

    CurvePoint add(const CurvePoint& p1, const CurvePoint& p2) const {
        if (p1.is_inf) return p2;
        if (p2.is_inf) return p1;

        if (p1.x.equals(p2.x)) {
            if (p1.y.equals(p2.y) && !p1.y.is_null()) {
                return dbl(p1);
            }
            return CurvePoint::identity();
        }

        Bn256 num = FieldOps::mod_sub(p2.y, p1.y, p);
        Bn256 den = FieldOps::mod_sub(p2.x, p1.x, p);

        Bn256 inv_den = FieldOps::fermat_mod_inverse(den, p);
        Bn256 slope = FieldOps::mod_mul(num, inv_den, p);

        Bn256 slope_sq = FieldOps::mod_mul(slope, slope, p);
        Bn256 x3 = FieldOps::mod_sub(FieldOps::mod_sub(slope_sq, p1.x, p), p2.x, p);
        Bn256 y3 = FieldOps::mod_sub(FieldOps::mod_mul(slope, FieldOps::mod_sub(p1.x, x3, p), p), p1.y, p);

        return {x3, y3, false};
    }

    CurvePoint mul(const Bn256& scalar, const CurvePoint& pt) const {
        CurvePoint acc0 = CurvePoint::identity();
        CurvePoint acc1 = pt;

        for (int i = 255; i >= 0; --i) {
            uint64_t b = (scalar.d[i / 64] >> (i % 64)) & 1ULL;
            if (b) {
                acc0 = add(acc0, acc1);
                acc1 = dbl(acc1);
            } else {
                acc1 = add(acc1, acc0);
                acc0 = dbl(acc0);
            }
        }
        return acc0;
    }
};

namespace EcdsaSystem {
    struct KeyPair {
        Bn256 sec;
        CurvePoint pub;
    };

    struct EcdsaSig {
        Bn256 r;
        Bn256 s;
    };

    KeyPair make_keys(const CurveEngine& crv, const Bn256& priv) {
        return {priv, crv.mul(priv, crv.G)};
    }

    Bn256 derive_ecdh(const CurveEngine& crv, const Bn256& priv, const CurvePoint& peer_pub) {
        CurvePoint pt = crv.mul(priv, peer_pub);
        return pt.x;
    }

    EcdsaSig sign(const CurveEngine& crv, const Bn256& e_hash, const Bn256& priv, const Bn256& k_eph) {
        CurvePoint R_pt = crv.mul(k_eph, crv.G);

        Bn512 rx_buf{};
        for (int i = 0; i < 4; ++i) rx_buf.d[i] = R_pt.x.d[i];
        Bn256 r = FieldOps::reduce512(rx_buf, crv.q);

        Bn256 inv_k = FieldOps::fermat_mod_inverse(k_eph, crv.q);

        Bn256 rd = FieldOps::mod_mul(r, priv, crv.q);
        Bn256 e_rd = FieldOps::mod_add(e_hash, rd, crv.q);
        Bn256 s = FieldOps::mod_mul(inv_k, e_rd, crv.q);

        return {r, s};
    }

    bool verify(const CurveEngine& crv, const Bn256& e_hash, const EcdsaSig& sig, const CurvePoint& pub) {
        if (sig.r.is_null() || !sig.r.is_less(crv.q)) return false;
        if (sig.s.is_null() || !sig.s.is_less(crv.q)) return false;

        Bn256 w = FieldOps::fermat_mod_inverse(sig.s, crv.q);

        Bn256 u1 = FieldOps::mod_mul(e_hash, w, crv.q);
        Bn256 u2 = FieldOps::mod_mul(sig.r, w, crv.q);

        CurvePoint term1 = crv.mul(u1, crv.G);
        CurvePoint term2 = crv.mul(u2, pub);
        CurvePoint final_pt = crv.add(term1, term2);

        if (final_pt.is_inf) return false;

        Bn512 fx_buf{};
        for (int i = 0; i < 4; ++i) fx_buf.d[i] = final_pt.x.d[i];
        Bn256 v = FieldOps::reduce512(fx_buf, crv.q);

        return v.equals(sig.r);
    }
}

int main() {
    std::cout << ">>> SECP256K1 CRYPTOSYSTEM DEMONSTRATION <<<\n";
    std::cout << ">>> ECDSA / AFFINE WEIERSTRASS / CONSTANT-TIME FERMAT INVERSION <<<\n\n";

    CurveEngine curve{};
    curve.p = parse_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    curve.a = parse_hex("0000000000000000000000000000000000000000000000000000000000000000");
    curve.b = parse_hex("0000000000000000000000000000000000000000000000000000000000000007");
    curve.q = parse_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    curve.G = {
        parse_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        parse_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        false
    };

    std::cout << "Parameters:\n";
    std::cout << "p  = 0x" << dump_hex(curve.p) << "\n";
    std::cout << "q  = 0x" << dump_hex(curve.q) << "\n";
    std::cout << "Gx = 0x" << dump_hex(curve.G.x) << "\n";
    std::cout << "Gy = 0x" << dump_hex(curve.G.y) << "\n\n";

    std::cout << "[STAGE 1: ECDH AGREEMENT]\n";
    Bn256 dA = parse_hex("E8B3CE2D9B39B71AB7DF0E576B3C00A2C9FA84DE8C0A4B3FE0280D5DF1234567");
    Bn256 dB = parse_hex("A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF00112233445566778");

    auto alice = EcdsaSystem::make_keys(curve, dA);
    auto bob   = EcdsaSystem::make_keys(curve, dB);

    std::cout << "PrivKey A: 0x" << dump_hex(dA) << "\n";
    std::cout << "PubKey  A: 0x" << dump_hex(alice.pub.x) << "\n";
    std::cout << "PrivKey B: 0x" << dump_hex(dB) << "\n";
    std::cout << "PubKey  B: 0x" << dump_hex(bob.pub.x) << "\n";

    Bn256 ss_alice = EcdsaSystem::derive_ecdh(curve, dA, bob.pub);
    Bn256 ss_bob   = EcdsaSystem::derive_ecdh(curve, dB, alice.pub);

    std::cout << "Alice Secret: 0x" << dump_hex(ss_alice) << "\n";
    std::cout << "Bob   Secret: 0x" << dump_hex(ss_bob) << "\n";

    if (ss_alice.equals(ss_bob)) {
        std::cout << "ECDH RESULT: AGREED\n\n";
    } else {
        std::cout << "ECDH RESULT: FAILED\n\n";
    }

    std::cout << "[STAGE 2: ECDSA SIGNATURE]\n";
    Bn256 digest = parse_hex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
    Bn256 k_seed = parse_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    std::cout << "Digest e: 0x" << dump_hex(digest) << "\n";
    std::cout << "k        : 0x" << dump_hex(k_seed) << "\n";

    auto signature = EcdsaSystem::sign(curve, digest, dA, k_seed);
    std::cout << "Sig.r    : 0x" << dump_hex(signature.r) << "\n";
    std::cout << "Sig.s    : 0x" << dump_hex(signature.s) << "\n";

    bool valid = EcdsaSystem::verify(curve, digest, signature, alice.pub);
    std::cout << "Authentic verify: " << (valid ? "PASSED" : "FAILED") << "\n\n";

    std::cout << "[STAGE 3: INTEGRITY VERIFICATION]\n";
    auto bad_sig = signature;
    bad_sig.s.d[0] ^= 0xA5ULL;

    std::cout << "Corrupted s: 0x" << dump_hex(bad_sig.s) << "\n";
    bool bad_valid = EcdsaSystem::verify(curve, digest, bad_sig, alice.pub);
    std::cout << "Tampered verify : " << (bad_valid ? "ACCEPTED (FAULT)" : "REJECTED (SECURE)") << "\n";

    return 0;
}
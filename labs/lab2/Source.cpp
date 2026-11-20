#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/evp.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;
using BigInt = boost::multiprecision::cpp_int;

namespace rsa_math {
    inline random_device& rng_dev() { static random_device d; return d; }
    inline mt19937_64& rng() { static mt19937_64 g(rng_dev()()); return g; }

    inline int bit_length(const BigInt& x) { return x <= 0 ? 0 : (int)boost::multiprecision::msb(x) + 1; }
    inline bool get_bit(const BigInt& x, int i) { return boost::multiprecision::bit_test(x, i); }

    inline BigInt random_bigint(int bits) {
        BigInt x = 0;
        int words = (bits + 63) / 64;
        for (int i = 0; i < words; ++i) { x <<= 64; x |= (uint64_t)rng()(); }
        int extra = words * 64 - bits;
        if (extra > 0) x >>= extra;
        x |= (BigInt(1) << (bits - 1));
        return x;
    }

    inline BigInt random_below(const BigInt& n) {
        if (n <= 0) throw runtime_error("random_below: n <= 0");
        int bits = bit_length(n);
        BigInt x = random_bigint(bits);
        while (x >= n) x = random_bigint(bits);
        return x;
    }

    inline BigInt gcd_extended(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) {
        if (b == 0) { x = 1; y = 0; return a; }
        BigInt x1, y1;
        BigInt g = gcd_extended(b, a % b, x1, y1);
        x = y1; y = x1 - (a / b) * y1;
        return g;
    }

    inline BigInt mod_inverse(const BigInt& a, const BigInt& m) {
        BigInt x, y;
        if (gcd_extended(a, m, x, y) != 1) throw runtime_error("mod_inverse: not coprime");
        return ((x % m) + m) % m;
    }

    inline BigInt mod_pow_ladder(const BigInt& base_in, const BigInt& exp, const BigInt& mod) {
        if (mod == 1) return BigInt(0);
        BigInt base = base_in % mod;
        if (base < 0) base += mod;
        BigInt R0 = 1 % mod, R1 = base;
        int bits = bit_length(exp);
        for (int i = bits - 1; i >= 0; --i) {
            BigInt mask = get_bit(exp, i) ? BigInt(1) : BigInt(0);
            BigInt diff = (R0 - R1) * mask; R0 -= diff; R1 += diff;
            R1 = (R0 * R1) % mod;
            R0 = (R0 * R0) % mod;
            BigInt diff2 = (R0 - R1) * mask; R0 -= diff2; R1 += diff2;
        }
        return R0;
    }

    inline BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod) {
        return mod_pow_ladder(base, exp, mod);
    }

    inline bool miller_rabin(const BigInt& n, int rounds = 40) {
        if (n < 2) return false;
        if (n < 4) return true;
        if ((n & 1) == 0) return false;
        static const int sp[] = { 3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97 };
        for (int p : sp) { if (n == p) return true; if (n % p == 0) return false; }
        BigInt d = n - 1; int s = 0;
        while ((d & 1) == 0) { d >>= 1; ++s; }
        for (int r = 0; r < rounds; ++r) {
            BigInt a = 2 + random_below(n - 3);
            BigInt x = mod_pow(a, d, n);
            if (x == 1 || x == n - 1) continue;
            bool composite = true;
            for (int i = 0; i < s - 1; ++i) {
                x = (x * x) % n;
                if (x == n - 1) { composite = false; break; }
            }
            if (composite) return false;
        }
        return true;
    }

    inline BigInt generate_prime(int bits) {
        while (true) {
            BigInt cand = random_bigint(bits); cand |= 1;
            if (miller_rabin(cand, 40)) return cand;
        }
    }

    struct RSAKeyPair {
        BigInt N, e, d, p, q, dp, dq, q_inv;
    };

    inline RSAKeyPair generate_rsa_key(int bits) {
        int pbits = bits / 2, qbits = bits - pbits;
        BigInt p, q;
        do { p = generate_prime(pbits); q = generate_prime(qbits); } while (p == q);
        BigInt N = p * q;
        BigInt pm1 = p - 1, qm1 = q - 1, x, y;
        BigInt g = gcd_extended(pm1, qm1, x, y);
        BigInt lambda = (pm1 / g) * qm1;
        BigInt e = 65537;
        if (boost::multiprecision::gcd(e, lambda) != 1) return generate_rsa_key(bits);
        BigInt d = mod_inverse(e, lambda);
        RSAKeyPair kp;
        kp.N = N; kp.e = e; kp.d = d; kp.p = p; kp.q = q;
        kp.dp = d % (p - 1); kp.dq = d % (q - 1);
        kp.q_inv = mod_inverse(q % p, p);
        return kp;
    }

    inline BigInt bytes_to_bigint(const vector<uint8_t>& b) {
        BigInt r = 0; for (uint8_t x : b) { r <<= 8; r |= x; } return r;
    }

    inline vector<uint8_t> bigint_to_bytes(const BigInt& x, size_t len) {
        vector<uint8_t> out(len, 0); BigInt t = x;
        for (size_t i = 0; i < len; ++i) { out[len - 1 - i] = (uint8_t)(t & 0xFF); t >>= 8; }
        return out;
    }
}

namespace rsa_core {
    using namespace rsa_math;

    inline BigInt rsa_encrypt_raw(const BigInt& m, const BigInt& e, const BigInt& N) {
        return mod_pow(m % N, e, N);
    }

    inline BigInt rsa_decrypt_crt(const BigInt& c, const RSAKeyPair& kp) {
        BigInt m1 = mod_pow_ladder(c % kp.p, kp.dp, kp.p);
        BigInt m2 = mod_pow_ladder(c % kp.q, kp.dq, kp.q);
        BigInt h = (kp.q_inv * (m1 - m2)) % kp.p;
        if (h < 0) h += kp.p;
        return m2 + h * kp.q;
    }

    inline BigInt rsa_decrypt_blinded(const BigInt& c, const RSAKeyPair& kp) {
        BigInt r;
        do { r = random_below(kp.N - 1) + 1; } while (boost::multiprecision::gcd(r, kp.N) != 1);
        BigInt r_inv = mod_inverse(r, kp.N);
        BigInt r_e = mod_pow(r, kp.e, kp.N);
        BigInt c_blinded = (c * r_e) % kp.N;
        BigInt m_blinded = rsa_decrypt_crt(c_blinded, kp);
        return (m_blinded * r_inv) % kp.N;
    }
}

namespace rsa_oaep {
    using namespace rsa_math;
    static constexpr size_t HASH_LEN = 32;

    inline vector<uint8_t> sha3_256(const uint8_t* data, size_t len) {
        vector<uint8_t> out(HASH_LEN);
        unsigned int outlen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
        EVP_DigestUpdate(ctx, data, len);
        EVP_DigestFinal_ex(ctx, out.data(), &outlen);
        EVP_MD_CTX_free(ctx);
        return out;
    }

    inline vector<uint8_t> sha3_256(const vector<uint8_t>& d) {
        return sha3_256(d.data(), d.size());
    }

    inline vector<uint8_t> mgf1(const uint8_t* seed, size_t seed_len, size_t mask_len) {
        vector<uint8_t> mask(mask_len);
        size_t offset = 0;
        for (uint32_t counter = 0; offset < mask_len; ++counter) {
            uint8_t c[4] = { (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                            (uint8_t)(counter >> 8), (uint8_t)counter };
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(ctx, seed, seed_len);
            EVP_DigestUpdate(ctx, c, 4);
            uint8_t h[HASH_LEN]; unsigned int hlen = 0;
            EVP_DigestFinal_ex(ctx, h, &hlen);
            EVP_MD_CTX_free(ctx);
            size_t to_copy = min<size_t>(HASH_LEN, mask_len - offset);
            memcpy(mask.data() + offset, h, to_copy);
            offset += to_copy;
        }
        return mask;
    }

    inline vector<uint8_t> oaep_encode(const vector<uint8_t>& M,
        const vector<uint8_t>& label, size_t k)
    {
        if (M.size() > k - 2 * HASH_LEN - 2)
            throw runtime_error("OAEP: message too long");
        vector<uint8_t> lHash = sha3_256(label);
        size_t db_len = k - HASH_LEN - 1;
        vector<uint8_t> DB(db_len, 0);
        memcpy(DB.data(), lHash.data(), HASH_LEN);
        size_t ps_len = db_len - HASH_LEN - 1 - M.size();
        DB[HASH_LEN + ps_len] = 0x01;
        memcpy(DB.data() + HASH_LEN + ps_len + 1, M.data(), M.size());
        vector<uint8_t> seed(HASH_LEN);
        for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = (uint8_t)(rng()() & 0xFF);
        auto dbMask = mgf1(seed.data(), seed.size(), db_len);
        vector<uint8_t> maskedDB(db_len);
        for (size_t i = 0; i < db_len; ++i) maskedDB[i] = DB[i] ^ dbMask[i];
        auto seedMask = mgf1(maskedDB.data(), maskedDB.size(), HASH_LEN);
        vector<uint8_t> maskedSeed(HASH_LEN);
        for (size_t i = 0; i < HASH_LEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];
        vector<uint8_t> EM(k, 0);
        EM[0] = 0x00;
        memcpy(EM.data() + 1, maskedSeed.data(), HASH_LEN);
        memcpy(EM.data() + 1 + HASH_LEN, maskedDB.data(), db_len);
        return EM;
    }

    inline bool oaep_decode(const vector<uint8_t>& EM,
        const vector<uint8_t>& label, vector<uint8_t>& M_out)
    {
        size_t k = EM.size();
        if (k < 2 * HASH_LEN + 2) return false;
        size_t db_len = k - HASH_LEN - 1;
        uint8_t err = 0;
        err |= EM[0];
        const uint8_t* maskedSeed = EM.data() + 1;
        const uint8_t* maskedDB = EM.data() + 1 + HASH_LEN;
        auto seedMask = mgf1(maskedDB, db_len, HASH_LEN);
        vector<uint8_t> seed(HASH_LEN);
        for (size_t i = 0; i < HASH_LEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];
        auto dbMask = mgf1(seed.data(), seed.size(), db_len);
        vector<uint8_t> DB(db_len);
        for (size_t i = 0; i < db_len; ++i) DB[i] = maskedDB[i] ^ dbMask[i];
        vector<uint8_t> lHash = sha3_256(label);
        uint8_t lhash_diff = 0;
        for (size_t i = 0; i < HASH_LEN; ++i) lhash_diff |= (uint8_t)(DB[i] ^ lHash[i]);
        err |= lhash_diff;
        size_t msg_offset = db_len;
        uint8_t found = 0;
        for (size_t i = HASH_LEN; i < db_len; ++i) {
            uint8_t b = DB[i];
            uint8_t is_one = (uint8_t)(b == 0x01);
            uint8_t is_zero = (uint8_t)(b == 0x00);
            uint8_t bad = (uint8_t)((1 - found) & (1 - is_one) & (1 - is_zero));
            err |= bad;
            uint8_t newly_found = (uint8_t)((1 - found) & is_one);
            msg_offset = (size_t)newly_found * (i + 1) + (size_t)(1 - newly_found) * msg_offset;
            found |= newly_found;
        }
        err |= (uint8_t)(1 - found);
        size_t msg_len = db_len - msg_offset;
        M_out.assign(msg_len, 0);
        for (size_t i = 0; i < msg_len; ++i) M_out[i] = DB[msg_offset + i];
        uint8_t ok_mask = (uint8_t)(err == 0 ? 0xFF : 0x00);
        for (size_t i = 0; i < M_out.size(); ++i) M_out[i] &= ok_mask;
        return err == 0;
    }

    inline vector<uint8_t> encrypt(const vector<uint8_t>& M,
        const vector<uint8_t>& label, const rsa_math::RSAKeyPair& kp)
    {
        size_t k = (bit_length(kp.N) + 7) / 8;
        auto EM = oaep_encode(M, label, k);
        BigInt c = rsa_core::rsa_encrypt_raw(bytes_to_bigint(EM), kp.e, kp.N);
        return bigint_to_bytes(c, k);
    }

    inline bool decrypt(const vector<uint8_t>& C,
        const vector<uint8_t>& label, const rsa_math::RSAKeyPair& kp,
        vector<uint8_t>& M_out)
    {
        size_t k = (bit_length(kp.N) + 7) / 8;
        if (C.size() != k) return false;
        BigInt c = bytes_to_bigint(C);
        if (c >= kp.N) return false;
        BigInt m = rsa_core::rsa_decrypt_blinded(c, kp);
        return oaep_decode(bigint_to_bytes(m, k), label, M_out);
    }
}

static void print_hex(const string& name, const vector<uint8_t>& v, size_t limit = 32) {
    cout << name << " (" << v.size() << " байт): ";
    size_t n = min(v.size(), limit);
    for (size_t i = 0; i < n; ++i)
        cout << hex << setw(2) << setfill('0') << (int)v[i];
    if (v.size() > limit) cout << "...";
    cout << dec << "\n";
}

int main() {
    setlocale(LC_ALL, "ru");
    cout << "RSA-3072 + SHA3-256 + OAEP + CRT + Blinding\n\n";

    cout << "[*] Генерация ключа 3072 бит...\n";
    rsa_math::RSAKeyPair kp = rsa_math::generate_rsa_key(3072);
    cout << "    |N| = " << rsa_math::bit_length(kp.N) << " бит\n";
    cout << "    |p| = " << rsa_math::bit_length(kp.p) << " бит\n";
    cout << "    |q| = " << rsa_math::bit_length(kp.q) << " бит\n\n";

    string text = "Лабораторная №2: RSA + CRT + OAEP + Blinding";
    vector<uint8_t> M(text.begin(), text.end());
    vector<uint8_t> label;

    print_hex("[+] M", M);
    auto C = rsa_oaep::encrypt(M, label, kp);
    print_hex("[+] C", C);

    vector<uint8_t> M2;
    bool ok = rsa_oaep::decrypt(C, label, kp, M2);
    cout << "[+] decrypt ok = " << (ok ? "true" : "false") << "\n";
    print_hex("[+] M'", M2);
    cout << "[+] M' строка: \"" << string(M2.begin(), M2.end()) << "\"\n\n";

    vector<uint8_t> bad = C;
    bad[10] ^= 0x01;
    vector<uint8_t> M3;
    bool ok2 = rsa_oaep::decrypt(bad, label, kp, M3);
    cout << "[+] decrypt(повреждён) ok = " << (ok2 ? "true" : "false") << "\n";
    print_hex("[+] M'(повреждён)", M3);

    return 0;
}

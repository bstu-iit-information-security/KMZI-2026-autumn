#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <string>

using namespace std;

// big integer class for rsa-4096 operations
class BigInt {
public:
    vector<uint32_t> v;

    BigInt() {}
    BigInt(uint64_t val) {
        if (val > 0) {
            v.push_back(static_cast<uint32_t>(val & 0xFFFFFFFF));
            if (val >> 32) v.push_back(static_cast<uint32_t>(val >> 32));
        }
    }

    void trim() {
        while (!v.empty() && v.back() == 0) v.pop_back();
    }

    bool is_zero() const {
        for (auto x : v) if (x != 0) return false;
        return true;
    }

    bool is_even() const {
        if (v.empty()) return true;
        return (v[0] & 1) == 0;
    }

    bool tstbit(size_t bit) const {
        size_t idx = bit / 32;
        size_t pos = bit % 32;
        if (idx >= v.size()) return false;
        return (v[idx] >> pos) & 1;
    }

    void setbit(size_t bit) {
        size_t idx = bit / 32;
        size_t pos = bit % 32;
        if (idx >= v.size()) v.resize(idx + 1, 0);
        v[idx] |= (1U << pos);
    }

    size_t bit_len() const {
        if (v.empty()) return 0;
        size_t idx = v.size() - 1;
        while (idx > 0 && v[idx] == 0) idx--;
        if (v[idx] == 0) return 0;
        uint32_t top = v[idx];
        size_t bits = idx * 32;
        while (top > 0) { bits++; top >>= 1; }
        return bits;
    }

    static int cmp(const BigInt& a, const BigInt& b) {
        size_t la = a.v.size(), lb = b.v.size();
        while (la > 0 && a.v[la - 1] == 0) la--;
        while (lb > 0 && b.v[lb - 1] == 0) lb--;
        if (la != lb) return la < lb ? -1 : 1;
        for (size_t i = la; i > 0; --i) {
            if (a.v[i - 1] != b.v[i - 1])
                return a.v[i - 1] < b.v[i - 1] ? -1 : 1;
        }
        return 0;
    }

    static BigInt add(const BigInt& a, const BigInt& b) {
        BigInt res;
        uint64_t carry = 0;
        size_t n = max(a.v.size(), b.v.size());
        for (size_t i = 0; i < n || carry; ++i) {
            uint64_t sum = carry;
            if (i < a.v.size()) sum += a.v[i];
            if (i < b.v.size()) sum += b.v[i];
            res.v.push_back(static_cast<uint32_t>(sum & 0xFFFFFFFF));
            carry = sum >> 32;
        }
        res.trim();
        return res;
    }

    static BigInt sub(const BigInt& a, const BigInt& b) {
        BigInt res;
        int64_t borrow = 0;
        for (size_t i = 0; i < a.v.size(); ++i) {
            int64_t diff = static_cast<int64_t>(a.v[i]) - borrow - (i < b.v.size() ? b.v[i] : 0);
            if (diff < 0) {
                diff += 0x100000000LL;
                borrow = 1;
            } else {
                borrow = 0;
            }
            res.v.push_back(static_cast<uint32_t>(diff));
        }
        res.trim();
        return res;
    }

    static BigInt mul(const BigInt& a, const BigInt& b) {
        BigInt res;
        res.v.resize(a.v.size() + b.v.size(), 0);
        for (size_t i = 0; i < a.v.size(); ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < b.v.size() || carry; ++j) {
                uint64_t cur = res.v[i + j] + carry + (uint64_t)a.v[i] * (j < b.v.size() ? b.v[j] : 0);
                res.v[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
        }
        res.trim();
        return res;
    }

    static BigInt shift_right_1(const BigInt& a) {
        BigInt res;
        if (a.v.empty()) return res;
        res.v.resize(a.v.size(), 0);
        uint32_t carry = 0;
        for (size_t i = a.v.size(); i > 0; --i) {
            uint32_t cur = a.v[i - 1];
            res.v[i - 1] = (cur >> 1) | (carry << 31);
            carry = cur & 1;
        }
        res.trim();
        return res;
    }

    static BigInt shift_left_1(const BigInt& a) {
        BigInt res;
        if (a.v.empty()) return res;
        res.v.resize(a.v.size(), 0);
        uint32_t carry = 0;
        for (size_t i = 0; i < a.v.size(); ++i) {
            uint64_t cur = ((uint64_t)a.v[i] << 1) | carry;
            res.v[i] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
            carry = static_cast<uint32_t>(cur >> 32);
        }
        if (carry) res.v.push_back(carry);
        res.trim();
        return res;
    }

    static BigInt mod(const BigInt& a, const BigInt& m) {
        if (m.is_zero()) throw invalid_argument("division by zero");
        BigInt rem;
        size_t bits = a.bit_len();
        for (size_t i = bits; i > 0; --i) {
            rem = shift_left_1(rem);
            if (a.tstbit(i - 1)) rem.setbit(0);
            if (cmp(rem, m) >= 0) {
                rem = sub(rem, m);
            }
        }
        return rem;
    }

    static BigInt mod_pow(BigInt base, BigInt exp, const BigInt& m) {
        BigInt res(1);
        base = mod(base, m);
        size_t bits = exp.bit_len();
        for (size_t i = 0; i < bits; ++i) {
            if (exp.tstbit(i)) {
                res = mod(mul(res, base), m);
            }
            base = mod(mul(base, base), m);
        }
        return res;
    }

    static BigInt from_bytes(const vector<uint8_t>& bytes) {
        BigInt res;
        for (uint8_t b : bytes) {
            for (int k = 0; k < 8; ++k) {
                res = shift_left_1(res);
            }
            res = add(res, BigInt(b));
        }
        return res;
    }

    vector<uint8_t> to_bytes(size_t fixed_len) const {
        vector<uint8_t> res(fixed_len, 0);
        BigInt temp = *this;
        for (size_t i = 0; i < fixed_len; ++i) {
            if (!temp.v.empty()) {
                res[fixed_len - 1 - i] = static_cast<uint8_t>(temp.v[0] & 0xFF);
            }
            for (int k = 0; k < 8; ++k) {
                temp = shift_right_1(temp);
            }
        }
        return res;
    }

    static BigInt from_hex(const string& hex_str) {
        vector<uint8_t> bytes;
        size_t len = hex_str.length();
        size_t start = (len % 2 != 0) ? 1 : 0;
        if (start) {
            char c = hex_str[0];
            uint8_t val = (c >= '0' && c <= '9') ? c - '0' :
                          (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                          (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
            bytes.push_back(val);
        }
        for (size_t i = start; i < len; i += 2) {
            string byteString = hex_str.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return from_bytes(bytes);
    }
};

// sha-384 implementation
namespace Cryptography {

class SHA384 {
private:
    static inline uint64_t rotr(uint64_t x, size_t n) {
        return (x >> n) | (x << (64 - n));
    }
    static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint64_t Sigma0(uint64_t x) {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }
    static inline uint64_t Sigma1(uint64_t x) {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }
    static inline uint64_t sigma0(uint64_t x) {
        return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
    }
    static inline uint64_t sigma1(uint64_t x) {
        return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
    }

    static const uint64_t K[80];

public:
    static void hash(const uint8_t* data, size_t len, uint8_t out[48]) {
        uint64_t H[8] = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
            0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a876d468b80ULL,
            0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
        };

        size_t padded_len = len + 1 + 16;
        if (padded_len % 128 != 0) {
            padded_len += 128 - (padded_len % 128);
        }

        vector<uint8_t> padded(padded_len, 0);
        if (len > 0 && data != nullptr) {
            memcpy(padded.data(), data, len);
        }
        padded[len] = 0x80;

        uint64_t bit_len = static_cast<uint64_t>(len) * 8;
        for (int i = 0; i < 8; ++i) {
            padded[padded_len - 8 + i] = static_cast<uint8_t>((bit_len >> (56 - i * 8)) & 0xFF);
        }

        for (size_t offset = 0; offset < padded_len; offset += 128) {
            uint64_t W[80];
            for (size_t t = 0; t < 16; ++t) {
                W[t] = 0;
                for (size_t b = 0; b < 8; ++b) {
                    W[t] = (W[t] << 8) | padded[offset + t * 8 + b];
                }
            }
            for (size_t t = 16; t < 80; ++t) {
                W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
            }

            uint64_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint64_t e = H[4], f = H[5], g = H[6], h = H[7];

            for (size_t t = 0; t < 80; ++t) {
                uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
                uint64_t T2 = Sigma0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        for (size_t i = 0; i < 6; ++i) {
            for (size_t b = 0; b < 8; ++b) {
                out[i * 8 + b] = static_cast<uint8_t>((H[i] >> (56 - b * 8)) & 0xFF);
            }
        }
    }
};

const uint64_t SHA384::K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7bef0bf89ULL,
    0x48a1e2225140102cULL, 0x059b64011d82f2abULL, 0x1caaab05880a3e6eULL, 0x5471c6210428db85ULL,
    0x804245107230485aULL, 0x3e778736a0ed1671ULL, 0x6e2f129a08302f23ULL, 0x12248425ed3728f3ULL,
    0x82f42a1f81d1136bULL, 0x540c42f02931215dULL, 0x23a5e847c2111812ULL, 0x3d0b2f5d9f04130fULL,
    0xd0ec3264103135cbULL, 0x33e9b119131c4f6dULL, 0x3b1236166a010d2cULL, 0x8f22bc08226d7f02ULL,
    0x2641a0224d084ef7ULL, 0x0113f019f3f4c6eeULL, 0xd0291931ec87d3a0ULL, 0x217d83383a8862e3ULL,
    0xc44561081a29367dULL, 0x0d2948bc50a6311dULL, 0x1e3a681d33f20815ULL, 0x271f2803b0c515a8ULL,
    0x5a510f2c4180d297ULL, 0x619f727c4273c52eULL, 0xa4369f6e625a525fULL, 0x1a84f331d279e89bULL,
    0x854483ae5d8f6d6cULL, 0x116035860d5b128cULL, 0xa51ef3a1727937a0ULL, 0xa2f1025a1ff7f83eULL,
    0x4e6592288338e3a2ULL, 0x2a3e0f792e39dd8dULL, 0x048515c13e573a4aULL, 0xe28f41334c9c748eULL,
    0x4e082f61e272bb83ULL, 0x82d9213123c5ed8aULL, 0x8f466d735071141eULL, 0x93be2a95e263c7b2ULL,
    0x19273523f03bfe38ULL, 0x367f33eb0c7b32cbULL, 0xd17c0f1620c0245aULL, 0xa285f52317134448ULL,
    0x81d283c74b486a67ULL, 0x2077978d38cb090bULL, 0xbf9c39d885a02102ULL, 0x0d0370f2095cc606ULL,
    0x2036eb59ee02cb42ULL, 0x0d3f27f8087968aaULL, 0x4a123f1124622100ULL, 0x4778e178122a28e3ULL
};

} // namespace Cryptography

// constant-time binary gcd modular inverse algorithm
namespace NumberTheory {

BigInt ct_mod_inverse_binary_gcd(const BigInt& q, const BigInt& p) {
    size_t nbits = p.bit_len();
    size_t max_iterations = 2 * nbits;

    BigInt u = q;
    BigInt v = p;
    BigInt x1(1);
    BigInt x2(0);

    for (size_t i = 0; i < max_iterations; ++i) {
        bool u_is_even = u.is_even();

        BigInt u_shifted = BigInt::shift_right_1(u);
        BigInt x1_updated;
        if (!x1.is_even()) {
            x1_updated = BigInt::shift_right_1(BigInt::add(x1, p));
        } else {
            x1_updated = BigInt::shift_right_1(x1);
        }

        if (u_is_even) {
            u = u_shifted;
            x1 = x1_updated;
        } else {
            int cmp = BigInt::cmp(u, v);
            if (cmp >= 0) {
                u = BigInt::shift_right_1(BigInt::sub(u, v));
                
                BigInt temp;
                if (BigInt::cmp(x1, x2) < 0) {
                    temp = BigInt::sub(BigInt::add(x1, p), x2);
                } else {
                    temp = BigInt::sub(x1, x2);
                }
                if (!temp.is_even()) {
                    temp = BigInt::add(temp, p);
                }
                x1 = BigInt::shift_right_1(temp);
            } else {
                v = BigInt::shift_right_1(BigInt::sub(v, u));

                BigInt temp;
                if (BigInt::cmp(x2, x1) < 0) {
                    temp = BigInt::sub(BigInt::add(x2, p), x1);
                } else {
                    temp = BigInt::sub(x2, x1);
                }
                if (!temp.is_even()) {
                    temp = BigInt::add(temp, p);
                }
                x2 = BigInt::shift_right_1(temp);
            }
        }
    }

    BigInt inv = BigInt::mod(x1, p);
    return inv;
}

} // namespace NumberTheory

// OAEP  using sha-384
namespace OAEP {

constexpr size_t HLEN = 48;             // SHA-384 hash = 48 bytes
constexpr size_t KEY_BYTES_4096 = 512; // 4096 bits = 512 bytes

void mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len) {
    uint8_t counter_bytes[4];
    uint32_t counter = 0;
    size_t generated = 0;

    vector<uint8_t> buf(seed_len + 4);
    memcpy(buf.data(), seed, seed_len);

    uint8_t digest[HLEN];

    while (generated < mask_len) {
        counter_bytes[0] = static_cast<uint8_t>((counter >> 24) & 0xFF);
        counter_bytes[1] = static_cast<uint8_t>((counter >> 16) & 0xFF);
        counter_bytes[2] = static_cast<uint8_t>((counter >> 8) & 0xFF);
        counter_bytes[3] = static_cast<uint8_t>(counter & 0xFF);

        memcpy(buf.data() + seed_len, counter_bytes, 4);
        Cryptography::SHA384::hash(buf.data(), buf.size(), digest);

        size_t to_copy = min(HLEN, mask_len - generated);
        memcpy(mask + generated, digest, to_copy);

        generated += to_copy;
        counter++;
    }
}

vector<uint8_t> encode(const vector<uint8_t>& message, const vector<uint8_t>& seed) {
    size_t k = KEY_BYTES_4096;
    size_t max_msg_len = k - 2 * HLEN - 2;
    if (message.size() > max_msg_len) {
        throw invalid_argument("message too long for oaep-sha384");
    }

    uint8_t lHash[HLEN];
    Cryptography::SHA384::hash(nullptr, 0, lHash);

    size_t db_len = k - HLEN - 1;
    vector<uint8_t> DB(db_len, 0x00);

    memcpy(DB.data(), lHash, HLEN);
    size_t ps_len = db_len - HLEN - 1 - message.size();
    DB[HLEN + ps_len] = 0x01;
    if (!message.empty()) {
        memcpy(DB.data() + HLEN + ps_len + 1, message.data(), message.size());
    }

    vector<uint8_t> dbMask(db_len);
    mgf1(seed.data(), HLEN, dbMask.data(), db_len);

    vector<uint8_t> maskedDB(db_len);
    for (size_t i = 0; i < db_len; ++i) {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    vector<uint8_t> seedMask(HLEN);
    mgf1(maskedDB.data(), db_len, seedMask.data(), HLEN);

    vector<uint8_t> maskedSeed(HLEN);
    for (size_t i = 0; i < HLEN; ++i) {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    vector<uint8_t> EM(k, 0x00);
    memcpy(EM.data() + 1, maskedSeed.data(), HLEN);
    memcpy(EM.data() + 1 + HLEN, maskedDB.data(), db_len);

    return EM;
}

bool decode_constant_time(const vector<uint8_t>& EM, vector<uint8_t>& out_message) {
    size_t k = KEY_BYTES_4096;
    size_t db_len = k - HLEN - 1;

    if (EM.size() != k) return false;

    uint8_t error_mask = EM[0];

    const uint8_t* maskedSeed = EM.data() + 1;
    const uint8_t* maskedDB = EM.data() + 1 + HLEN;

    vector<uint8_t> seedMask(HLEN);
    mgf1(maskedDB, db_len, seedMask.data(), HLEN);

    vector<uint8_t> seed(HLEN);
    for (size_t i = 0; i < HLEN; ++i) {
        seed[i] = maskedSeed[i] ^ seedMask[i];
    }

    vector<uint8_t> dbMask(db_len);
    mgf1(seed.data(), HLEN, dbMask.data(), db_len);

    vector<uint8_t> DB(db_len);
    for (size_t i = 0; i < db_len; ++i) {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    uint8_t lHash[HLEN];
    Cryptography::SHA384::hash(nullptr, 0, lHash);
    for (size_t i = 0; i < HLEN; ++i) {
        error_mask |= (DB[i] ^ lHash[i]);
    }

    size_t one_index = 0;
    uint8_t found_one = 0;

    for (size_t i = HLEN; i < db_len; ++i) {
        uint8_t is_one = (DB[i] == 0x01) ? 1 : 0;
        uint8_t take = is_one & (~found_one);
        one_index = (take * i) | ((~take) & one_index);
        found_one |= is_one;
    }

    error_mask |= (found_one ^ 0x01);

    out_message.clear();
    if (error_mask == 0) {
        size_t msg_start = one_index + 1;
        out_message.assign(DB.begin() + msg_start, DB.end());
        return true;
    }

    return false;
}

} // namespace OAEP

// rsa key structure and garner algorithm decryption
struct RSAKey {
    BigInt N, e, d;
    BigInt p, q;
    BigInt dp, dq, qinv;
};

class RSACRTCore {
public:
    static BigInt encrypt(const BigInt& m, const RSAKey& key) {
        return BigInt::mod_pow(m, key.e, key.N);
    }

    static BigInt decrypt_crt(const BigInt& c, const RSAKey& key) {
        BigInt m1 = BigInt::mod_pow(c, key.dp, key.p);
        BigInt m2 = BigInt::mod_pow(c, key.dq, key.q);

        BigInt h;
        if (BigInt::cmp(m1, m2) < 0) {
            BigInt temp = BigInt::sub(BigInt::add(m1, key.p), m2);
            h = BigInt::mod(BigInt::mul(temp, key.qinv), key.p);
        } else {
            BigInt temp = BigInt::sub(m1, m2);
            h = BigInt::mod(BigInt::mul(temp, key.qinv), key.p);
        }

        BigInt m = BigInt::add(m2, BigInt::mul(h, key.q));
        return m;
    }
};

// entry point and verification flow
int main() {
    cout << "Initializing RSA-4096 parameters..." << endl;

    // valid 2048-bit prime numbers from rfc 3526 and rfc 7919
    string p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                  "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
                  "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
                  "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
                  "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
                  "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    string q_hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
                  "A9E13641146433FBCC939DCE249B3C1A2CA32741ACF12C5CD6179E40B01D9D99"
                  "99059F5441D91E4759451996E252D5E0FA716F3D3C1F4FA87F3B563D5F5494C0"
                  "1C6615EC8225A7BD9142EE8D105D5C328227B6F7F6F5711C750B69FB5E0325B5"
                  "91B65B706C8369ECF2054B1F6305F884A234204646DF72E293A52140C836DDF2"
                  "1A3615F8A002BC0681A953E5F18C642E059F131A4BE911DDF47F202513F57F6B"
                  "0FDD6476579899138F3223030467C9D924190C1F576E27A6C9E0C7A5F3E79C29"
                  "3677464A4D6820C78A0558DD3F271171810931557D079366DF0473EF226D41BE"
                  "20042D3844D1FFFFFFFFFFFFFFFF";

    RSAKey key;
    key.p = BigInt::from_hex(p_hex);
    key.q = BigInt::from_hex(q_hex);
    key.N = BigInt::mul(key.p, key.q);
    key.e = BigInt(65537);

    // key generation parameters calculation
    BigInt p_1 = BigInt::sub(key.p, BigInt(1));
    BigInt q_1 = BigInt::sub(key.q, BigInt(1));
    BigInt phi = BigInt::mul(p_1, q_1);

    key.d = NumberTheory::ct_mod_inverse_binary_gcd(key.e, phi);
    key.dp = BigInt::mod(key.d, p_1);
    key.dq = BigInt::mod(key.d, q_1);
    key.qinv = NumberTheory::ct_mod_inverse_binary_gcd(key.q, key.p);

    cout << "[+] Keys p and q successfully loaded (2048-bit RFC primes)." << endl;
    cout << "[+] Calculated private key d and CRT parameters (dp, dq)." << endl;
    cout << "[+] Calculated q_inv using binary GCD algorithm." << endl;

    vector<uint8_t> secret_msg = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
    vector<uint8_t> seed(OAEP::HLEN, 0x3C);

    // 1. oaep encoding
    vector<uint8_t> EM = OAEP::encode(secret_msg, seed);
    cout << "[+] OAEP padding created." << endl;

    // 2. rsa encryption
    BigInt m = BigInt::from_bytes(EM);
    BigInt c = RSACRTCore::encrypt(m, key);
    cout << "[+] RSA encryption completed." << endl;

    // 3. rsa decryption via garner's crt
    BigInt decrypted_m = RSACRTCore::decrypt_crt(c, key);
    cout << "[+] RSA decryption using Garner's CRT completed." << endl;

    // 4. bytes extraction and oaep decoding
    vector<uint8_t> decrypted_EM = decrypted_m.to_bytes(OAEP::KEY_BYTES_4096);

    vector<uint8_t> recovered_msg;
    if (OAEP::decode_constant_time(decrypted_EM, recovered_msg)) {
        cout << "[+] Successfully decrypted: ";
        for (char ch : recovered_msg) cout << ch;
        cout << endl;
    } else {
        cout << "[-] OAEP decoding error!" << endl;
    }

    return 0;
}
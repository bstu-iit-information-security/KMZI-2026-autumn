#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>


// SHA-256
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

void sha256(const uint8_t* data, size_t len, std::array<uint8_t, 32>& out) {
    uint32_t state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    std::vector<uint8_t> padded(data, data + len);
    padded.push_back(0x80);
    while ((padded.size() % 64) != 56) padded.push_back(0x00);
    uint64_t bit_len = len * 8;
    for (int i = 7; i >= 0; --i) padded.push_back((bit_len >> (i * 8)) & 0xFF);
    
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32_t m[64];
        for (int j = 0, k = 0; j < 16; ++j, k += 4)
            m[j] = (padded[i + k] << 24) | (padded[i + k + 1] << 16) | (padded[i + k + 2] << 8) | (padded[i + k + 3]);
        for (int j = 16; j < 64; ++j)
            m[j] = SIG1(m[j - 2]) + m[j - 7] + SIG0(m[j - 15]) + m[j - 16];
            
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], f = state[5], g = state[6], h = state[7];
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = h + EP1(e) + CH(e, f, g) + SHA256_K[j] + m[j];
            uint32_t t2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
    
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (state[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        out[i * 4 + 3] = state[i] & 0xFF;
    }
}

constexpr size_t BIGINT_WORDS = 96;      // 3072 бита
constexpr size_t BIGINT_DOUBLE_WORDS = 192; // 6144 бита
constexpr size_t BIGINT_BITS = 3072;

struct BigIntDouble {
    std::array<uint32_t, BIGINT_DOUBLE_WORDS> digits = {0};
};

class BigInt {
public:
    std::array<uint32_t, BIGINT_WORDS> digits = {0};

    BigInt() {}
    BigInt(uint64_t val) {
        digits[0] = static_cast<uint32_t>(val & 0xFFFFFFFF);
        digits[1] = static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF);
    }

    bool testBit(size_t index) const {
        if (index >= BIGINT_BITS) return false;
        return (digits[index / 32] >> (index % 32)) & 1;
    }

    bool isEven() const { return (digits[0] & 1) == 0; }

    BigInt shiftRight1() const {
        BigInt res;
        uint32_t carry = 0;
        for (int i = BIGINT_WORDS - 1; i >= 0; --i) {
            uint64_t cur = (static_cast<uint64_t>(carry) << 32) | digits[i];
            res.digits[i] = static_cast<uint32_t>(cur >> 1);
            carry = digits[i] & 1;
        }
        return res;
    }

    bool operator==(const BigInt& other) const {
        uint32_t diff = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) diff |= (digits[i] ^ other.digits[i]);
        return diff == 0;
    }

    bool operator<(const BigInt& other) const {
        uint32_t borrow = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            int64_t diff = static_cast<int64_t>(digits[i]) - other.digits[i] - borrow;
            borrow = (diff < 0) ? 1 : 0;
        }
        return borrow == 1;
    }

    BigInt operator+(const BigInt& other) const {
        BigInt res;
        uint64_t carry = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            uint64_t sum = static_cast<uint64_t>(digits[i]) + other.digits[i] + carry;
            res.digits[i] = static_cast<uint32_t>(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        return res;
    }

    BigInt operator-(const BigInt& other) const {
        BigInt res;
        int64_t borrow = 0;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            int64_t diff = static_cast<int64_t>(digits[i]) - other.digits[i] - borrow;
            if (diff < 0) { diff += 0x100000000LL; borrow = 1; } 
            else { borrow = 0; }
            res.digits[i] = static_cast<uint32_t>(diff);
        }
        return res;
    }

    BigIntDouble operator*(const BigInt& other) const {
        BigIntDouble res;
        for (size_t i = 0; i < BIGINT_WORDS; ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                uint64_t cur = res.digits[i + j] + static_cast<uint64_t>(digits[i]) * other.digits[j] + carry;
                res.digits[i + j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
            res.digits[i + BIGINT_WORDS] += carry;
        }
        return res;
    }

    BigInt modDouble(const BigIntDouble& num) const {
        BigInt remainder;
        for (int i = BIGINT_DOUBLE_WORDS - 1; i >= 0; --i) {
            for (int bit = 31; bit >= 0; --bit) {
                uint32_t carry_rem = 0;
                for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                    uint64_t cur = (static_cast<uint64_t>(remainder.digits[j]) << 1) | carry_rem;
                    remainder.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                    carry_rem = static_cast<uint32_t>(cur >> 32);
                }
                if ((num.digits[i] >> bit) & 1) remainder.digits[0] |= 1;

                if (!(remainder < *this)) remainder = remainder - *this;
            }
        }
        return remainder;
    }

    BigInt operator%(const BigInt& divisor) const {
        BigIntDouble ext;
        std::copy(digits.begin(), digits.end(), ext.digits.begin());
        return divisor.modDouble(ext);
    }
    
    // Вспомогательное деление для генерации ключей
    std::pair<BigInt, BigInt> divmod(const BigInt& divisor) const {
        BigInt quotient, remainder;
        for (int i = BIGINT_WORDS - 1; i >= 0; --i) {
            for (int bit = 31; bit >= 0; --bit) {
                uint32_t carry_rem = 0;
                for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                    uint64_t cur = (static_cast<uint64_t>(remainder.digits[j]) << 1) | carry_rem;
                    remainder.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                    carry_rem = static_cast<uint32_t>(cur >> 32);
                }
                if ((digits[i] >> bit) & 1) remainder.digits[0] |= 1;

                if (!(remainder < divisor)) {
                    remainder = remainder - divisor;
                    uint32_t carry_quot = 0;
                    for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                        uint64_t cur = (static_cast<uint64_t>(quotient.digits[j]) << 1) | carry_quot;
                        quotient.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                        carry_quot = static_cast<uint32_t>(cur >> 32);
                    }
                    quotient.digits[0] |= 1;
                } else {
                    uint32_t carry_quot = 0;
                    for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                        uint64_t cur = (static_cast<uint64_t>(quotient.digits[j]) << 1) | carry_quot;
                        quotient.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                        carry_quot = static_cast<uint32_t>(cur >> 32);
                    }
                }
            }
        }
        return { quotient, remainder };
    }
    BigInt operator/(const BigInt& other) const { return divmod(other).first; }
};

BigInt bytesToBigInt(const std::array<uint8_t, 384>& data) {
    BigInt res;
    for(size_t i = 0; i < 384; ++i) {
        size_t wordIdx = (383 - i) / 4;
        size_t byteIdx = (383 - i) % 4;
        res.digits[wordIdx] |= static_cast<uint32_t>(data[i]) << (byteIdx * 8);
    }
    return res;
}

void bigIntToBytes(const BigInt& val, std::array<uint8_t, 384>& out) {
    for(size_t i = 0; i < 384; ++i) {
        size_t wordIdx = (383 - i) / 4;
        size_t byteIdx = (383 - i) % 4;
        out[i] = (val.digits[wordIdx] >> (byteIdx * 8)) & 0xFF;
    }
}

namespace RSACore {
    struct RSAKeys { BigInt N, e, d, p, q, dp, dq, qInv; };
}

namespace Math {
    BigInt modularExponentiationJoyeTun(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
        BigInt R[2];
        R[0] = BigInt(1);
        R[1] = base % modulus;
        
        for (int i = BIGINT_BITS - 1; i >= 0; --i) {
            size_t b = exp.testBit(i) ? 1 : 0;
            size_t not_b = 1 - b;
            BigInt multiplied = modulus.modDouble(R[0] * R[1]);
            BigInt squared = modulus.modDouble(R[b] * R[b]);
            R[not_b] = multiplied;
            R[b] = squared;
        }
        return R[0];
    }

    BigInt generateRandomBigInt(size_t bitLen) {
        BigInt res;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
        size_t words = bitLen / 32;
        for (size_t i = 0; i < words; ++i) res.digits[i] = dist(gen);
        res.digits[0] |= 1;
        res.digits[words - 1] |= (1U << ((bitLen % 32) == 0 ? 31 : (bitLen % 32) - 1));
        return res;
    }

    bool millerRabinTest(const BigInt& n, int k) {
        if (n.isEven() || n == BigInt(1)) return false;
        if (n == BigInt(2) || n == BigInt(3)) return true;
        BigInt n_minus_1 = n - BigInt(1);
        BigInt d = n_minus_1;
        int s = 0;
        
        while (d.isEven()) {
            d = d.shiftRight1();
            s++;
        }

        for (int i = 0; i < k; ++i) {
            BigInt a = generateRandomBigInt(1024); 
            if (!(a < n_minus_1)) a = a % n_minus_1;
            if (a == BigInt(0) || a == BigInt(1)) a = BigInt(2);
            BigInt x = modularExponentiationJoyeTun(a, d, n);
            if (x == BigInt(1) || x == n_minus_1) continue;
            bool isComposite = true;
            for (int r = 1; r < s; ++r) {
                x = modularExponentiationJoyeTun(x, BigInt(2), n);
                if (x == n_minus_1) {
                    isComposite = false;
                    break;
                }
            }
            if (isComposite) return false;
        }
        return true;
    }

    BigInt generateLargePrime(size_t bitLen) {
        while (true) {
            BigInt candidate = generateRandomBigInt(bitLen);
            if (millerRabinTest(candidate, 10)) return candidate;
        }
    }

    BigInt modInverse(BigInt a, BigInt m) {
        BigInt m0 = m, t, q;
        BigInt x0 = BigInt(0), x1 = BigInt(1);
        if (m == BigInt(1)) return BigInt(0);
        while (a > BigInt(1)) {
            auto dm = a.divmod(m0);
            q = dm.first;
            t = m0;
            m0 = dm.second;
            a = t;
            t = x0;
            BigIntDouble qx0_ext = q * x0;
            BigInt qx0 = m.modDouble(qx0_ext); 
            if (x1 < qx0) {
                BigInt diff = qx0 - x1;
                BigInt rem = diff % m;
                x0 = (rem == BigInt(0)) ? BigInt(0) : (m - rem);
            } else {
                x0 = x1 - qx0;
            }
            x1 = t;
        }
        return x1;
    }

    RSACore::RSAKeys generateRSAKeys() {
        RSACore::RSAKeys keys;
        size_t primeBits = 1536; // Для N = 3072
        
        //генерация 1536-битных простых чисел может занять продолжительное время.
        std::cout << "   [+] Генерация p..." << std::endl;
        keys.p = generateLargePrime(primeBits);
        std::cout << "   [+] Генерация q..." << std::endl;
        keys.q = generateLargePrime(primeBits);
        if (keys.p < keys.q) std::swap(keys.p, keys.q);

        BigIntDouble n_ext = keys.p * keys.q;
        keys.N = keys.N + n_ext.digits[0];
        for(size_t i = 0; i < BIGINT_WORDS; ++i) keys.N.digits[i] = n_ext.digits[i];

        BigInt phi;
        BigIntDouble phi_ext = (keys.p - BigInt(1)) * (keys.q - BigInt(1));
        for(size_t i = 0; i < BIGINT_WORDS; ++i) phi.digits[i] = phi_ext.digits[i];

        keys.e = BigInt(65537);
        keys.d = modInverse(keys.e, phi);
        keys.dp = keys.d % (keys.p - BigInt(1));
        keys.dq = keys.d % (keys.q - BigInt(1));
        keys.qInv = modInverse(keys.q, keys.p);
        return keys;
    }
}

namespace RSACore {
    BigInt encrypt(const BigInt& m, const RSAKeys& keys) {
        return Math::modularExponentiationJoyeTun(m, keys.e, keys.N);
    }

    BigInt decryptCRT(const BigInt& c, const RSAKeys& keys) {
        BigInt m1 = Math::modularExponentiationJoyeTun(c, keys.dp, keys.p);
        BigInt m2 = Math::modularExponentiationJoyeTun(c, keys.dq, keys.q);
        BigInt diff;
        if (m1 < m2) diff = m1 + keys.p - m2;
        else diff = m1 - m2;
        
        BigInt h = keys.p.modDouble(keys.qInv * diff);
        return m2 + keys.N.modDouble(h * keys.q);
    }
}

namespace OAEP {
    constexpr size_t k = 384;      
    constexpr size_t hLen = 32;    
    
    void MGF1(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen) {
        std::array<uint8_t, 32> hashOut;
        std::array<uint8_t, 384> buffer = {0}; 
        std::memcpy(buffer.data(), seed, seedLen);
        
        size_t offset = 0;
        uint32_t counter = 0;
        
        while (offset < maskLen) {
            buffer[seedLen] = (counter >> 24) & 0xFF;
            buffer[seedLen + 1] = (counter >> 16) & 0xFF;
            buffer[seedLen + 2] = (counter >> 8) & 0xFF;
            buffer[seedLen + 3] = counter & 0xFF;
            
            sha256(buffer.data(), seedLen + 4, hashOut);
            size_t copyLen = std::min(hLen, maskLen - offset);
            std::memcpy(mask + offset, hashOut.data(), copyLen);
            offset += copyLen;
            counter++;
        }
    }

    bool padOAEP(const std::vector<uint8_t>& message, std::array<uint8_t, k>& EM) {
        if (message.size() > k - 2 * hLen - 2) return false;

        EM.fill(0);
        std::array<uint8_t, hLen> lHashCalc;
        sha256(nullptr, 0, lHashCalc); 

        std::array<uint8_t, k - hLen - 1> DB;
        DB.fill(0);
        std::memcpy(DB.data(), lHashCalc.data(), hLen);
        
        size_t psLen = (k - hLen - 1) - message.size() - hLen - 1;
        DB[hLen + psLen] = 0x01; 
        std::memcpy(DB.data() + hLen + psLen + 1, message.data(), message.size());

        std::array<uint8_t, hLen> seed;
        std::random_device rd;
        for (size_t i = 0; i < hLen; ++i) {
            seed[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        std::array<uint8_t, k - hLen - 1> dbMask;
        MGF1(seed.data(), hLen, dbMask.data(), k - hLen - 1);
        for (size_t i = 0; i < k - hLen - 1; ++i) DB[i] ^= dbMask[i];

        std::array<uint8_t, hLen> seedMask;
        MGF1(DB.data(), k - hLen - 1, seedMask.data(), hLen);
        for (size_t i = 0; i < hLen; ++i) seed[i] ^= seedMask[i];

        EM[0] = 0x00;
        std::memcpy(EM.data() + 1, seed.data(), hLen);
        std::memcpy(EM.data() + 1 + hLen, DB.data(), k - hLen - 1);
        return true;
    }

    bool unpadOAEP(std::array<uint8_t, k>& EM, std::array<uint8_t, k>& outMessage, size_t& outLen) {
        uint8_t error_mask = 0;
        error_mask |= EM[0];
        
        std::array<uint8_t, hLen> seedMask;
        MGF1(&EM[1 + hLen], k - hLen - 1, seedMask.data(), hLen);
        std::array<uint8_t, hLen> seed;
        for (size_t i = 0; i < hLen; ++i) seed[i] = EM[1 + i] ^ seedMask[i];
        
        std::array<uint8_t, k - hLen - 1> dbMask;
        MGF1(seed.data(), hLen, dbMask.data(), k - hLen - 1);
        std::array<uint8_t, k - hLen - 1> DB;
        for (size_t i = 0; i < k - hLen - 1; ++i) DB[i] = EM[1 + hLen + i] ^ dbMask[i];
        
        std::array<uint8_t, hLen> lHashCalc;
        sha256(nullptr, 0, lHashCalc); 
        for (size_t i = 0; i < hLen; ++i) error_mask |= (DB[i] ^ lHashCalc[i]); 
        
        uint8_t found_01 = 0;
        size_t msg_index = 0;
        
        for (size_t i = hLen; i < k - hLen - 1; ++i) {
            uint8_t is_01 = (DB[i] == 0x01) & ~found_01;
            uint8_t is_zero = (DB[i] == 0x00);
            error_mask |= (~found_01 & ~is_01 & ~is_zero);
            msg_index = (is_01 * (i + 1)) | (~is_01 * msg_index);
            found_01 |= is_01;
        }
        
        error_mask |= ~found_01; 
        if (error_mask == 0) {
            outLen = (k - hLen - 1) - msg_index;
            std::memcpy(outMessage.data(), DB.data() + msg_index, outLen);
            return true;
        }
        return false;
    }
}

int main() {
    std::cout << " Инициализация ядра RSA 3072-bit (Генерация займет время)...\n";
    RSACore::RSAKeys keys = Math::generateRSAKeys();
    
    std::string text = "ЭТО ОЧЕНЬ СТРАШНАЯ ЛАБА";
    std::vector<uint8_t> message(text.begin(), text.end());
    
    std::array<uint8_t, OAEP::k> EM;
    if (OAEP::padOAEP(message, EM)) {
        std::cout << " Упаковка OAEP выполнена.\n";
    }
    
    std::cout << " Шифрование (Constant-Time Joye-Tun)...\n";
    BigInt m_bigint = bytesToBigInt(EM);
    BigInt c = RSACore::encrypt(m_bigint, keys);
    
    std::cout << " Расшифрование (CRT Гарнер)...\n";
    BigInt decrypted_m = RSACore::decryptCRT(c, keys);
    
    std::array<uint8_t, OAEP::k> decrypted_EM;
    bigIntToBytes(decrypted_m, decrypted_EM);
    
    std::array<uint8_t, OAEP::k> original_message;
    size_t msg_len = 0;
    
    std::cout << " Деинкапсуляция и проверка...\n";
    bool isValid = OAEP::unpadOAEP(decrypted_EM, original_message, msg_len);
    
    if (isValid) {
        std::string outStr(original_message.begin(), original_message.begin() + msg_len);
        std::cout << "\n Извлеченное сообщение: " << outStr << "\n";
    } else {
        std::cout << "\n Нарушение целостности OAEP (Атака Блейхенбахера не прошла)\n";
    }
    
    return 0;
}
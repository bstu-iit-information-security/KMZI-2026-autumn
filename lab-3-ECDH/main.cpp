#include <iostream>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

// SHA-512 (Без динамического выделения памяти)

static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_64(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_64(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_64(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_64(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

void sha512(const uint8_t* data, size_t len, std::array<uint8_t, 64>& out) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    };

    size_t padded_len = len + 1;
    while (padded_len % 128 != 112) padded_len++;
    padded_len += 16;

    std::array<uint8_t, 256> chunk; // Буфер для обработки
    size_t offset = 0;

    for (size_t i = 0; i < padded_len; i += 128) {
        chunk.fill(0);
        for (size_t j = 0; j < 128; ++j) {
            size_t data_idx = i + j;
            if (data_idx < len) chunk[j] = data[data_idx];
            else if (data_idx == len) chunk[j] = 0x80;
        }

        if (i + 128 >= padded_len) {
            uint64_t bit_len = len * 8;
            for (int j = 7; j >= 0; --j) chunk[120 + j] = (bit_len >> (56 - j * 8)) & 0xFF;
        }

        uint64_t m[80];
        for (int j = 0; j < 16; ++j) {
            m[j] = 0;
            for (int k = 0; k < 8; ++k) m[j] = (m[j] << 8) | chunk[j * 8 + k];
        }
        for (int j = 16; j < 80; ++j) {
            m[j] = SIG1_64(m[j - 2]) + m[j - 7] + SIG0_64(m[j - 15]) + m[j - 16];
        }

        uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int j = 0; j < 80; ++j) {
            uint64_t t1 = h + EP1_64(e) + CH64(e, f, g) + SHA512_K[j] + m[j];
            uint64_t t2 = EP0_64(a) + MAJ64(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) out[i * 8 + j] = (state[i] >> (56 - j * 8)) & 0xFF;
    }
}

constexpr size_t BIGINT_WORDS = 10;       // 320 бит
constexpr size_t BIGINT_DOUBLE_WORDS = 20; // 640 бит
constexpr size_t BIGINT_BITS = 320;

struct BigIntDouble {
    std::array<uint32_t, BIGINT_DOUBLE_WORDS> digits = { 0 };
};

class BigInt {
public:
    std::array<uint32_t, BIGINT_WORDS> digits = { 0 };

    BigInt() {}
    BigInt(uint64_t val) {
        digits[0] = static_cast<uint32_t>(val & 0xFFFFFFFF);
        digits[1] = static_cast<uint32_t>((val >> 32) & 0xFFFFFFFF);
    }

    BigInt(const std::string& hex) {
        std::string h = hex;
        if (h.length() % 8 != 0) h = std::string(8 - (h.length() % 8), '0') + h;
        size_t word_idx = 0;
        for (int i = (int)h.length() - 8; i >= 0 && word_idx < BIGINT_WORDS; i -= 8) {
            digits[word_idx++] = std::stoul(h.substr(i, 8), nullptr, 16);
        }
    }

    std::string ToHexString() const {
        std::stringstream ss;
        bool started = false;
        for (int i = BIGINT_WORDS - 1; i >= 0; --i) {
            if (digits[i] != 0 || started || i == 0) {
                if (started) ss << std::setfill('0') << std::setw(8) << std::hex << digits[i];
                else ss << std::hex << digits[i];
                started = true;
            }
        }
        return ss.str();
    }

    bool testBit(size_t index) const {
        if (index >= BIGINT_BITS) return false;
        return (digits[index / 32] >> (index % 32)) & 1;
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

                uint32_t carry_quot = 0;
                for (size_t j = 0; j < BIGINT_WORDS; ++j) {
                    uint64_t cur = (static_cast<uint64_t>(quotient.digits[j]) << 1) | carry_quot;
                    quotient.digits[j] = static_cast<uint32_t>(cur & 0xFFFFFFFF);
                    carry_quot = static_cast<uint32_t>(cur >> 32);
                }

                if (!(remainder < divisor)) {
                    remainder = remainder - divisor;
                    quotient.digits[0] |= 1;
                }
            }
        }
        return { quotient, remainder };
    }
    BigInt operator/(const BigInt& other) const { return divmod(other).first; }
};

BigInt ModAdd(const BigInt& a, const BigInt& b, const BigInt& p) { return (a + b) % p; }
BigInt ModSub(const BigInt& a, const BigInt& b, const BigInt& p) {
    return (a < b) ? (p - (b - a)) % p : (a - b) % p;
}
BigInt ModMul(const BigInt& a, const BigInt& b, const BigInt& p) {
    return p.modDouble(a * b);
}
BigInt ModInverse(BigInt a, BigInt m) {
    BigInt m0 = m, t, q;
    BigInt x0 = BigInt(0), x1 = BigInt(1);

    if (m == BigInt(1)) return BigInt(0);

    // ИСПРАВЛЕНИЕ: строгое условие (a > 1)
    while (BigInt(1) < a) {
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
        }
        else {
            x0 = x1 - qx0;
        }
        x1 = t;
    }
    return x1;
}
// Параметры Ed25519 (в виде Hex-строк)
const BigInt p_val("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
// a = -1 mod p (что эквивалентно p - 1)
const BigInt a_val("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec");
const BigInt d_val("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
const BigInt q_val("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

// Базовая точка G (аффинные координаты(x,y))
const BigInt Gx("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
const BigInt Gy("6666666666666666666666666666666666666666666666666666666666666658");

struct PointProjective { BigInt X; BigInt Y; BigInt Z; };
const PointProjective BasePointG = { Gx, Gy, BigInt(1) };
const PointProjective PointZero = { BigInt(0), BigInt(1), BigInt(1) };

BigInt ProjectiveToAffineX(const PointProjective& P) {
    BigInt Z_inv = ModInverse(P.Z, p_val);
    return ModMul(P.X, Z_inv, p_val);
}
BigInt ProjectiveToAffineY(const PointProjective& P) {
    BigInt Z_inv = ModInverse(P.Z, p_val);
    return ModMul(P.Y, Z_inv, p_val);
}


PointProjective UnifiedAddConstantTime(const PointProjective& P1, const PointProjective& P2) {
    PointProjective P3;
    BigInt A = ModMul(P1.Z, P2.Z, p_val);
    BigInt B = ModMul(A, A, p_val);
    BigInt C = ModMul(P1.X, P2.X, p_val);
    BigInt D = ModMul(P1.Y, P2.Y, p_val);
    BigInt E = ModMul(ModMul(d_val, C, p_val), D, p_val);

    BigInt sumXY1 = ModAdd(P1.X, P1.Y, p_val);
    BigInt sumXY2 = ModAdd(P2.X, P2.Y, p_val);
    BigInt term1 = ModSub(ModSub(ModMul(sumXY1, sumXY2, p_val), C, p_val), D, p_val);
    P3.X = ModMul(ModMul(A, term1, p_val), ModSub(B, E, p_val), p_val);

    BigInt term2 = ModSub(D, ModMul(a_val, C, p_val), p_val);
    P3.Y = ModMul(ModMul(A, term2, p_val), ModAdd(B, E, p_val), p_val);
    P3.Z = ModMul(ModSub(B, E, p_val), ModAdd(B, E, p_val), p_val);
    return P3;
}

PointProjective ConstantTimeSelect(bool bit, const PointProjective& P_True, const PointProjective& P_False) {
    PointProjective res;
    uint32_t mask = bit ? 0xFFFFFFFF : 0x00000000;
    for (size_t i = 0; i < BIGINT_WORDS; ++i) {
        res.X.digits[i] = (P_True.X.digits[i] & mask) | (P_False.X.digits[i] & ~mask);
        res.Y.digits[i] = (P_True.Y.digits[i] & mask) | (P_False.Y.digits[i] & ~mask);
        res.Z.digits[i] = (P_True.Z.digits[i] & mask) | (P_False.Z.digits[i] & ~mask);
    }
    return res;
}

PointProjective SecureScalarMultiply(const BigInt& d, const PointProjective& G) {
    PointProjective Q = PointZero;
    PointProjective R = G;
    // 256 итераций вне зависимости от длины ключа
    for (int i = 0; i < 256; ++i) {
        bool bit = d.testBit(i);
        PointProjective TempQ = UnifiedAddConstantTime(Q, R);
        Q = ConstantTimeSelect(bit, TempQ, Q);
        R = UnifiedAddConstantTime(R, R);
    }
    return Q;
}

// ПРОТОКОЛЫ ECDH И EdDSA

BigInt HashToBigInt(const std::string& data) {
    std::array<uint8_t, 64> hashOut;
    sha512(reinterpret_cast<const uint8_t*>(data.c_str()), data.length(), hashOut);
    std::string hexHash;
    for (uint8_t b : hashOut) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hexHash += buf;
    }
    return BigInt(hexHash);
}

struct Signature { PointProjective R; BigInt S; };

Signature EdDSASign(const BigInt& d, const PointProjective& PublicKey, const std::string& message) {
    Signature sig;
    BigInt r = HashToBigInt(d.ToHexString() + message) % q_val; // Детерминированный эфемерный ключ
    sig.R = SecureScalarMultiply(r, BasePointG);

    std::string h_input = ProjectiveToAffineX(sig.R).ToHexString() +
        ProjectiveToAffineX(PublicKey).ToHexString() + message;
    BigInt h = HashToBigInt(h_input) % q_val;
    sig.S = ModAdd(r, ModMul(h, d, q_val), q_val);
    return sig;
}

bool EdDSAVerify(const PointProjective& PublicKey, const std::string& message, const Signature& sig) {
    std::string h_input = ProjectiveToAffineX(sig.R).ToHexString() +
        ProjectiveToAffineX(PublicKey).ToHexString() + message;
    BigInt h = HashToBigInt(h_input) % q_val;

    PointProjective SG = SecureScalarMultiply(sig.S, BasePointG);
    PointProjective hA = SecureScalarMultiply(h, PublicKey);
    PointProjective RightSide = UnifiedAddConstantTime(sig.R, hA);

    return (ProjectiveToAffineX(SG) == ProjectiveToAffineX(RightSide)) &&
        (ProjectiveToAffineY(SG) == ProjectiveToAffineY(RightSide));
}


int main() {
    setlocale(LC_ALL, "RU");
    std::cout << "--- Алгебра Эдвардса (Ed25519) и Constant-Time Ядро ---\n\n";

    // Секретные ключи в шестнадцатеричном виде
    BigInt d_Alice("4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d");
    BigInt d_Bob("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b");

    PointProjective Q_Alice = SecureScalarMultiply(d_Alice, BasePointG);
    PointProjective Q_Bob = SecureScalarMultiply(d_Bob, BasePointG);

    std::cout << "[1] Тестирование ECDH...\n";
    PointProjective SharedSecretAlice = SecureScalarMultiply(d_Alice, Q_Bob);
    PointProjective SharedSecretBob = SecureScalarMultiply(d_Bob, Q_Alice);

    std::cout << "Секрет Алисы (X): " << ProjectiveToAffineX(SharedSecretAlice).ToHexString() << "\n";
    std::cout << "Секрет Боба  (X): " << ProjectiveToAffineX(SharedSecretBob).ToHexString() << "\n";

    if (ProjectiveToAffineX(SharedSecretAlice) == ProjectiveToAffineX(SharedSecretBob)) {
        std::cout << "[+] Успех: Общие секреты совпадают.\n\n";
    }

    std::cout << "[2] Тестирование цифровой подписи EdDSA (Ed25519)...\n";
    std::string message = "Cryptographic Test Message";
    Signature sig = EdDSASign(d_Alice, Q_Alice, message);

    std::cout << "Подпись R (X): " << ProjectiveToAffineX(sig.R).ToHexString() << "\n";
    std::cout << "Подпись S:     " << sig.S.ToHexString() << "\n";

    bool isValid = EdDSAVerify(Q_Alice, message, sig);
    std::cout << (isValid ? "[+] Успех: Подпись математически верна.\n\n" : "[-] Ошибка: Подпись недействительна.\n\n");

    std::cout << "[3] Проверка отбраковки искаженной подписи...\n";
    Signature tamperedSig = sig;
    tamperedSig.S = tamperedSig.S + BigInt(1); // Искажаем S
    bool isTamperedValid = EdDSAVerify(Q_Alice, message, tamperedSig);

    std::cout << (isTamperedValid ? "[-] Провал: Искаженная подпись принята.\n"
        : "[+] Успех: Искаженная подпись корректно отклонена.\n");

    return 0;
}
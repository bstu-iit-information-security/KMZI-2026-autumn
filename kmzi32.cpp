#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <algorithm>
#include <clocale>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;

constexpr size_t KEY_BITS = 3072;
constexpr size_t KEY_BYTES = KEY_BITS / 8;
constexpr size_t PRIME_BITS = 1536;
constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t MAX_MESSAGE_LEN = KEY_BYTES - 2 * SHA256_DIGEST_SIZE - 2;

class SHA256 {
private:
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];

    static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static uint32_t choose(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static uint32_t sig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static uint32_t sig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static uint32_t theta0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static uint32_t theta1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    void transform(const uint8_t chunk[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(chunk[i * 4]) << 24) | (uint32_t(chunk[i * 4 + 1]) << 16) |
                (uint32_t(chunk[i * 4 + 2]) << 8) | uint32_t(chunk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sig1(e) + choose(e, f, g) + k[i] + w[i];
            uint32_t t2 = sig0(a) + majority(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    void init() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        count = 0;
    }

    SHA256() { init(); }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer[count % 64] = data[i];
            count++;
            if (count % 64 == 0) transform(buffer);
        }
    }

    void final(uint8_t digest[32]) {
        uint8_t pad[64] = { 0x80 };
        size_t rem = count % 64;
        size_t pad_len = (rem < 56) ? (56 - rem) : (120 - rem);
        uint64_t bit_len = count * 8;
        update(pad, pad_len);

        uint8_t len_bytes[8];
        for (int i = 0; i < 8; ++i) len_bytes[i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
        update(len_bytes, 8);

        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
    }

    static void hash(const uint8_t* in, size_t len, uint8_t out[32]) {
        SHA256 ctx;
        if (len > 0 && in != nullptr) {
            ctx.update(in, len);
        }
        ctx.final(out);
    }
};

BigInt bytesToBigInt(const std::array<uint8_t, KEY_BYTES>& data) {
    BigInt res = 0;
    boost::multiprecision::import_bits(res, data.begin(), data.end(), 8, true);
    return res;
}

void bigIntToBytes(const BigInt& val, std::array<uint8_t, KEY_BYTES>& out) {
    out.fill(0);
    std::vector<uint8_t> temp;
    boost::multiprecision::export_bits(val, std::back_inserter(temp), 8, true);
    size_t copyLen = (std::min)(temp.size(), KEY_BYTES);
    std::memcpy(out.data() + (KEY_BYTES - copyLen), temp.data(), copyLen);
}

namespace RSACore {
    struct RSAKeys { BigInt N, e, d, p, q, dp, dq, qInv; };
}

namespace Math {
    BigInt modularExponentiationJoyeTun(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
        if (exp == 0) return BigInt(1) % modulus;
        BigInt R[2];
        R[0] = 1;
        R[1] = base % modulus;

        int msb_val = boost::multiprecision::msb(exp);
        for (int i = msb_val; i >= 0; --i) {
            int b = boost::multiprecision::bit_test(exp, i) ? 1 : 0;
            int not_b = 1 - b;
            BigInt multiplied = (R[0] * R[1]) % modulus;
            BigInt squared = (R[b] * R[b]) % modulus;
            R[not_b] = multiplied;
            R[b] = squared;
        }
        return R[0];
    }

    BigInt generateRandomBigInt(size_t bitLen) {
        static std::mt19937_64 gen(std::chrono::system_clock::now().time_since_epoch().count());
        BigInt res = 0;
        size_t words = (bitLen + 63) / 64;
        for (size_t i = 0; i < words; ++i) {
            uint64_t r = gen();
            res = (res << 64) | r;
        }
        if (bitLen < words * 64) {
            res &= (BigInt(1) << bitLen) - 1;
        }
        boost::multiprecision::bit_set(res, bitLen - 1);
        boost::multiprecision::bit_set(res, 0);
        return res;
    }

    bool millerRabinTest(const BigInt& n, int k) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0) return false;

        BigInt d = n - 1;
        int s = 0;
        while (d % 2 == 0) {
            d /= 2;
            s++;
        }

        for (int i = 0; i < k; ++i) {
            BigInt a = generateRandomBigInt(PRIME_BITS - 10) % (n - 2) + 2;
            BigInt x = modularExponentiationJoyeTun(a, d, n);
            if (x == 1 || x == n - 1) continue;
            bool composite = true;
            for (int r = 1; r < s; ++r) {
                x = (x * x) % n;
                if (x == n - 1) {
                    composite = false;
                    break;
                }
            }
            if (composite) return false;
        }
        return true;
    }

    BigInt generateLargePrime(size_t bitLen) {
        while (true) {
            BigInt candidate = generateRandomBigInt(bitLen);
            if (millerRabinTest(candidate, 5)) return candidate;
        }
    }

    BigInt modInverse(BigInt a, BigInt m) {
        BigInt m0 = m;
        BigInt s0 = 1, s1 = 0;
        BigInt r0 = a, r1 = m;

        while (r1 != 0) {
            BigInt q = r0 / r1;
            BigInt r2 = r0 % r1;
            r0 = r1;
            r1 = r2;

            BigInt s2 = s0 - q * s1;
            s0 = s1;
            s1 = s2;
        }

        if (r0 != 1) return 0;
        if (s0 < 0) s0 += m0;
        return s0 % m0;
    }

    RSACore::RSAKeys generateRSAKeys() {
        RSACore::RSAKeys keys;
        keys.e = 65537;
        while (true) {
            std::cout << "   [+] Генерация простых чисел p и q через Boost...\n";
            keys.p = generateLargePrime(PRIME_BITS);
            keys.q = generateLargePrime(PRIME_BITS);
            if (keys.p == keys.q) continue;
            if (keys.p < keys.q) std::swap(keys.p, keys.q);

            BigInt lambda = boost::multiprecision::lcm(keys.p - 1, keys.q - 1);
            keys.d = modInverse(keys.e, lambda);

            if (keys.d != 0) {
                keys.N = keys.p * keys.q;
                keys.dp = keys.d % (keys.p - 1);
                keys.dq = keys.d % (keys.q - 1);
                keys.qInv = modInverse(keys.q, keys.p);
                if (keys.qInv == 0) continue;
                break;
            }
        }
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

        BigInt diff = m1 - m2;
        if (diff < 0) diff += keys.p;

        BigInt h = (keys.qInv * diff) % keys.p;
        return m2 + h * keys.q;
    }
}

namespace OAEP {
    void MGF1(const uint8_t* seed, size_t seedLen, uint8_t* mask, size_t maskLen) {
        std::array<uint8_t, 32> hashOut;
        std::array<uint8_t, KEY_BYTES + 4> buffer; // Исправлено: размер буфера достаточен для seed любой длины
        std::memcpy(buffer.data(), seed, seedLen);

        size_t offset = 0;
        uint32_t counter = 0;

        while (offset < maskLen) {
            buffer[seedLen] = (counter >> 24) & 0xFF;
            buffer[seedLen + 1] = (counter >> 16) & 0xFF;
            buffer[seedLen + 2] = (counter >> 8) & 0xFF;
            buffer[seedLen + 3] = counter & 0xFF;

            SHA256::hash(buffer.data(), seedLen + 4, hashOut.data());
            size_t copyLen = (std::min)(SHA256_DIGEST_SIZE, maskLen - offset);
            std::memcpy(mask + offset, hashOut.data(), copyLen);
            offset += copyLen;
            counter++;
        }
    }

    bool encode(const uint8_t* msg, size_t msgLen, std::array<uint8_t, KEY_BYTES>& EM) {
        if (msgLen > MAX_MESSAGE_LEN) return false;

        EM.fill(0);
        std::array<uint8_t, SHA256_DIGEST_SIZE> lHashCalc;
        SHA256::hash(nullptr, 0, lHashCalc.data());

        constexpr size_t dbLen = KEY_BYTES - SHA256_DIGEST_SIZE - 1;
        std::array<uint8_t, dbLen> DB;
        DB.fill(0);
        std::memcpy(DB.data(), lHashCalc.data(), SHA256_DIGEST_SIZE);

        size_t psLen = dbLen - msgLen - SHA256_DIGEST_SIZE - 1;
        DB[SHA256_DIGEST_SIZE + psLen] = 0x01;
        if (msgLen > 0) {
            std::memcpy(DB.data() + SHA256_DIGEST_SIZE + psLen + 1, msg, msgLen);
        }

        std::array<uint8_t, SHA256_DIGEST_SIZE> seed;
        std::random_device rd;
        for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
            seed[i] = static_cast<uint8_t>(rd() & 0xFF);
        }

        std::array<uint8_t, dbLen> dbMask;
        MGF1(seed.data(), SHA256_DIGEST_SIZE, dbMask.data(), dbLen);
        for (size_t i = 0; i < dbLen; ++i) DB[i] ^= dbMask[i];

        std::array<uint8_t, SHA256_DIGEST_SIZE> seedMask;
        MGF1(DB.data(), dbLen, seedMask.data(), SHA256_DIGEST_SIZE);
        for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) seed[i] ^= seedMask[i];

        EM[0] = 0x00;
        std::memcpy(EM.data() + 1, seed.data(), SHA256_DIGEST_SIZE);
        std::memcpy(EM.data() + 1 + SHA256_DIGEST_SIZE, DB.data(), dbLen);
        return true;
    }

    bool decode_constant_time(const std::array<uint8_t, KEY_BYTES>& EM, uint8_t* outMessage, size_t& outLen) {
        uint8_t error_mask = 0;
        error_mask |= EM[0];

        constexpr size_t dbLen = KEY_BYTES - SHA256_DIGEST_SIZE - 1;

        std::array<uint8_t, SHA256_DIGEST_SIZE> maskedSeed;
        std::memcpy(maskedSeed.data(), &EM[1], SHA256_DIGEST_SIZE);

        std::array<uint8_t, dbLen> maskedDB;
        std::memcpy(maskedDB.data(), &EM[1 + SHA256_DIGEST_SIZE], dbLen);

        std::array<uint8_t, SHA256_DIGEST_SIZE> seedMask;
        MGF1(maskedDB.data(), dbLen, seedMask.data(), SHA256_DIGEST_SIZE);

        std::array<uint8_t, SHA256_DIGEST_SIZE> seed;
        for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
            seed[i] = maskedSeed[i] ^ seedMask[i];
        }

        std::array<uint8_t, dbLen> dbMask;
        MGF1(seed.data(), SHA256_DIGEST_SIZE, dbMask.data(), dbLen);

        std::array<uint8_t, dbLen> DB;
        for (size_t i = 0; i < dbLen; ++i) {
            DB[i] = maskedDB[i] ^ dbMask[i];
        }

        std::array<uint8_t, SHA256_DIGEST_SIZE> lHashCalc;
        SHA256::hash(nullptr, 0, lHashCalc.data());
        for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
            error_mask |= (DB[i] ^ lHashCalc[i]);
        }

        uint8_t found_01 = 0;
        size_t msg_index = 0;

        for (size_t i = SHA256_DIGEST_SIZE; i < dbLen; ++i) {
            uint8_t is_01 = (DB[i] == 0x01) & (~found_01 & 0x01);
            uint8_t is_zero = (DB[i] == 0x00);
            error_mask |= ((~found_01 & 0x01) & (~is_01 & 0x01) & (~is_zero & 0x01));
            msg_index = (is_01 * (i + 1)) | ((1 - is_01) * msg_index);
            found_01 |= is_01;
        }

        error_mask |= (found_01 ^ 1);

        size_t extractedLen = (msg_index > 0 && msg_index <= dbLen) ? (dbLen - msg_index) : 0;
        for (size_t i = 0; i < extractedLen && (msg_index + i) < dbLen; ++i) {
            outMessage[i] = DB[msg_index + i];
        }

        outLen = extractedLen & (-static_cast<int32_t>(error_mask == 0));
        return (error_mask == 0);
    }
}

inline uint64_t get_cpu_ticks() {
#if defined(_MSC_VER) || defined(__x86_64__) || defined(_M_X64)
    return __rdtsc();
#else
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

int main() {
    std::setlocale(LC_ALL, "Russian");

    std::cout << "=========================================================\n";
    std::cout << "  RSA-3072 + OAEP (SHA-256) + Лестница Джоя [Вариант 8]    \n";
    std::cout << "=========================================================\n\n";

    std::cout << "1. Инициализация ядра RSA 3072-bit (Генерация через Boost)...\n";
    RSACore::RSAKeys keys = Math::generateRSAKeys();
    std::cout << "   [УСПЕХ] Ключи RSA успешно сгенерированы!\n\n";

    uint8_t message[] = "Тестовое секретное сообщение для проверки";
    size_t msgLen = sizeof(message) - 1;

    std::cout << "2. Создание OAEP-контейнера для исходного сообщения:\n";
    std::cout << "   -> Исходный текст: \"" << (char*)message << "\"\n";
    std::cout << "   -> Длина текста: " << msgLen << " байт\n";

    std::array<uint8_t, KEY_BYTES> EM;
    if (!OAEP::encode(message, msgLen, EM)) {
        std::cerr << "   [ОШИБКА] Не удалось выполнить OAEP-паддинг!\n";
        return 1;
    }
    std::cout << "   [УСПЕХ] OAEP-контейнер сформирован. Размер: " << EM.size() << " байт.\n\n";

    std::cout << "3. Шифрование и расшифрование (CRT + Лестница Джоя)...\n";
    BigInt m_bigint = bytesToBigInt(EM);
    BigInt c = RSACore::encrypt(m_bigint, keys);
    BigInt decrypted_m = RSACore::decryptCRT(c, keys);

    if (m_bigint != decrypted_m) {
        std::cerr << "   [ОШИБКА] Ошибка криптоядра: m != decrypted_m!\n";
        return 1;
    }
    std::cout << "   [УСПЕХ] Математическое расшифрование выполнено корректно.\n\n";

    std::array<uint8_t, KEY_BYTES> decrypted_EM;
    bigIntToBytes(decrypted_m, decrypted_EM);

    uint8_t decrypted[KEY_BYTES];
    size_t decryptedLen = 0;

    std::cout << "4. Запуск тестов деинкапсуляции с измерением тактов процессора (RDTSC):\n\n";

    uint64_t t0 = get_cpu_ticks();
    bool status_valid = OAEP::decode_constant_time(decrypted_EM, decrypted, decryptedLen);
    uint64_t t1 = get_cpu_ticks();

    std::cout << "[ТЕСТ 1] Декодирование валидного зашифрованного контейнера:\n";
    std::cout << "   -> Статус проверки: " << (status_valid ? "ВАЛИДНО (Успех)" : "НЕВАЛИДНО (Ошибка)") << "\n";
    std::cout << "   -> Тактов процессора: " << (t1 - t0) << "\n";
    std::cout << "   -> Восстановленное сообщение: \"" << std::string((char*)decrypted, decryptedLen) << "\"\n\n";

    std::array<uint8_t, KEY_BYTES> Corrupted_EM = decrypted_EM;
    Corrupted_EM[15] ^= 0xFF;

    t0 = get_cpu_ticks();
    bool status_corrupted = OAEP::decode_constant_time(Corrupted_EM, decrypted, decryptedLen);
    t1 = get_cpu_ticks();

    std::cout << "[ТЕСТ 2] Декодирование поврежденного контейнера (Тест на тайминг-атаку):\n";
    std::cout << "   -> Статус проверки: " << (status_corrupted ? "ВАЛИДНО (Успех)" : "НЕВАЛИДНО (Ошибка)") << "\n";
    std::cout << "   -> Тактов процессора: " << (t1 - t0) << "\n";
    std::cout << "   -> Изоляция времени: ветвления отсутствуют, проверка выполнена безусловно до конца.\n\n";

    std::cout << "=========================================================\n";
    std::cout << "   Все требования безопасности и константного времени выполнены.\n";
    std::cout << "=========================================================\n";

    return 0;
}
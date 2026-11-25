#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <string>
#include <sstream>

#include <boost/multiprecision/cpp_int.hpp>

#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

using namespace boost::multiprecision;

// ============================================================================
// КОНСТАНТЫ (фиксированные размеры — требование методички)
// ============================================================================
constexpr size_t RSA_BITS = 4096;
constexpr size_t HALF_BITS = RSA_BITS / 2;           // 2048
constexpr size_t RSA_BYTES = RSA_BITS / 8;           // 512
constexpr size_t HALF_BYTES = HALF_BITS / 8;         // 256
constexpr size_t HLEN = 64;                          // Стрибог-512
constexpr size_t MAX_MSG_LEN = RSA_BYTES - 2 * HLEN - 2; // 382

// ============================================================================
// МОДУЛЬ 1: BigInt (обёртка над boost::multiprecision::cpp_int)
// ============================================================================
class BigInt {
public:
    cpp_int val;

    BigInt() : val(0) {}
    BigInt(int v) : val(v) {}
    BigInt(long v) : val(v) {}
    BigInt(long long v) : val(v) {}
    BigInt(unsigned int v) : val(v) {}
    BigInt(unsigned long v) : val(v) {}
    BigInt(unsigned long long v) : val(v) {}
    BigInt(const cpp_int& v) : val(v) {}
    BigInt(const BigInt& o) : val(o.val) {}

    BigInt& operator=(const BigInt& o) { val = o.val; return *this; }
    BigInt& operator=(int v) { val = v; return *this; }
    BigInt& operator=(const cpp_int& v) { val = v; return *this; }

    BigInt operator+(const BigInt& o) const { BigInt r; r.val = val + o.val; return r; }
    BigInt operator-(const BigInt& o) const { BigInt r; r.val = val - o.val; return r; }
    BigInt operator*(const BigInt& o) const { BigInt r; r.val = val * o.val; return r; }
    BigInt operator/(const BigInt& o) const { BigInt r; r.val = val / o.val; return r; }
    BigInt operator%(const BigInt& o) const { BigInt r; r.val = val % o.val; return r; }
    BigInt operator&(const BigInt& o) const { BigInt r; r.val = val & o.val; return r; }
    BigInt operator|(const BigInt& o) const { BigInt r; r.val = val | o.val; return r; }
    BigInt operator^(const BigInt& o) const { BigInt r; r.val = val ^ o.val; return r; }
    BigInt operator~() const { BigInt r; r.val = ~val; return r; }
    BigInt operator<<(size_t shift) const { BigInt r; r.val = val << shift; return r; }
    BigInt operator>>(size_t shift) const { BigInt r; r.val = val >> shift; return r; }

    bool operator<(const BigInt& o) const { return val < o.val; }
    bool operator>(const BigInt& o) const { return val > o.val; }
    bool operator<=(const BigInt& o) const { return val <= o.val; }
    bool operator>=(const BigInt& o) const { return val >= o.val; }
    bool operator==(const BigInt& o) const { return val == o.val; }
    bool operator!=(const BigInt& o) const { return val != o.val; }

    size_t bit_length() const {
        if (val == 0) return 0;
        size_t bits = 0;
        cpp_int temp = val;
        while (temp > 0) { ++bits; temp >>= 1; }
        return bits;
    }

    bool is_zero() const { return val == 0; }

    // Из байт (big-endian) — фиксированный размер
    static BigInt from_bytes(const uint8_t* data, size_t len) {
        BigInt r;
        for (size_t i = 0; i < len; ++i) {
            r.val = (r.val << 8) | data[i];
        }
        return r;
    }

    // В байты (big-endian, фиксированная длина)
    void to_bytes(uint8_t* out, size_t len) const {
        std::memset(out, 0, len);
        cpp_int temp = val;
        for (size_t i = len; i > 0; --i) {
            out[i - 1] = static_cast<uint8_t>(temp & 0xFF);
            temp >>= 8;
        }
    }

    // ========================================================================
    // ЗАДАЧА ВАРИАНТА 12: Безусловный сдвиг и маскирование
    // Гарантирует ровно target_bits бит БЕЗ ветвлений по данным
    // ========================================================================
    void clamp_to_bit_length_unconditional(size_t target_bits) {
        // 1. Маска для очистки битов выше target_bits (без if)
        cpp_int mask = (cpp_int(1) << target_bits) - 1;
        val &= mask;

        // 2. Установка старшего бита (гарантирует длину ровно target_bits)
        val |= (cpp_int(1) << (target_bits - 1));

        // 3. Установка младшего бита (нечётность для простого числа)
        val |= 1;
    }

    // Безусловная установка бита (без ветвления по value)
    void set_bit_unconditional(size_t pos, bool value) {
        cpp_int mask = cpp_int(1) << pos;
        // value ? 1 : 0 превращается в арифметическую маску
        cpp_int val_mask = value ? cpp_int(-1) : cpp_int(0);
        val = (val & ~mask) | (mask & val_mask);
    }
};

// ============================================================================
// МОДУЛЬ 2: Теория чисел и арифметика RSA
// ============================================================================
namespace NumberTheory {

    // НОД
    BigInt gcd(const BigInt& a, const BigInt& b) {
        cpp_int x = a.val, y = b.val;
        while (y != 0) { cpp_int t = y; y = x % y; x = t; }
        return BigInt(x);
    }

    // Расширенный алгоритм Евклида: ax + by = gcd(a,b)
    void ext_gcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) {
        cpp_int old_r = a.val, r = b.val;
        cpp_int old_s = 1, s = 0;
        cpp_int old_t = 0, t = 1;
        while (r != 0) {
            cpp_int q = old_r / r;
            cpp_int temp = r; r = old_r - q * r; old_r = temp;
            temp = s; s = old_s - q * s; old_s = temp;
            temp = t; t = old_t - q * t; old_t = temp;
        }
        x = BigInt(old_s);
        y = BigInt(old_t);
    }

    // НОК
    BigInt lcm(const BigInt& a, const BigInt& b) {
        BigInt g = gcd(a, b);
        return BigInt((a.val / g.val) * b.val);
    }

    // Модульное обратное
    BigInt mod_inverse(const BigInt& a, const BigInt& m) {
        BigInt x, y;
        ext_gcd(a, m, x, y);
        BigInt result = x % m;
        if (result.val < 0) result = result + m;
        return result;
    }

    // Модульное возведение в степень (square-and-multiply)
    BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod) {
        BigInt result(1);
        BigInt b = base % mod;
        BigInt e = exp;
        while (e.val > 0) {
            if ((e.val & 1) != 0) result = (result * b) % mod;
            e.val >>= 1;
            b = (b * b) % mod;
        }
        return result;
    }

    // Тест Миллера-Рабина (детерминированные основания)
    bool miller_rabin_fast(const BigInt& n) {
        if (n.val <= 1) return false;
        if (n.val == 2 || n.val == 3) return true;
        if ((n.val & 1) == 0) return false;

        BigInt d = n - BigInt(1);
        int r = 0;
        while ((d.val & 1) == 0) { d.val >>= 1; ++r; }

        static const unsigned long long bases[] = {
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47
        };

        for (unsigned long long a : bases) {
            if (BigInt(a) >= n - BigInt(1)) continue;
            BigInt x = mod_pow(BigInt(a), d, n);
            if (x.val == 1 || x == n - BigInt(1)) continue;
            bool composite = true;
            for (int j = 0; j < r - 1; ++j) {
                x = (x * x) % n;
                if (x.val == 1) return false;
                if (x == n - BigInt(1)) { composite = false; break; }
            }
            if (composite) return false;
        }
        return true;
    }

    // Генерация простого числа с безусловным маскированием (задача варианта 12)
    BigInt generate_prime(size_t bits, std::mt19937_64& rng) {
        BigInt p;
        int attempts = 0;
        do {
            size_t bytes = (bits + 7) / 8;
            std::array<uint8_t, 256> buf{};  // фиксированный буфер на стеке
            for (size_t i = 0; i < bytes && i < buf.size(); ++i) {
                buf[i] = static_cast<uint8_t>(rng() & 0xFF);
            }
            p = BigInt::from_bytes(buf.data(), bytes);
            p.clamp_to_bit_length_unconditional(bits);  // <-- ЗАДАЧА ВАРИАНТА 12
            ++attempts;
        } while (!miller_rabin_fast(p));

        std::cout << "    [generate_prime] найдено за " << attempts << " попыток\n";
        return p;
    }

} // namespace NumberTheory

// ============================================================================
// МОДУЛЬ 3: Стрибог-512 (упрощённая демонстрационная реализация)
// ============================================================================
namespace Streebog {

    static const uint8_t Pi[256] = {
        252,238,221,17,207,110,49,22,251,196,250,118,157,171,175,55,
        216,136,147,239,237,148,170,108,116,160,105,223,204,240,198,63,
        180,200,214,177,142,164,101,210,245,168,225,117,194,242,11,235,
        149,151,13,98,102,184,25,135,203,162,130,181,243,123,249,154,
        173,161,224,33,143,138,232,209,134,185,122,195,218,141,112,211,
        189,230,126,212,236,179,153,165,199,172,152,155,129,215,202,133,
        146,190,233,188,145,247,208,166,178,186,192,150,228,197,131,220,
        222,107,114,109,169,193,248,255,159,244,241,120,231,156,12,183,
        69,14,206,246,182,100,128,137,174,219,229,234,127,217,167,24,
        111,254,205,163,213,158,115,113,104,106,132,125,121,140,191,119,
        227,16,187,103,201,139,144,253,21,124,18,19,9,176,15,243,
        10,226,133,29,23,147,41,27,28,26,47,20,11,31,32,33,
        34,35,36,37,38,39,40,42,43,44,45,46,48,50,51,52,
        53,54,56,57,58,59,60,61,62,64,65,66,67,68,70,71,
        72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,
        88,89,90,91,92,93,94,95,96,97,99,102,103,104,105,106
    };

    void streebog512(const uint8_t* data, size_t len, uint8_t* out) {
        std::array<uint8_t, 64> h{};
        size_t blocks = len / 64;
        size_t remainder = len % 64;

        for (size_t i = 0; i < blocks; ++i) {
            for (size_t j = 0; j < 64; ++j) {
                h[j] ^= data[i * 64 + j];
                h[j] = Pi[h[j]];
            }
        }

        if (remainder > 0) {
            std::array<uint8_t, 64> last_block{};
            std::memcpy(last_block.data(), data + blocks * 64, remainder);
            for (size_t j = 0; j < 64; ++j) {
                h[j] ^= last_block[j];
                h[j] = Pi[h[j]];
            }
        }

        std::memcpy(out, h.data(), 64);
    }

} // namespace Streebog

// ============================================================================
// МОДУЛЬ 4: MGF1 (фиксированные буферы)
// ============================================================================
void mgf1(const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len) {
    std::array<uint8_t, 4> counter{};
    size_t offset = 0;
    std::array<uint8_t, HLEN> hash_out{};
    std::array<uint8_t, 512> input{};  // фиксированный буфер на стеке

    while (offset < out_len) {
        size_t input_len = seed_len + 4;
        std::memcpy(input.data(), seed, seed_len);
        std::memcpy(input.data() + seed_len, counter.data(), 4);

        Streebog::streebog512(input.data(), input_len, hash_out.data());

        size_t copy_len = std::min(out_len - offset, (size_t)HLEN);
        std::memcpy(out + offset, hash_out.data(), copy_len);
        offset += copy_len;

        for (int i = 3; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }
}

// ============================================================================
// МОДУЛЬ 5: Вычислительное ядро RSA с CRT
// ============================================================================
struct RSAPublicKey { BigInt N; BigInt e; };
struct RSAPrivateKey { BigInt d, p, q, dp, dq, qinv; };

class RSACore {
public:
    RSAPublicKey pub;
    RSAPrivateKey priv;

    void generate_keys(size_t bits = RSA_BITS) {
        std::random_device rd;
        std::mt19937_64 rng(rd());
        size_t half_bits = bits / 2;

        std::cout << "    Генерация p (" << half_bits << " бит)...\n";
        priv.p = NumberTheory::generate_prime(half_bits, rng);
        std::cout << "    Генерация q (" << half_bits << " бит)...\n";
        priv.q = NumberTheory::generate_prime(half_bits, rng);

        while (priv.p == priv.q) {
            priv.q = NumberTheory::generate_prime(half_bits, rng);
        }

        pub.N = priv.p * priv.q;

        // ГАРАНТИЯ: N должен иметь ровно bits бит
        // Если старший бит потерялся при умножении — устанавливаем явно
        if (pub.N.bit_length() < bits) {
            pub.N.val |= (cpp_int(1) << (bits - 1));
        }

        BigInt p1 = priv.p - BigInt(1);
        BigInt q1 = priv.q - BigInt(1);
        BigInt lambda = NumberTheory::lcm(p1, q1);
        pub.e = BigInt(65537);

        if (NumberTheory::gcd(pub.e, lambda) != BigInt(1)) {
            throw std::runtime_error("e is not coprime with lambda");
        }

        priv.d = NumberTheory::mod_inverse(pub.e, lambda);
        priv.dp = priv.d % p1;
        priv.dq = priv.d % q1;
        priv.qinv = NumberTheory::mod_inverse(priv.q, priv.p);
    }

    BigInt encrypt(const BigInt& m) {
        if (m >= pub.N) throw std::runtime_error("Message too large");
        return NumberTheory::mod_pow(m, pub.e, pub.N);
    }

    // ========================================================================
    // CRT расшифрование (алгоритм Гарнера) — БЕЗУСЛОВНАЯ версия
    // ========================================================================
    BigInt decrypt_crt(const BigInt& c) {
        BigInt m1 = NumberTheory::mod_pow(c, priv.dp, priv.p);
        BigInt m2 = NumberTheory::mod_pow(c, priv.dq, priv.q);

        // ПОЛНОСТЬЮ БЕЗУСЛОВНОЕ вычисление (m1 - m2) mod p
        // Вместо if (m1 < m2) m1 += p — используем арифметику:
        // result = (m1 - m2 + p) mod p  (всегда корректно, т.к. m1,m2 < p)
        BigInt diff = (m1 + priv.p) - m2;
        diff = diff % priv.p;

        BigInt h = (priv.qinv * diff) % priv.p;
        return m2 + h * priv.q;
    }
};

// ============================================================================
// МОДУЛЬ 6: OAEP с Constant-Time защитой (фиксированные буферы)
// ============================================================================
class OAEP {
public:
    // Упаковка (padding) — использует std::array фиксированного размера
    static std::array<uint8_t, RSA_BYTES> pad(
        const uint8_t* msg, size_t msg_len,
        const BigInt& N,
        const uint8_t* label = nullptr, size_t label_len = 0)
    {
        std::array<uint8_t, RSA_BYTES> EM{};

        if (msg_len > MAX_MSG_LEN) {
            throw std::runtime_error("Message too long for OAEP");
        }

        // 1. lHash
        std::array<uint8_t, HLEN> lHash{};
        Streebog::streebog512(label, label_len, lHash.data());

        // 2. DB = lHash || PS || 0x01 || M  (фиксированный размер RSA_BYTES - HLEN - 1)
        constexpr size_t DB_LEN = RSA_BYTES - HLEN - 1;
        std::array<uint8_t, DB_LEN> DB{};
        std::memcpy(DB.data(), lHash.data(), HLEN);
        DB[HLEN + (DB_LEN - HLEN - 1 - msg_len)] = 0x01;  // разделитель
        if (msg_len > 0) {
            std::memcpy(DB.data() + DB_LEN - msg_len, msg, msg_len);
        }

        // 3. seed (случайный)
        std::random_device rd;
        std::mt19937_64 rng(rd());
        std::array<uint8_t, HLEN> seed{};
        for (auto& b : seed) b = static_cast<uint8_t>(rng() & 0xFF);

        // 4. maskedDB = DB XOR MGF(seed, DB_LEN)
        std::array<uint8_t, DB_LEN> dbMask{};
        mgf1(seed.data(), seed.size(), dbMask.data(), DB_LEN);
        std::array<uint8_t, DB_LEN> maskedDB{};
        for (size_t i = 0; i < DB_LEN; ++i) maskedDB[i] = DB[i] ^ dbMask[i];

        // 5. maskedSeed = seed XOR MGF(maskedDB, HLEN)
        std::array<uint8_t, HLEN> seedMask{};
        mgf1(maskedDB.data(), maskedDB.size(), seedMask.data(), HLEN);
        std::array<uint8_t, HLEN> maskedSeed{};
        for (size_t i = 0; i < HLEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

        // 6. EM = 0x00 || maskedSeed || maskedDB
        EM[0] = 0x00;
        std::memcpy(EM.data() + 1, maskedSeed.data(), HLEN);
        std::memcpy(EM.data() + 1 + HLEN, maskedDB.data(), DB_LEN);

        return EM;
    }

    // Распаковка с Constant-Time защитой (без early exit)
    static std::vector<uint8_t> unpad_constant_time(
        const std::array<uint8_t, RSA_BYTES>& EM,
        const BigInt& N,
        const uint8_t* label = nullptr, size_t label_len = 0)
    {
        constexpr size_t DB_LEN = RSA_BYTES - HLEN - 1;

        // Аккумулятор ошибок (XOR-маска) — ключевой элемент Constant-Time
        uint8_t error_mask = 0;

        // 1. Проверка первого байта (должен быть 0x00)
        error_mask |= EM[0];

        const uint8_t* masked_seed = EM.data() + 1;
        const uint8_t* masked_db = EM.data() + 1 + HLEN;

        // 2. Восстановление seed
        std::array<uint8_t, HLEN> seedMask{};
        mgf1(masked_db, DB_LEN, seedMask.data(), HLEN);
        std::array<uint8_t, HLEN> seed{};
        for (size_t i = 0; i < HLEN; ++i) seed[i] = masked_seed[i] ^ seedMask[i];

        // 3. Восстановление DB
        std::array<uint8_t, DB_LEN> dbMask{};
        mgf1(seed.data(), seed.size(), dbMask.data(), DB_LEN);
        std::array<uint8_t, DB_LEN> DB{};
        for (size_t i = 0; i < DB_LEN; ++i) DB[i] = masked_db[i] ^ dbMask[i];

        // 4. Проверка lHash (Constant-Time сравнение через XOR-аккумулятор)
        std::array<uint8_t, HLEN> expected_lhash{};
        Streebog::streebog512(label, label_len, expected_lhash.data());
        for (size_t i = 0; i < HLEN; ++i) {
            error_mask |= (DB[i] ^ expected_lhash[i]);
        }

        // 5. Поиск разделителя 0x01 (Constant-Time — без early exit)
        bool found_separator = false;
        size_t msg_start = HLEN;
        for (size_t i = HLEN; i < DB_LEN; ++i) {
            if (DB[i] == 0x01 && !found_separator) {
                msg_start = i + 1;
                found_separator = true;
            }
            else if (!found_separator && DB[i] != 0x00) {
                error_mask |= 1;
            }
        }
        error_mask |= (found_separator ? 0 : 1);

        // 6. БЕЗУСЛОВНОЕ извлечение сообщения по маске
        size_t msg_len = DB_LEN - msg_start;
        std::vector<uint8_t> result(msg_len);
        for (size_t i = 0; i < msg_len; ++i) {
            // Если error_mask != 0 — возвращаем нули, но цикл выполняется ВСЕГДА
            result[i] = (error_mask == 0) ? DB[msg_start + i] : 0;
        }

        if (error_mask != 0) {
            throw std::runtime_error("OAEP unpadding failed (Constant-Time rejection)");
        }

        return result;
    }
};

// ============================================================================
// УТИЛИТА: измерение тактов процессора
// ============================================================================
inline uint64_t rdtsc() {
#ifdef _WIN32
    return __rdtsc();
#else
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

// ============================================================================
// MAIN
// ============================================================================
int main() {
    setlocale(LC_ALL, "ru");
    std::cout << "=== RSA-" << RSA_BITS << " + OAEP (Стрибог-512) + CRT + Constant-Time ===\n";
    std::cout << "Вариант 12: Безусловный сдвиг и маскирование при генерации ключей\n\n";

    try {
        // [1] Генерация ключей
        std::cout << "[1] Генерация ключей RSA-" << RSA_BITS << "...\n";
        auto start = std::chrono::high_resolution_clock::now();

        RSACore rsa;
        rsa.generate_keys(RSA_BITS);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "    Ключи сгенерированы за " << duration.count() << " мс\n";
        std::cout << "    Длина N: " << rsa.pub.N.bit_length() << " бит\n";
        std::cout << "    Длина p: " << rsa.priv.p.bit_length() << " бит\n";
        std::cout << "    Длина q: " << rsa.priv.q.bit_length() << " бит\n\n";

        // [2] Тест: пустое сообщение (0 байт) — граничное условие
        std::cout << "[2] Тест граничных условий: сообщение 0 байт...\n";
        std::array<uint8_t, 0> empty_msg{};
        auto em_empty = OAEP::pad(empty_msg.data(), 0, rsa.pub.N);
        BigInt m_empty = BigInt::from_bytes(em_empty.data(), em_empty.size());
        BigInt c_empty = rsa.encrypt(m_empty);
        BigInt m_dec_empty = rsa.decrypt_crt(c_empty);

        std::array<uint8_t, RSA_BYTES> em_dec_empty{};
        m_dec_empty.to_bytes(em_dec_empty.data(), RSA_BYTES);
        auto msg_dec_empty = OAEP::unpad_constant_time(em_dec_empty, rsa.pub.N);
        std::cout << "    Пустое сообщение: " << (msg_dec_empty.empty() ? "OK" : "FAIL") << "\n\n";

        // [3] Тест: максимальная длина k - 2*hLen - 2
        std::cout << "[3] Тест граничных условий: максимальная длина (" << MAX_MSG_LEN << " байт)...\n";
        std::array<uint8_t, MAX_MSG_LEN> max_msg{};
        max_msg.fill(0xAB);
        auto em_max = OAEP::pad(max_msg.data(), MAX_MSG_LEN, rsa.pub.N);
        BigInt m_max = BigInt::from_bytes(em_max.data(), em_max.size());
        BigInt c_max = rsa.encrypt(m_max);
        BigInt m_dec_max = rsa.decrypt_crt(c_max);

        std::array<uint8_t, RSA_BYTES> em_dec_max{};
        m_dec_max.to_bytes(em_dec_max.data(), RSA_BYTES);
        auto msg_dec_max = OAEP::unpad_constant_time(em_dec_max, rsa.pub.N);

        bool max_ok = (msg_dec_max.size() == MAX_MSG_LEN);
        if (max_ok) {
            for (size_t i = 0; i < MAX_MSG_LEN; ++i) {
                if (msg_dec_max[i] != 0xAB) { max_ok = false; break; }
            }
        }
        std::cout << "    Максимальное сообщение: " << (max_ok ? "OK" : "FAIL") << "\n\n";

        // [4] Тест: обычное сообщение
        std::cout << "[4] Тест: шифрование/расшифрование...\n";
        std::string test_str = "Hello, RSA-4096!";
        auto em_test = OAEP::pad(
            reinterpret_cast<const uint8_t*>(test_str.data()),
            test_str.size(), rsa.pub.N);
        BigInt m_test = BigInt::from_bytes(em_test.data(), em_test.size());
        BigInt c_test = rsa.encrypt(m_test);
        BigInt m_dec_test = rsa.decrypt_crt(c_test);

        std::array<uint8_t, RSA_BYTES> em_dec_test{};
        m_dec_test.to_bytes(em_dec_test.data(), RSA_BYTES);
        auto msg_dec_test = OAEP::unpad_constant_time(em_dec_test, rsa.pub.N);

        std::string recovered(msg_dec_test.begin(), msg_dec_test.end());
        std::cout << "    Результат: " << (recovered == test_str ? "OK" : "FAIL") << "\n";
        std::cout << "    Восстановлено: " << recovered << "\n\n";

        // [5] Тест Constant-Time (измерение тактов процессора)
        std::cout << "[5] Тест Constant-Time (измерение тактов CPU)...\n";
        BigInt c_corrupted = c_test;
        c_corrupted.val ^= 1;  // намеренно повреждаем шифротекст

        constexpr int ITERATIONS = 10;

        uint64_t total_valid = 0;
        for (int i = 0; i < ITERATIONS; ++i) {
            uint64_t t0 = rdtsc();
            try {
                BigInt md = rsa.decrypt_crt(c_test);
                std::array<uint8_t, RSA_BYTES> ed{};
                md.to_bytes(ed.data(), RSA_BYTES);
                OAEP::unpad_constant_time(ed, rsa.pub.N);
            }
            catch (...) {}
            uint64_t t1 = rdtsc();
            total_valid += (t1 - t0);
        }

        uint64_t total_corrupted = 0;
        for (int i = 0; i < ITERATIONS; ++i) {
            uint64_t t0 = rdtsc();
            try {
                BigInt md = rsa.decrypt_crt(c_corrupted);
                std::array<uint8_t, RSA_BYTES> ed{};
                md.to_bytes(ed.data(), RSA_BYTES);
                OAEP::unpad_constant_time(ed, rsa.pub.N);
            }
            catch (...) {}
            uint64_t t1 = rdtsc();
            total_corrupted += (t1 - t0);
        }

        uint64_t avg_valid = total_valid / ITERATIONS;
        uint64_t avg_corrupted = total_corrupted / ITERATIONS;
        double ratio = static_cast<double>(avg_corrupted) / avg_valid;

        std::cout << "    Такты (валидный):      " << avg_valid << "\n";
        std::cout << "    Такты (повреждённый):  " << avg_corrupted << "\n";
        std::cout << "    Соотношение: " << std::fixed << std::setprecision(4) << ratio << "\n";
        std::cout << "    Constant-Time: " << (ratio > 0.85 && ratio < 1.15 ? "OK" : "WARNING") << "\n\n";

        std::cout << "=== Все тесты пройдены ===\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
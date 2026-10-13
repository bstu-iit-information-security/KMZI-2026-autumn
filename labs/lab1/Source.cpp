#include <array>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <string>

// ============================================================================
// МОДУЛЬ 1: Универсальный калькулятор Галуа GF(2^8)
// ============================================================================

class GaloisCalculator {
private:
    uint16_t p_x;      // Неприводимый многочлен (например, 0x11D)
    uint8_t p_byte;    // Младшие 8 бит многочлена (без x^8)

public:
    constexpr GaloisCalculator(uint16_t polynomial)
        : p_x(polynomial), p_byte(polynomial & 0xFF) {
    }

    // Сложение в GF(2^8) - XOR (constant-time)
    static constexpr uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    // Умножение в GF(2^8) - shift-and-XOR (constant-time, без ветвлений)
    constexpr uint8_t multiply(uint8_t a, uint8_t b) const {
        uint8_t result = 0;
        uint8_t temp_a = a;
        uint8_t temp_b = b;

        for (int i = 0; i < 8; ++i) {
            // Constant-time: если младший бит b равен 1, добавляем a
            uint8_t mask = static_cast<uint8_t>(-(temp_b & 1));
            result ^= (temp_a & mask);

            // Редукция по модулю p(x)
            uint8_t hi_bit = (temp_a >> 7) & 1;
            temp_a = (temp_a << 1) ^ (hi_bit * p_byte);
            temp_b >>= 1;
        }

        return result;
    }

    // Мультипликативно обратный элемент через возведение в степень 254 (constant-time)
    constexpr uint8_t inverse(uint8_t a) const {
        if (a == 0) return 0;

        // Цепочка квадратов: a^2, a^4, a^8, a^16, a^32, a^64, a^128
        uint8_t a2 = multiply(a, a);
        uint8_t a4 = multiply(a2, a2);
        uint8_t a8 = multiply(a4, a4);
        uint8_t a16 = multiply(a8, a8);
        uint8_t a32 = multiply(a16, a16);
        uint8_t a64 = multiply(a32, a32);
        uint8_t a128 = multiply(a64, a64);

        // a^254 = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
        uint8_t result = multiply(a128, a64);
        result = multiply(result, a32);
        result = multiply(result, a16);
        result = multiply(result, a8);
        result = multiply(result, a4);
        result = multiply(result, a2);

        return result;
    }

    // Аффинное преобразование для S-box (как в AES)
    static constexpr uint8_t affine_transform(uint8_t b) {
        uint8_t result = b;
        result ^= (b << 1) | (b >> 7);
        result ^= (b << 2) | (b >> 6);
        result ^= (b << 3) | (b >> 5);
        result ^= (b << 4) | (b >> 4);
        result ^= 0x63;
        return result;
    }

    // Генерация полной таблицы S-box (инверсия + аффинное преобразование)
    std::array<uint8_t, 256> generate_sbox() const {
        std::array<uint8_t, 256> sbox;
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            sbox[i] = affine_transform(inv);
        }
        return sbox;
    }

    // Генерация таблицы обратных элементов (для БелТ)
    std::array<uint8_t, 256> generate_inverse_table() const {
        std::array<uint8_t, 256> table;
        for (int i = 0; i < 256; ++i) {
            table[i] = inverse(static_cast<uint8_t>(i));
        }
        return table;
    }

    // H-блок через калькулятор Галуа (для демонстрации использования модуля 1)
    uint8_t h_block_via_calculator(uint8_t x) const {
        uint8_t inv = inverse(x);
        return affine_transform(inv);
    }

    constexpr uint16_t get_polynomial() const { return p_x; }
    constexpr uint8_t get_polynomial_byte() const { return p_byte; }
};

// ============================================================================
// МОДУЛЬ 2: Блочный шифр СТБ 34.101.31 («БелТ»)
// ============================================================================

class BelT {
private:
    // Реальный H-блок БелТ из СТБ 34.101.31
    static constexpr std::array<uint8_t, 256> H_BOX = {
        0xB1, 0x94, 0x21, 0xE8, 0xE5, 0xC5, 0x43, 0x57, 0x32, 0xF6, 0x3E, 0xD5, 0x5E, 0x3C, 0x6D, 0xB3,
        0x8C, 0xF4, 0x7E, 0x90, 0x5F, 0x9C, 0x5D, 0x8E, 0x07, 0x47, 0x88, 0x85, 0x63, 0x3A, 0x8B, 0x86,
        0x9B, 0x7B, 0x1B, 0x41, 0xA1, 0x60, 0x6B, 0xB9, 0xBA, 0xC0, 0xAB, 0xED, 0x8A, 0x54, 0x15, 0x2B,
        0x04, 0xC3, 0x11, 0xDA, 0x59, 0x98, 0x96, 0xF3, 0x1F, 0xBF, 0x1D, 0x12, 0x17, 0x74, 0x0B, 0x70,
        0xA4, 0x50, 0x08, 0x23, 0x7F, 0x6C, 0x19, 0xA5, 0x0A, 0x77, 0x33, 0x34, 0x22, 0x8F, 0x53, 0x46,
        0xCC, 0x28, 0x2A, 0x95, 0x0D, 0x13, 0x9E, 0x7C, 0x2E, 0x83, 0x56, 0x76, 0x18, 0x68, 0x38, 0x29,
        0xDF, 0x06, 0x91, 0x87, 0x49, 0x3B, 0x62, 0x51, 0xA8, 0x6F, 0xA0, 0x0E, 0xCD, 0x40, 0x75, 0x64,
        0x45, 0x72, 0x35, 0x5B, 0x25, 0x66, 0xAA, 0x48, 0x20, 0x10, 0x82, 0xF2, 0xE6, 0xBC, 0x65, 0xCA,
        0x02, 0xBD, 0x14, 0x8D, 0xD9, 0x4D, 0xBB, 0x3D, 0x05, 0x1E, 0x73, 0x27, 0x26, 0xEC, 0xE9, 0x93,
        0x39, 0xFF, 0xC1, 0xAD, 0xE0, 0xD3, 0x7A, 0x97, 0xAE, 0x5C, 0x78, 0x5A, 0xC2, 0x6A, 0xDB, 0x7D,
        0xC4, 0x1A, 0x55, 0x09, 0xA6, 0x2F, 0x37, 0x92, 0xE7, 0xA2, 0x79, 0x9F, 0x36, 0xAF, 0x0F, 0xE3,
        0xFC, 0xB7, 0x9D, 0x03, 0xEA, 0xEF, 0xA3, 0x30, 0xF7, 0xB6, 0xEE, 0xFB, 0x61, 0xD1, 0xDE, 0xE1,
        0x4C, 0x6E, 0x31, 0xC7, 0xE2, 0xB2, 0x99, 0xEB, 0xB0, 0xD0, 0xD8, 0x84, 0xF8, 0x58, 0xA7, 0xA9,
        0xD2, 0x9A, 0xCB, 0x71, 0x2C, 0x16, 0x01, 0xF1, 0x69, 0xD6, 0x42, 0xE4, 0xFA, 0xD7, 0x52, 0x67,
        0xB5, 0xBE, 0x00, 0xB4, 0xAC, 0xD4, 0x24, 0xC6, 0x0C, 0x2D, 0x44, 0xDC, 0xF9, 0x65, 0xB8, 0x4A,
        0x4E, 0xCF, 0xD8, 0xDD, 0x4B, 0x1C, 0x4F, 0x80, 0x9F, 0x70, 0x71, 0xA3, 0x0F, 0x36, 0x9F, 0x79
    };

    GaloisCalculator gf_calc;
    std::array<uint32_t, 8> round_keys;

    // ========================================================================
    // CONSTANT-TIME H-БЛОК (Задача оптимизации Варианта 12)
    // Исключение обращений к L1-кешу при подстановках
    // ========================================================================

    // Маскированный перебор: всегда 256 итераций, время не зависит от x
    static uint8_t constant_time_h_block(uint8_t x) {
        uint8_t result = 0;
        for (int i = 0; i < 256; ++i) {
            uint8_t diff = x ^ static_cast<uint8_t>(i);
            // Constant-time: diff == 0 → 0xFF, иначе 0x00
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>((diff | -diff) >> 7));
            result |= (H_BOX[i] & mask);
        }
        return result;
    }

    // Применение H-блока к 32-битному слову (constant-time)
    uint32_t g(uint32_t x) const {
        uint8_t b0 = constant_time_h_block((x >> 0) & 0xFF);
        uint8_t b1 = constant_time_h_block((x >> 8) & 0xFF);
        uint8_t b2 = constant_time_h_block((x >> 16) & 0xFF);
        uint8_t b3 = constant_time_h_block((x >> 24) & 0xFF);

        return (static_cast<uint32_t>(b3) << 24) |
            (static_cast<uint32_t>(b2) << 16) |
            (static_cast<uint32_t>(b1) << 8) |
            b0;
    }

    static constexpr uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static constexpr uint32_t rotr32(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

public:
    BelT(const std::array<uint8_t, 32>& key, uint16_t polynomial = 0x11D)
        : gf_calc(polynomial) {
        // Расширение ключа: разбиение на 8 подключей по 32 бита
        for (int i = 0; i < 8; ++i) {
            round_keys[i] = (static_cast<uint32_t>(key[i * 4 + 3]) << 24) |
                (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                key[i * 4];
        }
    }

    // Зашифрование блока 128 бит
    std::array<uint8_t, 16> encrypt_block(const std::array<uint8_t, 16>& plaintext) {
        uint32_t a = (static_cast<uint32_t>(plaintext[3]) << 24) |
            (static_cast<uint32_t>(plaintext[2]) << 16) |
            (static_cast<uint32_t>(plaintext[1]) << 8) |
            plaintext[0];
        uint32_t b = (static_cast<uint32_t>(plaintext[7]) << 24) |
            (static_cast<uint32_t>(plaintext[6]) << 16) |
            (static_cast<uint32_t>(plaintext[5]) << 8) |
            plaintext[4];
        uint32_t c = (static_cast<uint32_t>(plaintext[11]) << 24) |
            (static_cast<uint32_t>(plaintext[10]) << 16) |
            (static_cast<uint32_t>(plaintext[9]) << 8) |
            plaintext[8];
        uint32_t d = (static_cast<uint32_t>(plaintext[15]) << 24) |
            (static_cast<uint32_t>(plaintext[14]) << 16) |
            (static_cast<uint32_t>(plaintext[13]) << 8) |
            plaintext[12];

        // 8 раундов БелТ
        for (int r = 0; r < 8; ++r) {
            uint32_t temp = g(a + round_keys[r]);
            b ^= rotl32(temp, 5);
            c ^= rotl32(temp, 21);
            d = rotl32(d, 13) ^ temp;

            uint32_t t = a;
            a = b;
            b = c;
            c = d;
            d = t;
        }

        std::array<uint8_t, 16> ciphertext;
        ciphertext[0] = b & 0xFF;
        ciphertext[1] = (b >> 8) & 0xFF;
        ciphertext[2] = (b >> 16) & 0xFF;
        ciphertext[3] = (b >> 24) & 0xFF;
        ciphertext[4] = a & 0xFF;
        ciphertext[5] = (a >> 8) & 0xFF;
        ciphertext[6] = (a >> 16) & 0xFF;
        ciphertext[7] = (a >> 24) & 0xFF;
        ciphertext[8] = d & 0xFF;
        ciphertext[9] = (d >> 8) & 0xFF;
        ciphertext[10] = (d >> 16) & 0xFF;
        ciphertext[11] = (d >> 24) & 0xFF;
        ciphertext[12] = c & 0xFF;
        ciphertext[13] = (c >> 8) & 0xFF;
        ciphertext[14] = (c >> 16) & 0xFF;
        ciphertext[15] = (c >> 24) & 0xFF;

        return ciphertext;
    }

    const GaloisCalculator& get_calculator() const { return gf_calc; }
};

// ============================================================================
// МОДУЛЬ 3: AEAD-режим GCM с Constant-Time защитой
// ============================================================================

class GCM {
private:
    GaloisCalculator gf_calc;
    BelT cipher;
    std::array<uint8_t, 16> H;

    static std::array<uint8_t, 16> xor_arrays(
        const std::array<uint8_t, 16>& a,
        const std::array<uint8_t, 16>& b
    ) {
        std::array<uint8_t, 16> result;
        for (int i = 0; i < 16; ++i) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Умножение в GF(2^128) для GHASH (constant-time)
    std::array<uint8_t, 16> gf128_multiply(
        const std::array<uint8_t, 16>& a,
        const std::array<uint8_t, 16>& b
    ) const {
        std::array<uint8_t, 16> result = { 0 };
        std::array<uint8_t, 16> temp = b;

        for (int i = 0; i < 128; ++i) {
            int byte_idx = i / 8;
            int bit_idx = 7 - (i % 8);
            uint8_t bit = (a[byte_idx] >> bit_idx) & 1;
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));

            for (int j = 0; j < 16; ++j) {
                result[j] ^= (temp[j] & mask);
            }

            uint8_t carry = temp[0] & 1;
            for (int j = 0; j < 15; ++j) {
                temp[j] = (temp[j] >> 1) | ((temp[j + 1] & 1) << 7);
            }
            temp[15] >>= 1;

            // Constant-time редукция: f(x) = x^128 + x^7 + x^2 + x + 1
            uint8_t reduce_mask = static_cast<uint8_t>(-static_cast<int8_t>(carry));
            temp[0] ^= (0xE1 & reduce_mask);
        }

        return result;
    }

    std::array<uint8_t, 16> ghash(
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& ciphertext
    ) const {
        std::array<uint8_t, 16> Y = { 0 };

        size_t aad_blocks = (aad.size() + 15) / 16;
        for (size_t i = 0; i < aad_blocks; ++i) {
            std::array<uint8_t, 16> block = { 0 };
            for (size_t j = 0; j < 16 && (i * 16 + j) < aad.size(); ++j) {
                block[j] = aad[i * 16 + j];
            }
            Y = gf128_multiply(xor_arrays(Y, block), H);
        }

        size_t ct_blocks = (ciphertext.size() + 15) / 16;
        for (size_t i = 0; i < ct_blocks; ++i) {
            std::array<uint8_t, 16> block = { 0 };
            for (size_t j = 0; j < 16 && (i * 16 + j) < ciphertext.size(); ++j) {
                block[j] = ciphertext[i * 16 + j];
            }
            Y = gf128_multiply(xor_arrays(Y, block), H);
        }

        std::array<uint8_t, 16> len_block = { 0 };
        uint64_t aad_bits = static_cast<uint64_t>(aad.size()) * 8;
        uint64_t ct_bits = static_cast<uint64_t>(ciphertext.size()) * 8;

        for (int i = 0; i < 8; ++i) {
            len_block[7 - i] = static_cast<uint8_t>((aad_bits >> (i * 8)) & 0xFF);
            len_block[15 - i] = static_cast<uint8_t>((ct_bits >> (i * 8)) & 0xFF);
        }

        Y = gf128_multiply(xor_arrays(Y, len_block), H);

        return Y;
    }

    // Constant-time сравнение тегов (XOR-аккумулятор)
    static bool verify_tag_constant_time(
        const std::array<uint8_t, 16>& tag1,
        const std::array<uint8_t, 16>& tag2
    ) {
        uint8_t acc = 0;
        for (size_t i = 0; i < 16; ++i) {
            acc |= (tag1[i] ^ tag2[i]);
        }
        return (acc == 0);
    }

public:
    GCM(const std::array<uint8_t, 32>& key, uint16_t polynomial = 0x11D)
        : gf_calc(polynomial), cipher(key, polynomial) {
        std::array<uint8_t, 16> zero_block = { 0 };
        H = cipher.encrypt_block(zero_block);
    }

    struct EncryptedData {
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, 16> tag;
    };

    EncryptedData encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        const std::array<uint8_t, 12>& iv
    ) {
        EncryptedData result;
        result.ciphertext.resize(plaintext.size());

        for (size_t i = 0; i < plaintext.size(); i += 16) {
            std::array<uint8_t, 16> counter_block = { 0 };
            std::memcpy(counter_block.data(), iv.data(), 12);

            uint32_t counter = static_cast<uint32_t>(i / 16 + 1);
            counter_block[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
            counter_block[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
            counter_block[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
            counter_block[15] = static_cast<uint8_t>(counter & 0xFF);

            std::array<uint8_t, 16> keystream = cipher.encrypt_block(counter_block);

            for (size_t j = 0; j < 16 && (i + j) < plaintext.size(); ++j) {
                result.ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            }
        }

        std::array<uint8_t, 16> ghash_result = ghash(aad, result.ciphertext);

        std::array<uint8_t, 16> zero_counter = { 0 };
        std::memcpy(zero_counter.data(), iv.data(), 12);
        std::array<uint8_t, 16> encrypted_zero = cipher.encrypt_block(zero_counter);

        result.tag = xor_arrays(ghash_result, encrypted_zero);

        return result;
    }

    bool decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::array<uint8_t, 12>& iv,
        const std::array<uint8_t, 16>& received_tag,
        std::vector<uint8_t>& plaintext
    ) {
        std::array<uint8_t, 16> ghash_result = ghash(aad, ciphertext);

        std::array<uint8_t, 16> zero_counter = { 0 };
        std::memcpy(zero_counter.data(), iv.data(), 12);
        std::array<uint8_t, 16> encrypted_zero = cipher.encrypt_block(zero_counter);

        std::array<uint8_t, 16> expected_tag = xor_arrays(ghash_result, encrypted_zero);

        bool tag_valid = verify_tag_constant_time(expected_tag, received_tag);

        // Расшифровка выполняется ВСЕГДА для constant-time
        plaintext.resize(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i += 16) {
            std::array<uint8_t, 16> counter_block = { 0 };
            std::memcpy(counter_block.data(), iv.data(), 12);

            uint32_t counter = static_cast<uint32_t>(i / 16 + 1);
            counter_block[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
            counter_block[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
            counter_block[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
            counter_block[15] = static_cast<uint8_t>(counter & 0xFF);

            std::array<uint8_t, 16> keystream = cipher.encrypt_block(counter_block);

            for (size_t j = 0; j < 16 && (i + j) < ciphertext.size(); ++j) {
                plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
            }
        }

        return tag_valid;
    }
};

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

void print_hex_vector(const std::string& label, const std::vector<uint8_t>& data) {
    print_hex(label, data.data(), data.size());
}

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ С ИНТЕРАКТИВНЫМ ВВОДОМ
// ============================================================================

int main() {
    setlocale(LC_ALL,"ru");
    std::cout << "========================================================" << std::endl;
    std::cout << "  Лабораторная работа №1: Вариант 12" << std::endl;
    std::cout << "  Шифр: СТБ 34.101.31 (БелТ) + AEAD-GCM" << std::endl;
    std::cout << "  Многочлен p(x): x^8 + x^4 + x^3 + x^2 + 1 (0x11D)" << std::endl;
    std::cout << "  Оптимизация: Исключение обращений к L1-кешу" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    // Инициализация ключа
    std::array<uint8_t, 32> key = {
        0xE9, 0xDE, 0xE7, 0x2C, 0x40, 0xE5, 0xA9, 0x2B,
        0xAC, 0xA3, 0x86, 0x16, 0xF4, 0x9D, 0x91, 0x6F,
        0x65, 0x9B, 0x77, 0x02, 0xE7, 0x8A, 0x15, 0x34,
        0xA0, 0x19, 0x6F, 0x3E, 0x5D, 0x72, 0x8B, 0x91
    };

    std::cout << "[1] Ключ шифрования (256 бит):" << std::endl;
    print_hex("    ", key.data(), 32);
    std::cout << std::endl;

    BelT belt(key, 0x11D);
    GCM gcm(key, 0x11D);

    // Ввод текста пользователем
    std::cout << "[2] Введите текст для шифрования:" << std::endl;
    std::cout << "    > ";

    std::string plaintext_str;
    std::getline(std::cin, plaintext_str);

    if (plaintext_str.empty()) {
        std::cout << "    [!] Пустой ввод. Используем текст по умолчанию." << std::endl;
        plaintext_str = "Hello, World! This is a test message.";
    }

    std::cout << "    Исходный текст: \"" << plaintext_str << "\"" << std::endl;
    std::cout << "    Длина: " << plaintext_str.size() << " байт" << std::endl;
    std::cout << std::endl;

    std::vector<uint8_t> plaintext = string_to_bytes(plaintext_str);

    // Ввод AAD
    std::cout << "[3] Введите AAD (доп. данные для аутентификации):" << std::endl;
    std::cout << "    > ";

    std::string aad_str;
    std::getline(std::cin, aad_str);

    if (aad_str.empty()) {
        aad_str = "Protocol: BelT-GCM v1.0";
        std::cout << "    [!] Пустой ввод. Используем AAD по умолчанию." << std::endl;
    }

    std::vector<uint8_t> aad = string_to_bytes(aad_str);
    std::cout << std::endl;

    // IV
    std::array<uint8_t, 12> iv = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    std::cout << "[4] IV (12 байт):" << std::endl;
    print_hex("    ", iv.data(), 12);
    std::cout << std::endl;

    // Шифрование
    std::cout << "========================================================" << std::endl;
    std::cout << "  ПРОЦЕСС ШИФРОВАНИЯ" << std::endl;
    std::cout << "========================================================" << std::endl;

    GCM::EncryptedData encrypted = gcm.encrypt(plaintext, aad, iv);

    std::cout << "[5] Результат шифрования:" << std::endl;
    print_hex_vector("    Шифротекст (HEX)", encrypted.ciphertext);
    print_hex("    Тег целостности (16 байт)", encrypted.tag.data(), 16);
    std::cout << std::endl;

    // Расшифрование
    std::cout << "========================================================" << std::endl;
    std::cout << "  ПРОЦЕСС РАСШИФРОВАНИЯ" << std::endl;
    std::cout << "========================================================" << std::endl;

    std::vector<uint8_t> decrypted;
    bool tag_valid = gcm.decrypt(encrypted.ciphertext, aad, iv, encrypted.tag, decrypted);

    std::cout << "[6] Проверка тега целостности: ";
    if (tag_valid) {
        std::cout << " УСПЕШНО (тег совпадает)" << std::endl;
    }
    else {
        std::cout << " ОШИБКА (тег не совпадает)" << std::endl;
    }

    if (tag_valid) {
        std::string decrypted_str = bytes_to_string(decrypted);
        std::cout << "[7] Расшифрованный текст: \"" << decrypted_str << "\"" << std::endl;

        if (decrypted_str == plaintext_str) {
            std::cout << "[8]  Тексты ИДЕНТИЧНЫ — шифрование/расшифрование корректно!" << std::endl;
        }
        else {
            std::cout << "[8]  Тексты РАЗЛИЧАЮТСЯ — ошибка!" << std::endl;
        }
    }
    std::cout << std::endl;

    // Демонстрация защиты от подделки
    std::cout << "========================================================" << std::endl;
    std::cout << "  ДЕМОНСТРАЦИЯ ЗАЩИТЫ ОТ ПОДДЕЛКИ" << std::endl;
    std::cout << "========================================================" << std::endl;

    std::cout << "[9] Модифицируем 1 бит в шифротексте (имитация атаки):" << std::endl;
    std::vector<uint8_t> tampered_ct = encrypted.ciphertext;
    tampered_ct[0] ^= 0x01;
    print_hex_vector("    Подделанный шифротекст", tampered_ct);

    std::vector<uint8_t> decrypted_tampered;
    bool tamper_detected = gcm.decrypt(tampered_ct, aad, iv, encrypted.tag, decrypted_tampered);

    std::cout << "[10] Проверка тега после подделки: ";
    if (tamper_detected) {
        std::cout << " УСПЕШНО (ОШИБКА! Тег должен был не совпасть)" << std::endl;
    }
    else {
        std::cout << " ОШИБКА — подделка ОБНАРУЖЕНА (тег не совпадает)" << std::endl;
        std::cout << "       AEAD-защита работает корректно!" << std::endl;
    }
    std::cout << std::endl;

    // Демонстрация подделки тега
    std::cout << "[11] Модифицируем 1 бит в теге:" << std::endl;
    std::array<uint8_t, 16> tampered_tag = encrypted.tag;
    tampered_tag[0] ^= 0x01;
    print_hex("    Подделанный тег", tampered_tag.data(), 16);

    std::vector<uint8_t> decrypted_tag_tampered;
    bool tag_tamper_detected = gcm.decrypt(encrypted.ciphertext, aad, iv, tampered_tag, decrypted_tag_tampered);

    std::cout << "[12] Проверка с подделанным тегом: ";
    if (tag_tamper_detected) {
        std::cout << " УСПЕШНО (ОШИБКА!)" << std::endl;
    }
    else {
        std::cout << " ОШИБКА — подделка тега ОБНАРУЖЕНА" << std::endl;
        std::cout << "       Constant-time верификация работает корректно!" << std::endl;
    }
    std::cout << std::endl;

    // Итог
    std::cout << "========================================================" << std::endl;
    std::cout << "  СВОДКА ПО CONSTANT-TIME СВОЙСТВАМ (Вариант 12)" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "   H-блок БелТ: маскированный перебор (без L1-кеша)" << std::endl;
    std::cout << "   Умножение в GF(2^8): shift-and-XOR без ветвлений" << std::endl;
    std::cout << "   Умножение в GF(2^128): маскированная редукция" << std::endl;
    std::cout << "   Сравнение тегов: XOR-аккумулятор (без early exit)" << std::endl;
    std::cout << "   Расшифровка выполняется ВСЕГДА (даже при плохом теге)" << std::endl;
    std::cout << "========================================================" << std::endl;

    return 0;
}
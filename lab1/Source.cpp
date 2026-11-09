#include <iostream>
#include <iomanip>
#include <array>
#include <cstdint>
#include <cstring>

// ============================================================================
// МОДУЛЬ 1: УНИВЕРСАЛЬНЫЙ КАЛЬКУЛЯТОР ГАЛУА GF(2^8)
// ============================================================================
class GaloisField28 {
private:
    uint16_t poly;      // Полный неприводимый многочлен (например, 0x11B)
    uint8_t  poly_byte; // Младшие 8 бит многочлена (0x1B)

public:
    explicit GaloisField28(uint16_t p = 0x11B) : poly(p), poly_byte(static_cast<uint8_t>(p & 0xFF)) {}

    // Сложение в GF(2^8) эквивалентно XOR
    inline uint8_t add(uint8_t a, uint8_t b) const {
        return a ^ b;
    }

    // Умножение методом shift-and-XOR в Constant-Time (без if/else)
    uint8_t multiply(uint8_t a, uint8_t b) const {
        uint8_t res = 0;
        for (int i = 0; i < 8; ++i) {
            // Маска бита b: 0xFF если бит установлен, иначе 0x00
            uint8_t bit_mask = static_cast<uint8_t>(-static_cast<int8_t>((b >> i) & 1));
            res ^= (a & bit_mask);

            // Редукция a = xtime(a) без ветвления
            uint8_t hi_bit = static_cast<uint8_t>(-static_cast<int8_t>((a >> 7) & 1));
            a = static_cast<uint8_t>(a << 1) ^ (hi_bit & poly_byte);
        }
        return res;
    }

    // Квадрат элемента: a^2
    inline uint8_t square(uint8_t a) const {
        return multiply(a, a);
    }

    // Обратный элемент a^(-1) = a^254 mod p(x) по МТФ (Constant-Time)
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
    // Для a = 0x00 автоматически дает 0x00
    uint8_t inverse(uint8_t a) const {
        uint8_t a2 = square(a);        // a^2
        uint8_t a4 = square(a2);       // a^4
        uint8_t a8 = square(a4);       // a^8
        uint8_t a16 = square(a8);       // a^16
        uint8_t a32 = square(a16);      // a^32
        uint8_t a64 = square(a32);      // a^64
        uint8_t a128 = square(a64);      // a^128

        uint8_t res = multiply(a128, a64);
        res = multiply(res, a32);
        res = multiply(res, a16);
        res = multiply(res, a8);
        res = multiply(res, a4);
        res = multiply(res, a2);
        return res;
    }

    // Аффинное преобразование AES над GF(2)
    static inline uint8_t affine_transform(uint8_t b) {
        // s_i = b_i ^ b_{(i+4)%8} ^ b_{(i+5)%8} ^ b_{(i+6)%8} ^ b_{(i+7)%8} ^ c_i
        uint8_t s = b ^
            static_cast<uint8_t>((b << 1) | (b >> 7)) ^
            static_cast<uint8_t>((b << 2) | (b >> 6)) ^
            static_cast<uint8_t>((b << 3) | (b >> 5)) ^
            static_cast<uint8_t>((b << 4) | (b >> 4));
        return s ^ 0x63;
    }

    // Вычисление S-box на лету (задача оптимизации варианта 1)
    uint8_t sbox_on_the_fly(uint8_t byte) const {
        uint8_t inv = inverse(byte);
        return affine_transform(inv);
    }
};

// ============================================================================
// МОДУЛЬ 2: БЛОЧНЫЙ ШИФР AES-128
// ============================================================================
class AES128 {
private:
    GaloisField28 gf;
    std::array<std::array<uint8_t, 16>, 11> round_keys;

    void key_expansion(const std::array<uint8_t, 16>& key) {
        std::memcpy(round_keys[0].data(), key.data(), 16);

        uint8_t rcon = 0x01;
        for (size_t r = 1; r <= 10; ++r) {
            std::array<uint8_t, 4> temp;
            for (size_t i = 0; i < 4; ++i) {
                temp[i] = round_keys[r - 1][12 + i];
            }

            // RotWord + SubWord на лету
            uint8_t t0 = gf.sbox_on_the_fly(temp[1]) ^ rcon;
            uint8_t t1 = gf.sbox_on_the_fly(temp[2]);
            uint8_t t2 = gf.sbox_on_the_fly(temp[3]);
            uint8_t t3 = gf.sbox_on_the_fly(temp[0]);

            // rcon = xtime(rcon)
            uint8_t hi_bit = static_cast<uint8_t>(-static_cast<int8_t>((rcon >> 7) & 1));
            rcon = static_cast<uint8_t>(rcon << 1) ^ (hi_bit & 0x1B);

            // Колонка 0
            round_keys[r][0] = round_keys[r - 1][0] ^ t0;
            round_keys[r][1] = round_keys[r - 1][1] ^ t1;
            round_keys[r][2] = round_keys[r - 1][2] ^ t2;
            round_keys[r][3] = round_keys[r - 1][3] ^ t3;

            // Колонки 1-3
            for (size_t col = 1; col < 4; ++col) {
                for (size_t row = 0; row < 4; ++row) {
                    round_keys[r][col * 4 + row] =
                        round_keys[r - 1][col * 4 + row] ^ round_keys[r][(col - 1) * 4 + row];
                }
            }
        }
    }

public:
    explicit AES128(const std::array<uint8_t, 16>& key, uint16_t poly = 0x11B) : gf(poly) {
        key_expansion(key);
    }

    std::array<uint8_t, 16> encrypt_block(const std::array<uint8_t, 16>& in) const {
        std::array<uint8_t, 16> state = in;

        // Начальный AddRoundKey
        for (size_t i = 0; i < 16; ++i) {
            state[i] ^= round_keys[0][i];
        }

        // Основные раунды 1..9
        for (size_t round = 1; round <= 9; ++round) {
            // 1. SubBytes на лету
            for (size_t i = 0; i < 16; ++i) {
                state[i] = gf.sbox_on_the_fly(state[i]);
            }

            // 2. ShiftRows
            std::array<uint8_t, 16> temp = state;
            state[1] = temp[5];  state[5] = temp[9];  state[9] = temp[13]; state[13] = temp[1];
            state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2];  state[14] = temp[6];
            state[3] = temp[15]; state[7] = temp[3];  state[11] = temp[7];  state[15] = temp[11];

            // 3. MixColumns (через калькулятор Галуа)
            for (size_t c = 0; c < 4; ++c) {
                size_t idx = c * 4;
                uint8_t s0 = state[idx + 0];
                uint8_t s1 = state[idx + 1];
                uint8_t s2 = state[idx + 2];
                uint8_t s3 = state[idx + 3];

                state[idx + 0] = gf.multiply(0x02, s0) ^ gf.multiply(0x03, s1) ^ s2 ^ s3;
                state[idx + 1] = s0 ^ gf.multiply(0x02, s1) ^ gf.multiply(0x03, s2) ^ s3;
                state[idx + 2] = s0 ^ s1 ^ gf.multiply(0x02, s2) ^ gf.multiply(0x03, s3);
                state[idx + 3] = gf.multiply(0x03, s0) ^ s1 ^ s2 ^ gf.multiply(0x02, s3);
            }

            // 4. AddRoundKey
            for (size_t i = 0; i < 16; ++i) {
                state[i] ^= round_keys[round][i];
            }
        }

        // Раунд 10: SubBytes -> ShiftRows -> AddRoundKey (без MixColumns)
        for (size_t i = 0; i < 16; ++i) {
            state[i] = gf.sbox_on_the_fly(state[i]);
        }

        std::array<uint8_t, 16> temp = state;
        state[1] = temp[5];  state[5] = temp[9];  state[9] = temp[13]; state[13] = temp[1];
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2];  state[14] = temp[6];
        state[3] = temp[15]; state[7] = temp[3];  state[11] = temp[7];  state[15] = temp[11];

        for (size_t i = 0; i < 16; ++i) {
            state[i] ^= round_keys[10][i];
        }

        return state;
    }
};

// ============================================================================
// МОДУЛЬ 3: AEAD-РЕЖИМ GCM И CONSTANT-TIME МЕХАНИЗМЫ
// ============================================================================
class AES_GCM {
private:
    AES128 cipher;
    std::array<uint8_t, 16> H{};

    // Умножение в GF(2^128) по модулю f(x) = x^128 + x^7 + x^2 + x + 1 (Constant-Time)
    static std::array<uint8_t, 16> gf128_mul(const std::array<uint8_t, 16>& X, const std::array<uint8_t, 16>& Y) {
        std::array<uint8_t, 16> Z{};
        std::array<uint8_t, 16> V = Y;

        for (int i = 0; i < 128; ++i) {
            uint8_t byte_val = X[i / 8];
            uint8_t bit = (byte_val >> (7 - (i % 8))) & 1;
            uint8_t bit_mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));

            for (size_t j = 0; j < 16; ++j) {
                Z[j] ^= (V[j] & bit_mask);
            }

            // Сдвиг V вправо на 1 бит
            uint8_t lsb_v = V[15] & 1;
            uint8_t carry = 0;
            for (size_t j = 0; j < 16; ++j) {
                uint8_t next_carry = (V[j] & 1) << 7;
                V[j] = (V[j] >> 1) | carry;
                carry = next_carry;
            }

            // Редукция константой 0xE1 по маске младшего бита
            uint8_t red_mask = static_cast<uint8_t>(-static_cast<int8_t>(lsb_v));
            V[0] ^= (0xE1 & red_mask);
        }
        return Z;
    }

    // Инкремент 32-битного счетчика
    static void inc32(std::array<uint8_t, 16>& block) {
        for (int i = 15; i >= 12; --i) {
            if (++block[i] != 0) break;
        }
    }

public:
    explicit AES_GCM(const std::array<uint8_t, 16>& key) : cipher(key) {
        std::array<uint8_t, 16> zero_block{};
        H = cipher.encrypt_block(zero_block);
    }

    void encrypt(
        const std::array<uint8_t, 12>& iv,
        const uint8_t* plaintext, size_t pt_len,
        const uint8_t* aad, size_t aad_len,
        uint8_t* ciphertext,
        std::array<uint8_t, 16>& tag
    ) {
        // Формирование CB_0: IV || 0x00000001
        std::array<uint8_t, 16> cb0{};
        std::memcpy(cb0.data(), iv.data(), 12);
        cb0[15] = 1;

        std::array<uint8_t, 16> cb = cb0;
        inc32(cb); // CB_1 для потока открытого текста

        // 1. CTR шифрование
        size_t offset = 0;
        while (offset < pt_len) {
            std::array<uint8_t, 16> pad = cipher.encrypt_block(cb);
            size_t chunk = (pt_len - offset < 16) ? (pt_len - offset) : 16;
            for (size_t i = 0; i < chunk; ++i) {
                ciphertext[offset + i] = plaintext[offset + i] ^ pad[i];
            }
            offset += chunk;
            inc32(cb);
        }

        // 2. GHASH
        std::array<uint8_t, 16> y{};

        // Обработка AAD
        offset = 0;
        while (offset < aad_len) {
            std::array<uint8_t, 16> block{};
            size_t chunk = (aad_len - offset < 16) ? (aad_len - offset) : 16;
            std::memcpy(block.data(), aad + offset, chunk);
            for (size_t i = 0; i < 16; ++i) y[i] ^= block[i];
            y = gf128_mul(y, H);
            offset += chunk;
        }

        // Обработка Ciphertext
        offset = 0;
        while (offset < pt_len) {
            std::array<uint8_t, 16> block{};
            size_t chunk = (pt_len - offset < 16) ? (pt_len - offset) : 16;
            std::memcpy(block.data(), ciphertext + offset, chunk);
            for (size_t i = 0; i < 16; ++i) y[i] ^= block[i];
            y = gf128_mul(y, H);
            offset += chunk;
        }

        // Блок длин (длины в битах, big-endian)
        std::array<uint8_t, 16> len_block{};
        uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
        uint64_t ct_bits = static_cast<uint64_t>(pt_len) * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
            len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
        }

        for (size_t i = 0; i < 16; ++i) y[i] ^= len_block[i];
        y = gf128_mul(y, H);

        // Итоговый тег: GHASH ^ E_K(CB_0)
        std::array<uint8_t, 16> e_cb0 = cipher.encrypt_block(cb0);
        for (size_t i = 0; i < 16; ++i) {
            tag[i] = y[i] ^ e_cb0[i];
        }
    }

    // Constant-time проверка тега целостности через битовый аккумулятор
    static bool verify_tag(const std::array<uint8_t, 16>& tag1, const std::array<uint8_t, 16>& tag2) {
        uint8_t delta = 0;
        for (size_t i = 0; i < 16; ++i) {
            delta |= (tag1[i] ^ tag2[i]);
        }
        return delta == 0;
    }
};

// ============================================================================
// ВЕРИФИКАЦИОННЫЙ ТЕСТОВЫЙ БЛОК
// ============================================================================
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << "\n";
}

int main() {
    setlocale(LC_ALL, "Russian");
    std::cout << "[+] Лабораторная работа №1. Вариант 1 (AES-128-GCM)\n";
    std::cout << "[+] Режим Constant-Time: генерация S-box через a^254 на лету\n\n";

    // NIST SP 800-38D Test Vector 1 (Empty PT and AAD)
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 12> iv{};
    std::array<uint8_t, 16> tag{};

    AES_GCM gcm(key);
    gcm.encrypt(iv, nullptr, 0, nullptr, 0, nullptr, tag);

    print_hex("Вычисленный Tag", tag.data(), 16);
    std::cout << "Ожидаемый Tag  : 58e2fccefa7e3061367f1d57a4e7455a\n";

    std::array<uint8_t, 16> expected_tag = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
    };

    bool valid = AES_GCM::verify_tag(tag, expected_tag);
    std::cout << "Верификация тега (Constant-Time): " << (valid ? "OK (SUCCESS)" : "FAIL") << "\n";

    return 0;
}
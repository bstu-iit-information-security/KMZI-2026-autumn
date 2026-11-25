Министерство образования Республики Беларусь

Учреждение образования
«Брестский Государственный технический университет»

Кафедра ИИТ

**Лабораторная работа №1**

По дисциплине «ССП»

Тема: «Низкоуровневая арифметика полей Галуа и блочные шифры в режиме AEAD»

> **Выполнил:**
>
> Студент 3 курса
>
> Группы ИИ-27/24
>
> Ханцевич Г.С.
>
> **Проверил:**
>
> Хацкевич А.С.

Брест 2026

---

**Цель работы:** автоматизация алгебраических вычислений путём создания универсального калькулятора конечных полей $\mathbb{GF}(2^8)$, реализация на его базе блочного шифра AES-128 в режиме аутентифицированного шифрования GCM и освоение техник программирования с постоянным временем исполнения (Constant-time).

**Индивидуальный вариант — №11:**

| Параметр | Значение |
|---|---|
| Алгоритм шифрования | AES-128 |
| Неприводимый многочлен $p(x)$ в $\mathbb{GF}(2^8)$ | $x^8+x^6+x^3+x^2+1$ (0x14D) |
| Полином GHASH $f(x)$ | $x^{128}+x^7+x^2+x+1$ |
| Задача оптимизации Constant-time | Алгоритм Карацубы для элементов $\mathbb{GF}(2^8)$ |

**Ход работы:**

**Задача:**

**Универсальный калькулятор полей Галуа, блочный шифр AES-128 и режим аутентифицированного шифрования GCM с элементами Constant-time защиты.**

1.1 [Модуль 1. Калькулятор поля Галуа (Galois Field Calculator):]{.underline}

- Класс `GaloisField`, принимающий на вход неприводимый многочлен $p(x)$ в виде целого числа (0x14D);
- Методы `add(a, b)`, `multiply(a, b)`, `inverse(a)`;
- Реализация умножения через классический алгоритм shift-and-xor и через алгоритм Карацубы (`multiplyKaratsuba`) — индивидуальная задача оптимизации варианта 11;
- Вычисление обратного элемента через малую теорему Ферма ($a^{254}\bmod p(x)$) фиксированной цепочкой возведений в квадрат — без ветвлений, зависящих от значения `a`;
- Динамическая генерация прямой и обратной таблицы замен (S-box) на основе аффинного преобразования над $\mathbb{GF}(2^8)$.

1.2 [Модуль 2. Блочный шифр AES-128:]{.underline}

- Расширение ключа (Key Schedule) с раундовыми константами Rcon, вычисляемыми динамически как степени образующего элемента поля из модуля 1;
- Раундовые преобразования `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`;
- Умножение на коэффициенты 0x02 и 0x03 в `MixColumns` выполняется через `multiplyKaratsuba` из модуля 1.

1.3 [Модуль 3. Режим AEAD-GCM и Constant-time защита:]{.underline}

- Вычисление вспомогательного ключа $H = E_K(0^{128})$;
- Режим счётчика (CTR) для шифрования данных;
- Функция GHASH — умножение в поле $\mathbb{GF}(2^{128})$ по модулю $f(x) = x^{128}+x^7+x^2+x+1$;
- Формирование и проверка тега целостности;
- Constant-time сравнение тегов через битовый XOR-аккумулятор (без раннего выхода из цикла).

**Код программы:**

Проект разбит на три изолированных модуля и главный файл с тестами. Файл сборки — `CMakeLists.txt`.

*Модуль 1 — `galois.h`*

```cpp
#ifndef GALOIS_H
#define GALOIS_H

#include <cstdint>

class GaloisField {
public:
    explicit GaloisField(uint16_t modulus);

    uint8_t add(uint8_t a, uint8_t b) const;
    uint8_t multiply(uint8_t a, uint8_t b) const;
    uint8_t multiplyKaratsuba(uint8_t a, uint8_t b) const;
    uint8_t power(uint8_t a, unsigned int exponent) const;
    uint8_t inverse(uint8_t a) const;
    void generateSBox(uint8_t sbox[256], uint8_t invSbox[256]) const;
    uint16_t modulus() const;

private:
    uint16_t modulus_;

    static uint16_t rawMultiply(uint8_t a, uint8_t b);
    uint8_t reduce(uint16_t value) const;
    static uint8_t affineTransform(uint8_t value);
};

#endif
```

*Модуль 1 — `galois.cpp`*

```cpp
#include "galois.h"

GaloisField::GaloisField(uint16_t modulus) : modulus_(modulus) {}

uint16_t GaloisField::modulus() const {
    return modulus_;
}

uint8_t GaloisField::add(uint8_t a, uint8_t b) const {
    return static_cast<uint8_t>(a ^ b);
}

uint16_t GaloisField::rawMultiply(uint8_t a, uint8_t b) {
    uint16_t result = 0;
    for (int i = 0; i < 8; ++i) {
        uint16_t bitMask = static_cast<uint16_t>(0) - static_cast<uint16_t>((b >> i) & 1);
        result = static_cast<uint16_t>(result ^ (bitMask & (static_cast<uint16_t>(a) << i)));
    }
    return result;
}

uint8_t GaloisField::reduce(uint16_t value) const {
    for (int i = 14; i >= 8; --i) {
        uint16_t bitMask = static_cast<uint16_t>(0) - static_cast<uint16_t>((value >> i) & 1);
        value = static_cast<uint16_t>(value ^ (bitMask & (static_cast<uint16_t>(modulus_) << (i - 8))));
    }
    return static_cast<uint8_t>(value);
}

uint8_t GaloisField::multiply(uint8_t a, uint8_t b) const {
    return reduce(rawMultiply(a, b));
}

uint8_t GaloisField::multiplyKaratsuba(uint8_t a, uint8_t b) const {
    uint8_t a1 = static_cast<uint8_t>(a >> 4);
    uint8_t a0 = static_cast<uint8_t>(a & 0x0F);
    uint8_t b1 = static_cast<uint8_t>(b >> 4);
    uint8_t b0 = static_cast<uint8_t>(b & 0x0F);

    uint16_t p0 = rawMultiply(a0, b0);
    uint16_t p2 = rawMultiply(a1, b1);
    uint16_t p1 = rawMultiply(static_cast<uint8_t>(a0 ^ a1), static_cast<uint8_t>(b0 ^ b1));

    uint16_t mid = static_cast<uint16_t>(p0 ^ p1 ^ p2);
    uint16_t raw = static_cast<uint16_t>((p2 << 8) ^ (mid << 4) ^ p0);

    return reduce(raw);
}

uint8_t GaloisField::power(uint8_t a, unsigned int exponent) const {
    uint8_t result = 1;
    uint8_t base = a;
    unsigned int e = exponent;
    while (e > 0) {
        if (e & 1u) {
            result = multiplyKaratsuba(result, base);
        }
        base = multiplyKaratsuba(base, base);
        e >>= 1;
    }
    return result;
}

uint8_t GaloisField::inverse(uint8_t a) const {
    uint8_t a2 = multiplyKaratsuba(a, a);
    uint8_t a4 = multiplyKaratsuba(a2, a2);
    uint8_t a8 = multiplyKaratsuba(a4, a4);
    uint8_t a16 = multiplyKaratsuba(a8, a8);
    uint8_t a32 = multiplyKaratsuba(a16, a16);
    uint8_t a64 = multiplyKaratsuba(a32, a32);
    uint8_t a128 = multiplyKaratsuba(a64, a64);

    uint8_t result = multiplyKaratsuba(a128, a64);
    result = multiplyKaratsuba(result, a32);
    result = multiplyKaratsuba(result, a16);
    result = multiplyKaratsuba(result, a8);
    result = multiplyKaratsuba(result, a4);
    result = multiplyKaratsuba(result, a2);
    return result;
}

uint8_t GaloisField::affineTransform(uint8_t value) {
    uint8_t result = 0;
    const uint8_t c = 0x63;
    for (int i = 0; i < 8; ++i) {
        uint8_t bit = 0;
        bit = static_cast<uint8_t>(bit ^ ((value >> i) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 4) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 5) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 6) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((value >> ((i + 7) % 8)) & 1));
        bit = static_cast<uint8_t>(bit ^ ((c >> i) & 1));
        result = static_cast<uint8_t>(result | (bit << i));
    }
    return result;
}

void GaloisField::generateSBox(uint8_t sbox[256], uint8_t invSbox[256]) const {
    for (int b = 0; b < 256; ++b) {
        uint8_t inv = inverse(static_cast<uint8_t>(b));
        sbox[b] = affineTransform(inv);
    }
    for (int b = 0; b < 256; ++b) {
        invSbox[sbox[b]] = static_cast<uint8_t>(b);
    }
}
```

*Модуль 2 — `aes128.h`*

```cpp
#ifndef AES128_H
#define AES128_H

#include <cstdint>
#include "galois.h"

class AES128 {
public:
    AES128(const GaloisField& field, const uint8_t key[16]);

    void encryptBlock(const uint8_t input[16], uint8_t output[16]) const;

private:
    const GaloisField& field_;
    uint8_t sbox_[256];
    uint8_t invSbox_[256];
    uint8_t roundKeys_[11][16];

    void keyExpansion(const uint8_t key[16]);
    void subBytes(uint8_t state[16]) const;
    void shiftRows(uint8_t state[16]) const;
    void mixColumns(uint8_t state[16]) const;
    void addRoundKey(uint8_t state[16], int round) const;
    uint8_t rcon(unsigned int index) const;
};

#endif
```

*Модуль 2 — `aes128.cpp`*

```cpp
#include "aes128.h"

AES128::AES128(const GaloisField& field, const uint8_t key[16]) : field_(field) {
    field_.generateSBox(sbox_, invSbox_);
    keyExpansion(key);
}

uint8_t AES128::rcon(unsigned int index) const {
    return field_.power(0x02, index - 1);
}

void AES128::keyExpansion(const uint8_t key[16]) {
    uint8_t w[44][4];

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            w[i][j] = key[i * 4 + j];
        }
    }

    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4] = { w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3] };

        if (i % 4 == 0) {
            uint8_t rotated[4] = { temp[1], temp[2], temp[3], temp[0] };
            uint8_t subbed[4];
            for (int k = 0; k < 4; ++k) {
                subbed[k] = sbox_[rotated[k]];
            }
            subbed[0] = static_cast<uint8_t>(subbed[0] ^ rcon(i / 4));
            for (int k = 0; k < 4; ++k) {
                temp[k] = subbed[k];
            }
        }

        for (int k = 0; k < 4; ++k) {
            w[i][k] = static_cast<uint8_t>(w[i - 4][k] ^ temp[k]);
        }
    }

    for (int r = 0; r < 11; ++r) {
        for (int col = 0; col < 4; ++col) {
            for (int row = 0; row < 4; ++row) {
                roundKeys_[r][row + 4 * col] = w[r * 4 + col][row];
            }
        }
    }
}

void AES128::subBytes(uint8_t state[16]) const {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox_[state[i]];
    }
}

void AES128::shiftRows(uint8_t state[16]) const {
    uint8_t temp[16];
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            temp[row + 4 * col] = state[row + 4 * ((col + row) % 4)];
        }
    }
    for (int i = 0; i < 16; ++i) {
        state[i] = temp[i];
    }
}

void AES128::mixColumns(uint8_t state[16]) const {
    for (int col = 0; col < 4; ++col) {
        uint8_t s0 = state[4 * col + 0];
        uint8_t s1 = state[4 * col + 1];
        uint8_t s2 = state[4 * col + 2];
        uint8_t s3 = state[4 * col + 3];

        uint8_t r0 = static_cast<uint8_t>(field_.multiplyKaratsuba(0x02, s0) ^ field_.multiplyKaratsuba(0x03, s1) ^ s2 ^ s3);
        uint8_t r1 = static_cast<uint8_t>(s0 ^ field_.multiplyKaratsuba(0x02, s1) ^ field_.multiplyKaratsuba(0x03, s2) ^ s3);
        uint8_t r2 = static_cast<uint8_t>(s0 ^ s1 ^ field_.multiplyKaratsuba(0x02, s2) ^ field_.multiplyKaratsuba(0x03, s3));
        uint8_t r3 = static_cast<uint8_t>(field_.multiplyKaratsuba(0x03, s0) ^ s1 ^ s2 ^ field_.multiplyKaratsuba(0x02, s3));

        state[4 * col + 0] = r0;
        state[4 * col + 1] = r1;
        state[4 * col + 2] = r2;
        state[4 * col + 3] = r3;
    }
}

void AES128::addRoundKey(uint8_t state[16], int round) const {
    for (int i = 0; i < 16; ++i) {
        state[i] = static_cast<uint8_t>(state[i] ^ roundKeys_[round][i]);
    }
}

void AES128::encryptBlock(const uint8_t input[16], uint8_t output[16]) const {
    uint8_t state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = input[i];
    }

    addRoundKey(state, 0);

    for (int round = 1; round <= 9; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, 10);

    for (int i = 0; i < 16; ++i) {
        output[i] = state[i];
    }
}
```

*Модуль 3 — `gcm.h`*

```cpp
#ifndef GCM_H
#define GCM_H

#include <cstdint>
#include <cstddef>
#include "aes128.h"

class GCM {
public:
    explicit GCM(const AES128& cipher);

    void encrypt(const uint8_t iv[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* plaintext, size_t ptLen,
                 uint8_t* ciphertext,
                 uint8_t tag[16]) const;

    bool decrypt(const uint8_t iv[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* ciphertext, size_t ctLen,
                 const uint8_t tag[16],
                 uint8_t* plaintext) const;

private:
    const AES128& cipher_;
    uint8_t h_[16];

    void gf128Multiply(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) const;
    void ghash(const uint8_t* aad, size_t aadLen, const uint8_t* data, size_t dataLen, uint8_t result[16]) const;
    void computeJ0(const uint8_t iv[12], uint8_t j0[16]) const;
    void incrementCounter(uint8_t block[16]) const;
    void ctrProcess(const uint8_t j0[16], const uint8_t* input, size_t len, uint8_t* output) const;
    static bool constantTimeEqual(const uint8_t a[16], const uint8_t b[16]);
};

#endif
```

*Модуль 3 — `gcm.cpp`*

```cpp
#include "gcm.h"

GCM::GCM(const AES128& cipher) : cipher_(cipher) {
    uint8_t zero[16] = { 0 };
    cipher_.encryptBlock(zero, h_);
}

void GCM::gf128Multiply(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) const {
    uint8_t v[16];
    for (int i = 0; i < 16; ++i) {
        v[i] = y[i];
    }
    uint8_t z[16] = { 0 };

    for (int i = 0; i < 128; ++i) {
        int byteIndex = i / 8;
        int bitIndex = 7 - (i % 8);
        uint8_t bit = static_cast<uint8_t>((x[byteIndex] >> bitIndex) & 1);
        uint8_t mask = static_cast<uint8_t>(static_cast<uint8_t>(0) - bit);

        for (int j = 0; j < 16; ++j) {
            z[j] = static_cast<uint8_t>(z[j] ^ (mask & v[j]));
        }

        uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = static_cast<uint8_t>(v[0] >> 1);

        uint8_t lsbMask = static_cast<uint8_t>(static_cast<uint8_t>(0) - lsb);
        v[0] = static_cast<uint8_t>(v[0] ^ (lsbMask & 0xE1));
    }

    for (int i = 0; i < 16; ++i) {
        result[i] = z[i];
    }
}

void GCM::ghash(const uint8_t* aad, size_t aadLen, const uint8_t* data, size_t dataLen, uint8_t result[16]) const {
    uint8_t y[16] = { 0 };

    size_t aadBlocks = (aadLen + 15) / 16;
    for (size_t b = 0; b < aadBlocks; ++b) {
        uint8_t block[16] = { 0 };
        size_t offset = b * 16;
        size_t remaining = aadLen - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            block[i] = aad[offset + i];
        }
        uint8_t xored[16];
        for (int i = 0; i < 16; ++i) {
            xored[i] = static_cast<uint8_t>(y[i] ^ block[i]);
        }
        gf128Multiply(xored, h_, y);
    }

    size_t dataBlocks = (dataLen + 15) / 16;
    for (size_t b = 0; b < dataBlocks; ++b) {
        uint8_t block[16] = { 0 };
        size_t offset = b * 16;
        size_t remaining = dataLen - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            block[i] = data[offset + i];
        }
        uint8_t xored[16];
        for (int i = 0; i < 16; ++i) {
            xored[i] = static_cast<uint8_t>(y[i] ^ block[i]);
        }
        gf128Multiply(xored, h_, y);
    }

    uint8_t lengthBlock[16] = { 0 };
    uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
    uint64_t dataBits = static_cast<uint64_t>(dataLen) * 8;
    for (int i = 0; i < 8; ++i) {
        lengthBlock[7 - i] = static_cast<uint8_t>((aadBits >> (8 * i)) & 0xFF);
        lengthBlock[15 - i] = static_cast<uint8_t>((dataBits >> (8 * i)) & 0xFF);
    }
    uint8_t xored[16];
    for (int i = 0; i < 16; ++i) {
        xored[i] = static_cast<uint8_t>(y[i] ^ lengthBlock[i]);
    }
    gf128Multiply(xored, h_, y);

    for (int i = 0; i < 16; ++i) {
        result[i] = y[i];
    }
}

void GCM::computeJ0(const uint8_t iv[12], uint8_t j0[16]) const {
    for (int i = 0; i < 12; ++i) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;
}

void GCM::incrementCounter(uint8_t block[16]) const {
    for (int i = 15; i >= 12; --i) {
        block[i] = static_cast<uint8_t>(block[i] + 1);
        if (block[i] != 0) {
            break;
        }
    }
}

void GCM::ctrProcess(const uint8_t j0[16], const uint8_t* input, size_t len, uint8_t* output) const {
    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) {
        counter[i] = j0[i];
    }
    incrementCounter(counter);

    size_t blocks = (len + 15) / 16;
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t keystream[16];
        cipher_.encryptBlock(counter, keystream);

        size_t offset = b * 16;
        size_t remaining = len - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = static_cast<uint8_t>(input[offset + i] ^ keystream[i]);
        }

        incrementCounter(counter);
    }
}

bool GCM::constantTimeEqual(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

void GCM::encrypt(const uint8_t iv[12],
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* plaintext, size_t ptLen,
                   uint8_t* ciphertext,
                   uint8_t tag[16]) const {
    uint8_t j0[16];
    computeJ0(iv, j0);

    ctrProcess(j0, plaintext, ptLen, ciphertext);

    uint8_t s[16];
    ghash(aad, aadLen, ciphertext, ptLen, s);

    uint8_t ek0[16];
    cipher_.encryptBlock(j0, ek0);

    for (int i = 0; i < 16; ++i) {
        tag[i] = static_cast<uint8_t>(s[i] ^ ek0[i]);
    }
}

bool GCM::decrypt(const uint8_t iv[12],
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* ciphertext, size_t ctLen,
                   const uint8_t tag[16],
                   uint8_t* plaintext) const {
    uint8_t j0[16];
    computeJ0(iv, j0);

    uint8_t s[16];
    ghash(aad, aadLen, ciphertext, ctLen, s);

    uint8_t ek0[16];
    cipher_.encryptBlock(j0, ek0);

    uint8_t computedTag[16];
    for (int i = 0; i < 16; ++i) {
        computedTag[i] = static_cast<uint8_t>(s[i] ^ ek0[i]);
    }

    bool valid = constantTimeEqual(computedTag, tag);

    ctrProcess(j0, ciphertext, ctLen, plaintext);

    return valid;
}
```

*Главный файл — `main.cpp`*

```cpp
#include <cstdio>
#include <cstring>
#include "galois.h"
#include "aes128.h"
#include "gcm.h"

static void printHex(const char* label, const uint8_t* data, size_t len) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        std::printf("%02X", data[i]);
    }
    std::printf("\n");
}

int main() {
    GaloisField gf(0x14D);

    bool inverseOk = true;
    for (int a = 1; a < 256; ++a) {
        uint8_t inv = gf.inverse(static_cast<uint8_t>(a));
        uint8_t check = gf.multiply(static_cast<uint8_t>(a), inv);
        if (check != 0x01) {
            inverseOk = false;
        }
    }
    std::printf("Test 1 (inverse correctness for all nonzero elements): %s\n", inverseOk ? "PASS" : "FAIL");
    std::printf("Test 1b (inverse of 0x00 maps to 0x00):                %s\n", gf.inverse(0x00) == 0x00 ? "PASS" : "FAIL");

    bool karatsubaOk = true;
    for (int a = 0; a < 256; ++a) {
        for (int b = 0; b < 256; ++b) {
            if (gf.multiply(static_cast<uint8_t>(a), static_cast<uint8_t>(b)) !=
                gf.multiplyKaratsuba(static_cast<uint8_t>(a), static_cast<uint8_t>(b))) {
                karatsubaOk = false;
            }
        }
    }
    std::printf("Test 2 (Karatsuba multiplication matches shift-and-xor for all pairs): %s\n", karatsubaOk ? "PASS" : "FAIL");

    uint8_t sbox[256];
    uint8_t invSbox[256];
    gf.generateSBox(sbox, invSbox);
    bool sboxOk = true;
    for (int b = 0; b < 256; ++b) {
        if (invSbox[sbox[b]] != b) {
            sboxOk = false;
        }
    }
    std::printf("Test 3 (S-box is a bijection, inverse S-box correctness):              %s\n", sboxOk ? "PASS" : "FAIL");

    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    AES128 aes(gf, key);

    uint8_t plainBlock[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t cipherBlock[16];
    aes.encryptBlock(plainBlock, cipherBlock);
    printHex("Test 4 plaintext block ", plainBlock, 16);
    printHex("Test 4 ciphertext block", cipherBlock, 16);

    GCM gcm(aes);

    uint8_t iv[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    const char* aadText = "header-data";
    const char* msgText = "Laboratory work variant 11: AES-128 with custom GF(2^8) polynomial and Karatsuba multiplication.";
    size_t aadLen = std::strlen(aadText);
    size_t msgLen = std::strlen(msgText);

    uint8_t ciphertext[256];
    uint8_t tag[16];
    gcm.encrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                reinterpret_cast<const uint8_t*>(msgText), msgLen,
                ciphertext, tag);

    printHex("Test 5 ciphertext", ciphertext, msgLen);
    printHex("Test 5 tag       ", tag, 16);

    uint8_t decrypted[256];
    bool validTag = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                 ciphertext, msgLen, tag, decrypted);
    decrypted[msgLen] = '\0';
    std::printf("Test 5 decrypted text: %s\n", decrypted);
    std::printf("Test 5 (tag verification on correct data):             %s\n", validTag ? "PASS" : "FAIL");

    uint8_t tamperedTag[16];
    std::memcpy(tamperedTag, tag, 16);
    tamperedTag[0] = static_cast<uint8_t>(tamperedTag[0] ^ 0x01);
    bool tamperedValid = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                      ciphertext, msgLen, tamperedTag, decrypted);
    std::printf("Test 6 (rejects tampered tag):                         %s\n", !tamperedValid ? "PASS" : "FAIL");

    uint8_t tamperedCiphertext[256];
    std::memcpy(tamperedCiphertext, ciphertext, msgLen);
    tamperedCiphertext[0] = static_cast<uint8_t>(tamperedCiphertext[0] ^ 0x01);
    bool tamperedCtValid = gcm.decrypt(iv, reinterpret_cast<const uint8_t*>(aadText), aadLen,
                                        tamperedCiphertext, msgLen, tag, decrypted);
    std::printf("Test 7 (rejects tampered ciphertext):                  %s\n", !tamperedCtValid ? "PASS" : "FAIL");

    return 0;
}
```

**Результаты выполнения программы:**

```
Test 1 (inverse correctness for all nonzero elements): PASS
Test 1b (inverse of 0x00 maps to 0x00):                PASS
Test 2 (Karatsuba multiplication matches shift-and-xor for all pairs): PASS
Test 3 (S-box is a bijection, inverse S-box correctness):              PASS
Test 4 plaintext block : 00112233445566778899AABBCCDDEEFF
Test 4 ciphertext block: 5A16D072429581B890CB18718121B495
Test 5 ciphertext: 57AC269AC8D452B8558F41FFB5718CD528FC5B112C1034417ED39BF012C62896F5FCBFB88AD483448FBAD05A0F8C4D79C5C0634E9B8462DFF7EBD41C31F8637D637B34C74FB62E1FA68C17B69B414B93C69ED79E91BDE2B7FF3F90B9A98E801E
Test 5 tag       : 7AE9094F4D467E26FF3FFAF93D06D726
Test 5 decrypted text: Laboratory work variant 11: AES-128 with custom GF(2^8) polynomial and Karatsuba multiplication.
Test 5 (tag verification on correct data):             PASS
Test 6 (rejects tampered tag):                         PASS
Test 7 (rejects tampered ciphertext):                  PASS
```

Программа реализует три изолированных модуля, взаимодействующих строго последовательно. Модуль `GaloisField` инициализируется неприводимым многочленом варианта $p(x)=\text{0x14D}$ и предоставляет операции `add`, `multiply` (классическое умножение по алгоритму shift-and-xor с редукцией по модулю через маскирование старших бит без ветвлений) и `multiplyKaratsuba` — умножение по алгоритму Карацубы, в котором каждый байт делится на два полубайта, вычисляются три «сырых» произведения половинной длины ($p_0$, $p_1$, $p_2$) и собираются в итоговый многочлен, после чего приводятся по тому же модулю; корректность метода подтверждена полным перебором всех $256\times256$ пар (Тест 2). Мультипликативно обратный элемент вычисляется через малую теорему Ферма фиксированной цепочкой из семи возведений в квадрат и шести умножений ($a^{254}=a^{128}\cdot a^{64}\cdots a^2$), что не содержит зависящих от `a` ветвлений и корректно обрабатывает нулевой элемент без специальной проверки (Тесты 1 и 1б). На основе `inverse` и аффинного преобразования с матрицей $M$ и константой $c=\text{0x63}$ строится таблица подстановки S-box и обратная к ней, биективность которых проверена перебором (Тест 3). Класс `AES128` использует эту таблицу в процедуре расширения ключа `keyExpansion` (с раундовыми константами Rcon, вычисляемыми как степени элемента 0x02 в том же поле) и в раундовых функциях `subBytes`, `shiftRows`, `mixColumns` (умножения на 2 и 3 выполняются через `multiplyKaratsuba`) и `addRoundKey`; метод `encryptBlock` последовательно выполняет начальное наложение ключа, девять полных раундов и финальный раунд без `MixColumns` (Тест 4). Класс `GCM` при создании шифрует нулевой блок для получения ключа хеширования $H$, реализует режим счётчика CTR через `ctrProcess`/`incrementCounter`, умножение в поле $\mathbb{GF}(2^{128})$ через побитовый алгоритм `gf128Multiply` (с редукционной константой 0xE1, соответствующей полиному $f(x)=x^{128}+x^7+x^2+x+1$) и функцию `ghash`, объединяющую AAD, шифротекст и блок длин; итоговый тег формируется XOR-ом результата GHASH с шифрованием блока $J_0$. Метод `decrypt` пересчитывает тег и сравнивает его с переданным через `constantTimeEqual` — побитовый XOR-аккумулятор без раннего выхода из цикла, что исключает утечку по времени о позиции несовпадения; расшифровка данных выполняется независимо от результата проверки. Сквозной сценарий шифрования и расшифровки текста с дополнительными аутентифицируемыми данными подтверждает совпадение исходного и расшифрованного текста при корректном теге (Тест 5), а также корректное отклонение подменённого тега (Тест 6) и подменённого шифротекста (Тест 7).

**Вывод:** Разработан универсальный калькулятор поля $\mathbb{GF}(2^8)$ с классическим и оптимизированным (по алгоритму Карацубы) умножением, на его основе реализован блочный шифр AES-128 с динамически генерируемым S-box под индивидуальный неприводимый многочлен варианта, а также режим аутентифицированного шифрования GCM с constant-time проверкой имитовставки. Изучены основы арифметики конечных полей, архитектуры SP-сетей, построения S-блоков и техник защиты от атак по времени выполнения.

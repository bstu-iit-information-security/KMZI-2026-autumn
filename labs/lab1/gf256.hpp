
#pragma once
#include <array>
#include <cstdint>

namespace gf {

// Маска 0xFF, если младший бит равен 1, иначе 0x00.
inline uint8_t mask_from_bit(uint8_t bit) {
    return static_cast<uint8_t>(0u - static_cast<uint32_t>(bit & 1u));
}

// Маска 0xFF, если x == 0, иначе 0x00 (без ветвлений).
inline uint8_t mask_is_zero(uint8_t x) {
    return static_cast<uint8_t>((static_cast<uint32_t>(x) - 1u) >> 8);
}

inline uint8_t rotl8(uint8_t x, unsigned k) {
    return static_cast<uint8_t>((x << k) | (x >> (8 - k)));
}

// Constant-time выбор из таблицы по секретному индексу:
// просматриваются все 256 элементов, адрес обращения не зависит от idx.
inline uint8_t ct_lookup(const std::array<uint8_t, 256>& table, uint8_t idx) {
    uint8_t r = 0;
    for (uint32_t i = 0; i < 256; ++i) {
        const uint32_t d = i ^ idx;  // 0 тогда и только тогда, когда i == idx
        const uint8_t m = static_cast<uint8_t>((d - 1u) >> 8);
        r |= static_cast<uint8_t>(table[i] & m);
    }
    return r;
}

class GF256 {
public:
    explicit GF256(uint16_t p_x) : p_(p_x) {}

    uint16_t poly() const { return p_; }

    // ---- сложение: XOR коэффициентов ----
    static uint8_t add(uint8_t a, uint8_t b) { return static_cast<uint8_t>(a ^ b); }

    // ---- умножение на x (xtime) без ветвлений ----
    // result = (b << 1) ^ (mask(b7) & p_byte)
    static uint8_t xtime(uint8_t b, uint8_t p_byte) {
        const uint8_t mask = mask_from_bit(static_cast<uint8_t>(b >> 7));
        return static_cast<uint8_t>((b << 1) ^ (mask & p_byte));
    }

    // ---- умножение: shift-and-XOR, ровно 8 итераций ----
    static uint8_t multiply(uint8_t a, uint8_t b, uint16_t p_x) {
        const uint8_t p_byte = static_cast<uint8_t>(p_x & 0xFFu);  // без старшего члена x^8
        uint8_t r = 0;
        for (int i = 0; i < 8; ++i) {
            r ^= static_cast<uint8_t>(a & mask_from_bit(b));  // r ^= a, если младший бит b == 1
            b = static_cast<uint8_t>(b >> 1);
            a = xtime(a, p_byte);
        }
        return r;
    }
    uint8_t multiply(uint8_t a, uint8_t b) const { return multiply(a, b, p_); }

    // ---- обратный элемент: a^254 (малая теорема Ферма), фиксированная цепочка ----
    // inverse(0) = 0, деления на ноль нет.
    static uint8_t inverse(uint8_t a, uint16_t p_x) {
        uint8_t sq = multiply(a, a, p_x);  // a^2
        uint8_t r = sq;
        for (int i = 0; i < 6; ++i) {      // a^4, a^8, ..., a^128
            sq = multiply(sq, sq, p_x);
            r = multiply(r, sq, p_x);
        }
        return r;                           // a^(2+4+...+128) = a^254
    }
    uint8_t inverse(uint8_t a) const { return inverse(a, p_); }

    // ---- обратный элемент: расширенный алгоритм Евклида (НЕ constant-time) ----
    // Используется только для перекрёстной проверки в тестах.
    static uint8_t inverse_euclid(uint8_t a, uint16_t p_x) {
        if (a == 0) return 0;
        uint32_t r0 = p_x, r1 = a, t0 = 0, t1 = 1;
        while (r1 != 0) {
            uint32_t q = 0, rem = r0;
            const int d1 = degree(r1);
            while (degree(rem) >= d1) {
                const int s = degree(rem) - d1;
                q ^= 1u << s;
                rem ^= r1 << s;
            }
            uint32_t qt = 0;
            for (int i = 0; i < 16; ++i)
                if ((q >> i) & 1u) qt ^= t1 << i;
            const uint32_t t2 = t0 ^ qt;
            r0 = r1; r1 = rem; t0 = t1; t1 = t2;
        }
        return static_cast<uint8_t>(t0);
    }

    // ---- проверка неприводимости p(x) степени 8 перебором делителей степени 1..4 ----
    static bool is_irreducible(uint16_t p_x) {
        if (degree(p_x) != 8) return false;
        for (uint32_t d = 2; d < 32; ++d) {
            uint32_t rem = p_x;
            const int dd = degree(d);
            while (degree(rem) >= dd) rem ^= d << (degree(rem) - dd);
            if (rem == 0) return false;
        }
        return true;
    }

    // ---- аффинное преобразование S-блока AES: M*b + 0x63 ----
    static uint8_t affine(uint8_t b) {
        return static_cast<uint8_t>(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63u);
    }
    static uint8_t inv_affine(uint8_t b) {
        return static_cast<uint8_t>(rotl8(b, 1) ^ rotl8(b, 3) ^ rotl8(b, 6) ^ 0x05u);
    }

    // ---- динамическая генерация S-box и обратного S-box для заданного p(x) ----
    void generate_sbox(std::array<uint8_t, 256>& sbox, std::array<uint8_t, 256>& inv_sbox) const {
        for (uint32_t x = 0; x < 256; ++x) {
            const uint8_t s = affine(inverse(static_cast<uint8_t>(x)));
            sbox[x] = s;
            inv_sbox[s] = static_cast<uint8_t>(x);
        }
    }

private:
    static int degree(uint32_t v) {
        int d = -1;
        while (v) { ++d; v >>= 1; }
        return d;
    }
    uint16_t p_;
};

}  // namespace gf

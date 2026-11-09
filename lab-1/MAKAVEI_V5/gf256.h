#pragma once
#include <array>
#include <cstdint>

namespace lab1 {

    // Универсальный калькулятор поля GF(2^8).
    // poly — целое представление неприводимого многочлена,
    // включая старший член x^8. Например: 0x12D -> x^8+x^5+x^3+x^2+1
    class GaloisField {
    public:
        explicit GaloisField(uint16_t poly);

        // Сложение в GF(2^8) = XOR
        static uint8_t add(uint8_t a, uint8_t b) {
            return static_cast<uint8_t>(a ^ b);
        }

        // Умножение: shift-and-XOR, constant-time (без ветвлений)
        uint8_t multiply(uint8_t a, uint8_t b) const;

        // Обратный элемент через a^254 (Ферма), constant-time
        uint8_t inverse(uint8_t a) const;

        // Возведение в степень (не constant-time, только для отладки)
        uint8_t power(uint8_t a, uint16_t n) const;

        uint16_t poly()     const { return poly_; }
        uint8_t  polyByte() const { return poly_byte_; }

        const std::array<uint8_t, 256>& sbox() const { return sbox_; }

    private:
        uint16_t poly_;
        uint8_t  poly_byte_;                  // младшие 8 бит полинома
        std::array<uint8_t, 256> sbox_;

        void buildSbox();
        static uint8_t affineTransform(uint8_t x);
    };

} // namespace lab1
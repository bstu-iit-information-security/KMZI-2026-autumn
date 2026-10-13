#pragma once
#include <array>
#include <cstdint>
#include <string>

// BigInt фиксированного размера: 2048 бит = 64 × 32-битных слов.
// Хранение little-endian. Без динамической памяти.
class BigInt {
public:
    static constexpr size_t MAX_WORDS = 64; // 2048 бит — хватает с запасом
    std::array<uint32_t, MAX_WORDS> words{};
    size_t size = 0;       // количество значащих слов
    bool negative = false; // знак

    BigInt() = default;
    BigInt(uint64_t v);
    explicit BigInt(const std::string& hex_str);

    // Арифметика
    BigInt operator+(const BigInt& o) const;
    BigInt operator-(const BigInt& o) const;
    BigInt operator*(const BigInt& o) const;
    BigInt operator/(const BigInt& o) const;
    BigInt operator%(const BigInt& o) const;
    BigInt& operator+=(const BigInt& o) { *this = *this + o; return *this; }
    BigInt& operator-=(const BigInt& o) { *this = *this - o; return *this; }
    BigInt& operator*=(const BigInt& o) { *this = *this * o; return *this; }
    BigInt& operator%=(const BigInt& o) { *this = *this % o; return *this; }
    BigInt& operator=(uint64_t v);

    // Битовые
    BigInt operator&(const BigInt& o) const;
    BigInt operator^(const BigInt& o) const;
    BigInt operator|(const BigInt& o) const;
    BigInt operator>>(size_t shift) const;
    BigInt operator<<(size_t shift) const;

    // Сравнения
    bool operator==(const BigInt& o) const;
    bool operator!=(const BigInt& o) const { return !(*this == o); }
    bool operator<(const BigInt& o) const;
    bool operator>(const BigInt& o) const { return o < *this; }
    bool operator<=(const BigInt& o) const { return !(o < *this); }
    bool operator>=(const BigInt& o) const { return !(*this < o); }

    // Утилиты
    bool is_zero() const { return size == 0; }
    bool is_odd() const { return size > 0 && (words[0] & 1); }
    size_t bit_length() const;
    bool bit(size_t i) const;
    std::string to_hex() const;
    uint64_t to_uint64() const;

    void trim(); // удаляет ведущие нулевые слова

    // Constant-time выбор (без IF)
    void cmov(const BigInt& other, bool condition);
    static BigInt constant_time_select(bool condition, const BigInt& true_val, const BigInt& false_val);
};

// Модульная арифметика
BigInt mod_add(const BigInt& a, const BigInt& b, const BigInt& p);
BigInt mod_sub(const BigInt& a, const BigInt& b, const BigInt& p);
BigInt mod_mul(const BigInt& a, const BigInt& b, const BigInt& p);
BigInt mod_pow(const BigInt& base, const BigInt& exp, const BigInt& mod);
BigInt mod_inverse(const BigInt& a, const BigInt& p);

BigInt random_scalar(const BigInt& q);
std::string to_hex(const BigInt& value);

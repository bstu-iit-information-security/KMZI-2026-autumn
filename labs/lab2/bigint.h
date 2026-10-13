#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <random>
#include <string>
#include <cstring>
#include <algorithm>

class BigInt {
public:
    using Word = uint32_t;
    using DWord = uint64_t;
    std::vector<Word> words;

    BigInt() { words.push_back(0); }
    BigInt(uint64_t v) {
        words.push_back(static_cast<Word>(v & 0xFFFFFFFF));
        if (v >> 32) words.push_back(static_cast<Word>(v >> 32));
    }

    void trim() { while (words.size() > 1 && words.back() == 0) words.pop_back(); }
    bool is_zero() const { return words.size() == 1 && words[0] == 0; }
    bool is_odd() const { return words[0] & 1; }

    static int cmp(const BigInt& a, const BigInt& b) {
        if (a.words.size() != b.words.size())
            return a.words.size() < b.words.size() ? -1 : 1;
        for (int i = static_cast<int>(a.words.size()) - 1; i >= 0; --i) {
            if (a.words[i] != b.words[i])
                return a.words[i] < b.words[i] ? -1 : 1;
        }
        return 0;
    }

    bool operator<(const BigInt& o)  const { return cmp(*this, o) <  0; }
    bool operator<=(const BigInt& o) const { return cmp(*this, o) <= 0; }
    bool operator>(const BigInt& o)  const { return cmp(*this, o) >  0; }
    bool operator>=(const BigInt& o) const { return cmp(*this, o) >= 0; }
    bool operator==(const BigInt& o) const { return cmp(*this, o) == 0; }
    bool operator!=(const BigInt& o) const { return cmp(*this, o) != 0; }

    BigInt operator+(const BigInt& o) const {
        BigInt res;
        res.words.assign(std::max(words.size(), o.words.size()) + 1, 0);
        DWord carry = 0;
        for (size_t i = 0; i < res.words.size(); ++i) {
            DWord sum = carry;
            if (i < words.size())   sum += words[i];
            if (i < o.words.size()) sum += o.words[i];
            res.words[i] = static_cast<Word>(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        res.trim();
        return res;
    }

    // ВНИМАНИЕ: требует *this >= o. Для general-purpose используйте вычитание со знаком.
    BigInt operator-(const BigInt& o) const {
        BigInt res;
        res.words.assign(words.size(), 0);
        int64_t borrow = 0;
        for (size_t i = 0; i < words.size(); ++i) {
            int64_t diff = static_cast<int64_t>(words[i]) - borrow
                         - (i < o.words.size() ? o.words[i] : 0);
            if (diff < 0) { diff += 0x100000000LL; borrow = 1; }
            else { borrow = 0; }
            res.words[i] = static_cast<Word>(diff);
        }
        res.trim();
        return res;
    }

    BigInt operator*(const BigInt& o) const {
        BigInt res;
        res.words.assign(words.size() + o.words.size(), 0);
        for (size_t i = 0; i < words.size(); ++i) {
            DWord carry = 0;
            for (size_t j = 0; j < o.words.size(); ++j) {
                DWord cur = res.words[i + j]
                          + static_cast<DWord>(words[i]) * o.words[j]
                          + carry;
                res.words[i + j] = static_cast<Word>(cur & 0xFFFFFFFF);
                carry = cur >> 32;
            }
            res.words[i + o.words.size()] += static_cast<Word>(carry);
        }
        res.trim();
        return res;
    }

    BigInt operator<<(unsigned bits) const {
        if (bits == 0) return *this;
        unsigned word_shift = bits / 32;
        unsigned bit_shift  = bits % 32;
        BigInt res;
        res.words.assign(words.size() + word_shift + 1, 0);
        for (size_t i = 0; i < words.size(); ++i) {
            DWord v = static_cast<DWord>(words[i]) << bit_shift;
            res.words[i + word_shift]     |= static_cast<Word>(v & 0xFFFFFFFF);
            res.words[i + word_shift + 1] |= static_cast<Word>(v >> 32);
        }
        res.trim();
        return res;
    }

    BigInt operator>>(unsigned bits) const {
        if (bits == 0) return *this;
        unsigned word_shift = bits / 32;
        unsigned bit_shift  = bits % 32;
        if (word_shift >= words.size()) return BigInt(0);
        BigInt res;
        res.words.assign(words.size() - word_shift, 0);
        for (size_t i = 0; i < res.words.size(); ++i) {
            DWord v = words[i + word_shift] >> bit_shift;
            if (bit_shift && i + word_shift + 1 < words.size())
                v |= static_cast<DWord>(words[i + word_shift + 1]) << (32 - bit_shift);
            res.words[i] = static_cast<Word>(v & 0xFFFFFFFF);
        }
        res.trim();
        return res;
    }

    unsigned bit_length() const {
        if (is_zero()) return 0;
        unsigned bits = 0;
        Word top = words.back();
        while (top) { bits++; top >>= 1; }
        return (static_cast<unsigned>(words.size()) - 1) * 32 + bits;
    }

    unsigned bit_at(unsigned i) const {
        unsigned w = i / 32, b = i % 32;
        if (w >= words.size()) return 0;
        return (words[w] >> b) & 1;
    }

    static void div_mod(const BigInt& num, const BigInt& den, BigInt& q, BigInt& r) {
        q = BigInt(0); r = BigInt(0);
        if (den.is_zero()) throw std::invalid_argument("Division by zero");
        if (num < den) { r = num; return; }

        unsigned n = num.bit_length();
        for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
            r = r << 1;
            if (num.bit_at(static_cast<unsigned>(i))) r.words[0] |= 1;
            if (r >= den) {
                r = r - den;
                // q |= 1 << i
                unsigned w = i / 32, b = i % 32;
                if (q.words.size() <= w) q.words.resize(w + 1, 0);
                q.words[w] |= (1U << b);
            }
        }
        q.trim(); r.trim();
    }

    BigInt operator/(const BigInt& o) const { BigInt q, r; div_mod(*this, o, q, r); return q; }
    BigInt operator%(const BigInt& o) const { BigInt q, r; div_mod(*this, o, q, r); return r; }

    // === ИСПРАВЛЕНО: используется Montgomery-Ladder-подобная схема без ветвления по битам exp ===
    // Это медленнее классического mod_pow, но защищает от SPA-утечек по экспоненте.
    static BigInt mod_pow(BigInt base, BigInt exp, const BigInt& mod) {
        if (mod == BigInt(1)) return BigInt(0);
        base = base % mod;
        BigInt res = BigInt(1);
        unsigned n = exp.bit_length();
        for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
            // R = R^2 mod N
            res = (res * res) % mod;
            // R = R * base^(bit) mod N — но без ветвления:
            // умножим res на base, если бит=1; если бит=0, умножим на 1 (=ничего не делаем)
            // Для постоянного времени используем фиктивное умножение:
            BigInt tmp = (res * base) % mod;
            unsigned bit = exp.bit_at(static_cast<unsigned>(i));
            // constant-time выбор: res = bit ? tmp : res
            // через маску (без if)
            BigInt mask = ct_select(bit, BigInt(1), BigInt(0)); // 1 если bit=1, иначе 0
            // res = res + (tmp - res) * mask  — но нужен BigInt с поддержкой вычитания со знаком.
            // Проще: выполнить умножение всегда, а результат замешать через ct_select.
            res = ct_select(bit, tmp, res);
        }
        return res;
    }

    // constant-time выбор: return bit ? a : b  (bit ∈ {0,1})
    static BigInt ct_select(unsigned bit, const BigInt& a, const BigInt& b) {
        // bit_mask = 0xFFFFFFFF если bit=1, иначе 0
        Word bit_mask = static_cast<Word>(0) - static_cast<Word>(bit);
        BigInt res;
        size_t n = std::max(a.words.size(), b.words.size());
        res.words.assign(n, 0);
        for (size_t i = 0; i < n; ++i) {
            Word aw = (i < a.words.size()) ? a.words[i] : 0;
            Word bw = (i < b.words.size()) ? b.words[i] : 0;
            res.words[i] = (aw & bit_mask) | (bw & ~bit_mask);
        }
        res.trim();
        return res;
    }

    // === ИСПРАВЛЕНО: mod_inverse через итеративный расширенный Евклид ===
    // Используем классический алгоритм с поддержкой отрицательных коэффициентов
    // через представление (t, sign) для модульного сокращения.
    static BigInt mod_inverse(BigInt a, BigInt m) {
        a = a % m;
        if (a.is_zero()) throw std::invalid_argument("mod_inverse: a == 0");
        BigInt old_r = a, r = m;
        BigInt old_s = BigInt(1), s = BigInt(0);
        // Инвариант: old_r = old_s * a (mod m), r = s * a (mod m)
        // Работаем с модульной арифметикой: s всегда в [0, m)
        while (!r.is_zero()) {
            BigInt q = old_r / r;
            BigInt new_r = old_r - q * r; old_r = r; r = new_r;
            // new_s = old_s - q*s mod m  (учитывая знак)
            BigInt qs = (q * s) % m;
            BigInt new_s = (old_s >= qs) ? (old_s - qs) : (old_s + m - qs);
            old_s = s; s = new_s;
        }
        if (old_r != BigInt(1)) throw std::invalid_argument("mod_inverse: not invertible");
        return old_s % m;
    }

    std::vector<uint8_t> to_bytes(size_t len) const {
        std::vector<uint8_t> bytes(len, 0);
        for (size_t i = 0; i < len; ++i) {
            size_t word_idx = i / 4;
            size_t byte_idx = i % 4;
            if (word_idx < words.size())
                bytes[len - 1 - i] = static_cast<uint8_t>((words[word_idx] >> (byte_idx * 8)) & 0xFF);
        }
        return bytes;
    }

    static BigInt from_bytes(const uint8_t* bytes, size_t len) {
        BigInt res = BigInt(0);
        for (size_t i = 0; i < len; ++i)
            res = res * BigInt(256) + BigInt(bytes[i]);
        return res;
    }

    // === ДОБАВЛЕНО: генерация случайного BigInt заданной битовой длины ===
    static BigInt random_bits(unsigned bits, std::mt19937_64& rng) {
        BigInt res = BigInt(0);
        unsigned words = (bits + 31) / 32;
        res.words.assign(words, 0);
        for (unsigned i = 0; i < words; ++i) res.words[i] = static_cast<Word>(rng() & 0xFFFFFFFF);
        // Усечь до bits
        unsigned top_bits = bits % 32;
        if (top_bits) res.words.back() &= (1U << top_bits) - 1;
        // Установить старший бит (чтобы гарантировать точную длину)
        res.words.back() |= (1U << ((bits - 1) % 32));
        // Установить младший бит (чтобы было нечётным)
        res.words[0] |= 1;
        res.trim();
        return res;
    }
};
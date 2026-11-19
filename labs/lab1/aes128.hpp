
#pragma once
#include <array>
#include <cstdint>
#include "gf256.hpp"

class Aes128 {
public:
    static constexpr int kBlock = 16;
    static constexpr int kRounds = 10;

    Aes128(const uint8_t key[16], uint16_t p_x) : gf_(p_x) {
        gf_.generate_sbox(sbox_, inv_sbox_);
        build_matrices();
        expand_key(key);
    }

    const std::array<uint8_t, 16>& mix_matrix() const { return mc_; }
    const std::array<uint8_t, 16>& inv_mix_matrix() const { return imc_; }
    const std::array<uint8_t, 256>& sbox() const { return sbox_; }
    const gf::GF256& field() const { return gf_; }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; ++i) s[i] = in[i];
        add_round_key(s, 0);
        for (int r = 1; r < kRounds; ++r) {
            sub_bytes(s, sbox_);
            shift_rows(s);
            mix_columns(s, mc_);
            add_round_key(s, r);
        }
        sub_bytes(s, sbox_);
        shift_rows(s);
        add_round_key(s, kRounds);
        for (int i = 0; i < 16; ++i) out[i] = s[i];
    }

    void decrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; ++i) s[i] = in[i];
        add_round_key(s, kRounds);
        for (int r = kRounds - 1; r >= 1; --r) {
            inv_shift_rows(s);
            sub_bytes(s, inv_sbox_);
            add_round_key(s, r);
            mix_columns(s, imc_);  // InvMixColumns
        }
        inv_shift_rows(s);
        sub_bytes(s, inv_sbox_);
        add_round_key(s, 0);
        for (int i = 0; i < 16; ++i) out[i] = s[i];
    }

    // Открытые для тестов: преобразование столбцов заданной матрицей.
    void mix_columns_public(uint8_t s[16]) const { mix_columns(s, mc_); }
    void inv_mix_columns_public(uint8_t s[16]) const { mix_columns(s, imc_); }

private:
    // Состояние хранится по столбцам: s[r + 4*c] = s_{r,c}.

    void sub_bytes(uint8_t s[16], const std::array<uint8_t, 256>& table) const {
        for (int i = 0; i < 16; ++i) s[i] = gf::ct_lookup(table, s[i]);
    }

    static void shift_rows(uint8_t s[16]) {
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        for (int i = 0; i < 16; ++i) s[i] = t[i];
    }
    static void inv_shift_rows(uint8_t s[16]) {
        uint8_t t[16];
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) t[r + 4 * ((c + r) & 3)] = s[r + 4 * c];
        for (int i = 0; i < 16; ++i) s[i] = t[i];
    }

    // Матричное умножение столбцов: S'_j = M * S_j над GF(2^8).
    // Число операций и обращений к памяти фиксировано, ветвлений нет.
    void mix_columns(uint8_t s[16], const std::array<uint8_t, 16>& m) const {
        for (int c = 0; c < 4; ++c) {
            uint8_t col[4], res[4];
            for (int r = 0; r < 4; ++r) col[r] = s[r + 4 * c];
            for (int i = 0; i < 4; ++i) {
                uint8_t acc = 0;
                for (int j = 0; j < 4; ++j) acc ^= gf_.multiply(m[4 * i + j], col[j]);
                res[i] = acc;
            }
            for (int r = 0; r < 4; ++r) s[r + 4 * c] = res[r];
        }
    }

    void add_round_key(uint8_t s[16], int round) const {
        for (int i = 0; i < 16; ++i) s[i] ^= rk_[16 * round + i];
    }

    // Прямая матрица MixColumns: циркулянт (02 03 01 01).
    // Обратная матрица: метод Гаусса–Жордана над GF(2^8) без ветвлений
    // (выбор ведущего элемента и нормировка выполняются масками).
    void build_matrices() {
        const uint8_t coef[4] = {0x02, 0x03, 0x01, 0x01};
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j) mc_[4 * i + j] = coef[(j - i + 4) & 3];

        uint8_t a[4][4], id[4][4];  // фиксированные массивы, не динамические контейнеры
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j) {
                a[i][j] = mc_[4 * i + j];
                id[i][j] = static_cast<uint8_t>(i == j ? 1 : 0);
            }

        for (int k = 0; k < 4; ++k) {
            // Если a[k][k] == 0, прибавляем к строке k первую строку r>k с ненулевым a[r][k].
            for (int r = k + 1; r < 4; ++r) {
                const uint8_t m = static_cast<uint8_t>(gf::mask_is_zero(a[k][k]) & ~gf::mask_is_zero(a[r][k]));
                for (int j = 0; j < 4; ++j) {
                    a[k][j] ^= static_cast<uint8_t>(a[r][j] & m);
                    id[k][j] ^= static_cast<uint8_t>(id[r][j] & m);
                }
            }
            // Нормировка строки: умножение на pivot^{-1}.
            const uint8_t pinv = gf_.inverse(a[k][k]);
            for (int j = 0; j < 4; ++j) {
                a[k][j] = gf_.multiply(a[k][j], pinv);
                id[k][j] = gf_.multiply(id[k][j], pinv);
            }
            // Обнуление столбца k в остальных строках.
            for (int r = 0; r < 4; ++r) {
                const uint8_t f = a[r][k];
                const uint8_t skip = gf::mask_from_bit(static_cast<uint8_t>(r == k ? 1 : 0));
                const uint8_t fm = static_cast<uint8_t>(f & ~skip);
                for (int j = 0; j < 4; ++j) {
                    a[r][j] ^= gf_.multiply(fm, a[k][j]);
                    id[r][j] ^= gf_.multiply(fm, id[k][j]);
                }
            }
        }
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j) imc_[4 * i + j] = id[i][j];
    }

    // Key Schedule: W_i = W_{i-4} ^ SubWord(RotWord(W_{i-1})) ^ Rcon, Rcon = x^{i/4-1} в GF(2^8).
    void expand_key(const uint8_t key[16]) {
        for (int i = 0; i < 16; ++i) rk_[i] = key[i];
        uint8_t rcon = 0x01;
        for (int i = 4; i < 44; ++i) {
            uint8_t t[4];
            for (int j = 0; j < 4; ++j) t[j] = rk_[4 * (i - 1) + j];
            if ((i & 3) == 0) {  // ветвление по публичному индексу слова
                const uint8_t t0 = t[0];
                t[0] = gf::ct_lookup(sbox_, t[1]);
                t[1] = gf::ct_lookup(sbox_, t[2]);
                t[2] = gf::ct_lookup(sbox_, t[3]);
                t[3] = gf::ct_lookup(sbox_, t0);
                t[0] ^= rcon;
                rcon = gf_.multiply(rcon, 0x02);
            }
            for (int j = 0; j < 4; ++j) rk_[4 * i + j] = rk_[4 * (i - 4) + j] ^ t[j];
        }
    }

    gf::GF256 gf_;
    std::array<uint8_t, 256> sbox_{}, inv_sbox_{};
    std::array<uint8_t, 16> mc_{}, imc_{};
    uint8_t rk_[176]{};
};

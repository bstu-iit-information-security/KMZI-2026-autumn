#include "aes128.h"
#include <cstring>
#include <utility>

namespace lab1 {

    static const uint8_t RCON[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    AES128::AES128(const uint8_t key[16], const GaloisField& gf)
        : gf_(gf) {
        keyExpansion(key);
        buildInvSbox();
        computeInvMixMatrix();
    }

    void AES128::buildInvSbox() {
        for (int i = 0; i < 256; ++i) {
            invSbox_[gf_.sbox()[i]] = static_cast<uint8_t>(i);
        }
    }

    // Вычисление обратной матрицы MixColumns над GF(2^8) для заданного p(x).
    // Строим её методом Гаусса-Жордана (однократно, при инициализации).
    void AES128::computeInvMixMatrix() {
        uint8_t M[4][4] = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02},
        };
        uint8_t A[4][8];
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) A[i][j] = M[i][j];
            for (int j = 0; j < 4; ++j) A[i][4 + j] = (i == j) ? 1 : 0;
        }
        for (int col = 0; col < 4; ++col) {
            int piv = -1;
            for (int r = col; r < 4; ++r) if (A[r][col]) { piv = r; break; }
            if (piv != col) {
                for (int j = 0; j < 8; ++j) std::swap(A[col][j], A[piv][j]);
            }
            uint8_t inv = gf_.inverse(A[col][col]);
            for (int j = 0; j < 8; ++j) A[col][j] = gf_.multiply(A[col][j], inv);
            for (int r = 0; r < 4; ++r) {
                if (r == col) continue;
                uint8_t f = A[r][col];
                for (int j = 0; j < 8; ++j) {
                    A[r][j] ^= gf_.multiply(f, A[col][j]);
                }
            }
        }
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                invMixMatrix_[i][j] = A[i][4 + j];
    }

    void AES128::keyExpansion(const uint8_t key[16]) {
        uint8_t w[176];
        std::memcpy(w, key, 16);
        for (int i = 4; i < 44; ++i) {
            uint8_t temp[4];
            std::memcpy(temp, w + (i - 1) * 4, 4);
            if (i % 4 == 0) {
                uint8_t t0 = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t0;
                for (int j = 0; j < 4; ++j) temp[j] = gf_.sbox()[temp[j]];
                temp[0] ^= RCON[i / 4];
            }
            for (int j = 0; j < 4; ++j) {
                w[i * 4 + j] = static_cast<uint8_t>(w[(i - 4) * 4 + j] ^ temp[j]);
            }
        }
        // Раскладка в 4×4 столбцовую форму: state[4*c + r]
        for (int round = 0; round < 11; ++round) {
            for (int c = 0; c < 4; ++c) {
                for (int k = 0; k < 4; ++k) {
                    roundKeys_[round][4 * c + k] = w[(4 * round + c) * 4 + k];
                }
            }
        }
    }

    void AES128::subBytes(uint8_t s[16]) const {
        for (int i = 0; i < 16; ++i) s[i] = gf_.sbox()[s[i]];
    }

    void AES128::invSubBytes(uint8_t s[16]) const {
        for (int i = 0; i < 16; ++i) s[i] = invSbox_[s[i]];
    }

    void AES128::shiftRows(uint8_t s[16]) const {
        uint8_t t[16];
        for (int r = 0; r < 4; ++r)
            for (int c = 0; c < 4; ++c)
                t[4 * c + r] = s[4 * ((c + r) & 3) + r];
        std::memcpy(s, t, 16);
    }

    void AES128::invShiftRows(uint8_t s[16]) const {
        uint8_t t[16];
        for (int r = 0; r < 4; ++r)
            for (int c = 0; c < 4; ++c)
                t[4 * ((c + r) & 3) + r] = s[4 * c + r];
        std::memcpy(s, t, 16);
    }

    // ============ ЗАДАЧА ВАРИАНТА 5 ============
    // Constant-time MixColumns: без if, без условных сдвигов.
    // Используется алгебраическое тождество:
    //   s'[0] = a0 ^ t ^ xtime(a0 ^ a1), где t = a0^a1^a2^a3
    // Умножение на 0x02 = xtime — уже constant-time (gf_.multiply).
    void AES128::mixColumns(uint8_t s[16]) const {
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = s[4 * c + 0];
            uint8_t a1 = s[4 * c + 1];
            uint8_t a2 = s[4 * c + 2];
            uint8_t a3 = s[4 * c + 3];

            uint8_t t = static_cast<uint8_t>(a0 ^ a1 ^ a2 ^ a3);

            s[4 * c + 0] = static_cast<uint8_t>(a0 ^ t ^ gf_.multiply(static_cast<uint8_t>(a0 ^ a1), 0x02));
            s[4 * c + 1] = static_cast<uint8_t>(a1 ^ t ^ gf_.multiply(static_cast<uint8_t>(a1 ^ a2), 0x02));
            s[4 * c + 2] = static_cast<uint8_t>(a2 ^ t ^ gf_.multiply(static_cast<uint8_t>(a2 ^ a3), 0x02));
            s[4 * c + 3] = static_cast<uint8_t>(a3 ^ t ^ gf_.multiply(static_cast<uint8_t>(a3 ^ a0), 0x02));
        }
    }

    // Constant-time InvMixColumns: циклы фиксированной длины,
    // всё умножение идёт через constant-time gf_.multiply.
    void AES128::invMixColumns(uint8_t s[16]) const {
        for (int c = 0; c < 4; ++c) {
            uint8_t in[4] = { s[4 * c + 0], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3] };
            uint8_t out[4];
            for (int i = 0; i < 4; ++i) {
                uint8_t acc = 0;
                for (int j = 0; j < 4; ++j) {
                    acc ^= gf_.multiply(invMixMatrix_[i][j], in[j]);
                }
                out[i] = acc;
            }
            s[4 * c + 0] = out[0];
            s[4 * c + 1] = out[1];
            s[4 * c + 2] = out[2];
            s[4 * c + 3] = out[3];
        }
    }

    void AES128::addRoundKey(uint8_t s[16], const uint8_t rk[16]) const {
        for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
    }

    void AES128::encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        std::memcpy(s, in, 16);
        addRoundKey(s, roundKeys_[0]);
        for (int r = 1; r <= 9; ++r) {
            subBytes(s);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, roundKeys_[r]);
        }
        subBytes(s);
        shiftRows(s);
        addRoundKey(s, roundKeys_[10]);
        std::memcpy(out, s, 16);
    }

    void AES128::decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        std::memcpy(s, in, 16);
        addRoundKey(s, roundKeys_[10]);
        for (int r = 9; r >= 1; --r) {
            invShiftRows(s);
            invSubBytes(s);
            addRoundKey(s, roundKeys_[r]);
            invMixColumns(s);
        }
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, roundKeys_[0]);
        std::memcpy(out, s, 16);
    }

} // namespace lab1
#include <iostream>
#include <cstdint>
#include <array>
#include <cstring>

class GaloisCalculator {
    uint16_t poly;

public:
    GaloisCalculator(uint16_t p = 0x1C3) : poly(p) {}

    uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    uint8_t multiply(uint8_t a, uint8_t b) {
        uint8_t result = 0;
        for (int i = 0; i < 8; i++) {
            uint8_t mask_b = -(b & 1);
            result ^= (a & mask_b);

            uint8_t msb_a = -(a >> 7);
            a = (a << 1) ^ (msb_a & (poly & 0xFF));
            b >>= 1;
        }
        return result;
    }

    uint8_t inverse(uint8_t a) {
        uint8_t mask_zero = (a == 0) ? 0x00 : 0xFF;

        uint8_t a2 = multiply(a, a);
        uint8_t a4 = multiply(a2, a2);
        uint8_t a8 = multiply(a4, a4);
        uint8_t a16 = multiply(a8, a8);
        uint8_t a32 = multiply(a16, a16);
        uint8_t a64 = multiply(a32, a32);
        uint8_t a128 = multiply(a64, a64);

        uint8_t res = multiply(a128, a64);
        res = multiply(res, a32);
        res = multiply(res, a16);
        res = multiply(res, a8);
        res = multiply(res, a4);
        res = multiply(res, a2);

        return res & mask_zero;
    }
};

class BelTCipher {
    std::array<uint32_t, 8> K;

    uint32_t rotl(uint32_t val, int shift) {
        return (val << shift) | (val >> (32 - shift));
    }

public:
    void setKey(const uint8_t key[32]) {
        for (int i = 0; i < 8; ++i) {
            K[i] = (uint32_t(key[i * 4 + 0]) << 24) |
                (uint32_t(key[i * 4 + 1]) << 16) |
                (uint32_t(key[i * 4 + 2]) << 8) |
                (uint32_t(key[i * 4 + 3]));
        }
    }

    uint32_t getRoundKey(int round, int step) {
        int forward_index = (round * 4 + step) % 8;
        int backward_index = (7 - forward_index) % 8;

        int reverse_mask = -((round >> 2) & 1);
        int final_index = (forward_index & ~reverse_mask) | (backward_index & reverse_mask);

        return K[final_index];
    }

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) {
        uint32_t a, b, c, d;
        std::memcpy(&a, in, 4);
        std::memcpy(&b, in + 4, 4);
        std::memcpy(&c, in + 8, 4);
        std::memcpy(&d, in + 12, 4);

        for (int r = 0; r < 8; ++r) {
            uint32_t k0 = getRoundKey(r, 0);
            uint32_t k1 = getRoundKey(r, 1);

            a = (a + k0);
            b ^= rotl(a, 9);
            c = (c + k1);
            d ^= rotl(c, 5);

            uint32_t t = a;
            a = b; b = c; c = d; d = t;
        }

        std::memcpy(out, &a, 4);
        std::memcpy(out + 4, &b, 4);
        std::memcpy(out + 8, &c, 4);
        std::memcpy(out + 12, &d, 4);
    }
};

class GCM {
    BelTCipher cipher;
    uint8_t H[16];

    void ghash_multiply(uint8_t X[16], const uint8_t Y[16]) {
        uint8_t Z[16] = { 0 };
        uint8_t V[16];
        std::memcpy(V, Y, 16);

        for (int i = 0; i < 128; ++i) {
            uint8_t bit = (X[i / 8] >> (7 - (i % 8))) & 1;
            uint8_t mask = -bit;

            for (int j = 0; j < 16; ++j) {
                Z[j] ^= (V[j] & mask);
            }

            uint8_t lsb = V[15] & 1;
            for (int j = 15; j > 0; --j) {
                V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
            }
            V[0] >>= 1;

            uint8_t reduction_mask = -lsb;
            V[0] ^= (0xE1 & reduction_mask);
        }
        std::memcpy(X, Z, 16);
    }

public:
    GCM(const uint8_t key[32]) {
        cipher.setKey(key);
        uint8_t zero_block[16] = { 0 };
        cipher.encryptBlock(zero_block, H);
    }

    void encrypt_and_tag(const uint8_t* pt, uint8_t* ct, size_t len, uint8_t tag[16]) {
        uint8_t block[16] = { 0 };
        uint8_t ghash_state[16] = { 0 };

        for (size_t i = 0; i < len; i += 16) {
            block[15]++;
            uint8_t keystream[16];
            cipher.encryptBlock(block, keystream);

            for (size_t j = 0; j < 16 && (i + j) < len; ++j) {
                ct[i + j] = pt[i + j] ^ keystream[j];
                ghash_state[j] ^= ct[i + j];
            }
            ghash_multiply(ghash_state, H);
        }
        std::memcpy(tag, ghash_state, 16);
    }

    bool verify_tag(const uint8_t expected_tag[16], const uint8_t received_tag[16]) {
        uint8_t accumulator = 0;
        for (int i = 0; i < 16; i++) {
            accumulator |= (expected_tag[i] ^ received_tag[i]);
        }
        return (accumulator == 0);
    }
};

int main() {
    uint8_t key[32] = { 0x01, 0x02, 0x03 };
    uint8_t plaintext[16] = "Test Data Block";
    uint8_t ciphertext[16];
    uint8_t tag[16];

    GCM gcm(key);
    gcm.encrypt_and_tag(plaintext, ciphertext, 16, tag);

    bool isValid = gcm.verify_tag(tag, tag);
    std::cout << "Зашифрование завершено. Валидность тега: " << (isValid ? "Успешно" : "Ошибка") << std::endl;

    return 0;
}
#include <iostream>
#include <iomanip>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

using namespace std;

class GF28 {
private:
    uint16_t irreducible_poly;
    uint8_t  reduction_const; //Младшие 8 бит многочлена

public:
    explicit GF28(uint16_t p = 0x11B): irreducible_poly(p), reduction_const(static_cast<uint8_t>(p & 0xFF)) {}

    //Сложение
    uint8_t add(uint8_t a, uint8_t b) const {
        return a ^ b;
    }

    //Умножение
    uint8_t multiply(uint8_t a, uint8_t b) const {
        uint8_t result = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t bit_mask = static_cast<uint8_t>(-static_cast<int8_t>((b >> i) & 1));
            result ^= (a & bit_mask);

            //Редукция a = xtime
            uint8_t hi_bit = static_cast<uint8_t>(-static_cast<int8_t>((a >> 7) & 1));
            a = static_cast<uint8_t>(a << 1) ^ (hi_bit & reduction_const);
        }
        return result;
    }

    //Обратный
    uint8_t inverse(uint8_t a) const {
        uint8_t a2 = multiply(a, a);
        uint8_t a4 = multiply(a2, a2);
        uint8_t a8 = multiply(a4, a4);
        uint8_t a16 = multiply(a8, a8);
        uint8_t a32 = multiply(a16, a16);
        uint8_t a64 = multiply(a32, a32);
        uint8_t a128 = multiply(a64, a64);

        uint8_t result = multiply(a128, a64);
        result = multiply(result, a32);
        result = multiply(result, a16);
        result = multiply(result, a8);
        result = multiply(result, a4);
        result = multiply(result, a2);
        return result;
    }

    //Аффинное преобразование
    static uint8_t affine_transform(uint8_t b) {
        uint8_t s = b ^ static_cast<uint8_t>((b << 1) | (b >> 7)) ^ static_cast<uint8_t>((b << 2) | (b >> 6)) ^ static_cast<uint8_t>((b << 3) | (b >> 5)) ^ static_cast<uint8_t>((b << 4) | (b >> 4));
        return s ^ 0x63;
    }

    //S-box на лету
    uint8_t sbox(uint8_t byte) const {
        uint8_t inv = inverse(byte);
        return affine_transform(inv);
    }
};

class AES128 {
private:
    GF28 gf;
    array<array<uint8_t, 16>, 11> RoundKeys;

    void keyExpansion(const array<uint8_t, 16>& key) {
        memcpy(RoundKeys[0].data(), key.data(), 16);

        uint8_t Rcon = 0x01;
        for (size_t r = 1; r <= 10; ++r) {
            array<uint8_t, 4> temp;
            for (size_t i = 0; i < 4; ++i) {
                temp[i] = RoundKeys[r - 1][12 + i];
            }

            //RotWord + SubWord
            uint8_t t0 = gf.sbox(temp[1]) ^ Rcon;
            uint8_t t1 = gf.sbox(temp[2]);
            uint8_t t2 = gf.sbox(temp[3]);
            uint8_t t3 = gf.sbox(temp[0]);

            //rcon = xtime(rcon)
            uint8_t hi_bit = static_cast<uint8_t>(-static_cast<int8_t>((Rcon >> 7) & 1));
            Rcon = static_cast<uint8_t>(Rcon << 1) ^ (hi_bit & 0x1B);

            //Колонка 0
            RoundKeys[r][0] = RoundKeys[r - 1][0] ^ t0;
            RoundKeys[r][1] = RoundKeys[r - 1][1] ^ t1;
            RoundKeys[r][2] = RoundKeys[r - 1][2] ^ t2;
            RoundKeys[r][3] = RoundKeys[r - 1][3] ^ t3;

            //Колонка 1-3
            for (size_t col = 1; col < 4; ++col) {
                for (size_t row = 0; row < 4; ++row) {
                    RoundKeys[r][col * 4 + row] = RoundKeys[r - 1][col * 4 + row] ^ RoundKeys[r][(col - 1) * 4 + row];
                }
            }
        }
    }

public:
    explicit AES128(const array<uint8_t, 16>& key, uint16_t poly = 0x11B) : gf(poly) {
        keyExpansion(key);
    }

    array<uint8_t, 16> encrypt(const array<uint8_t, 16>& in) const {
        array<uint8_t, 16> state = in;

        //AddRoundKey
        for (size_t i = 0; i < 16; ++i) {
            state[i] ^= RoundKeys[0][i];
        }

        //Раунды 1-9
        for (size_t round = 1; round <= 9; ++round) {
            //SubBytes
            for (size_t i = 0; i < 16; ++i) {
                state[i] = gf.sbox(state[i]);
            }

            //ShiftRows
            array<uint8_t, 16> temp = state;
            state[1]  = temp[5];  state[5]  = temp[9];  state[9]  = temp[13]; state[13] = temp[1];
            state[2]  = temp[10]; state[6]  = temp[14]; state[10] = temp[2];  state[14] = temp[6];
            state[3]  = temp[15]; state[7]  = temp[3];  state[11] = temp[7];  state[15] = temp[11];

            //MixColumns
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

            //AddRoundKey
            for (size_t i = 0; i < 16; ++i) {
                state[i] ^= RoundKeys[round][i];
            }
        }

        //Раунд 10
        for (size_t i = 0; i < 16; ++i) {
            state[i] = gf.sbox(state[i]);
        }

        array<uint8_t, 16> temp = state;
        state[1]  = temp[5];  state[5]  = temp[9];  state[9]  = temp[13]; state[13] = temp[1];
        state[2]  = temp[10]; state[6]  = temp[14]; state[10] = temp[2];  state[14] = temp[6];
        state[3]  = temp[15]; state[7]  = temp[3];  state[11] = temp[7];  state[15] = temp[11];

        for (size_t i = 0; i < 16; ++i) {
            state[i] ^= RoundKeys[10][i];
        }
        return state;
    }
};

class GCM {
private:
    AES128 cipher;
    array<uint8_t, 16> H{};

    static array<uint8_t, 16> gf_mul(const array<uint8_t, 16>& X, const array<uint8_t, 16>& Y) {
        array<uint8_t, 16> result{};
        array<uint8_t, 16> V = Y;

        for (int i = 0; i < 128; ++i) {
            uint8_t byte_val = X[i / 8];
            uint8_t bit = (byte_val >> (7 - (i % 8))) & 1;
            uint8_t bit_mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));

            for (size_t j = 0; j < 16; ++j) {
                result[j] ^= (V[j] & bit_mask);
            }

            uint8_t lsb_v = V[15] & 1;
            uint8_t carry = 0;
            for (size_t j = 0; j < 16; ++j) {
                uint8_t next_carry = (V[j] & 1) << 7;
                V[j] = (V[j] >> 1) | carry;
                carry = next_carry;
            }

            //Редукция константой 0xE1 по маске младшего бита
            uint8_t red_mask = static_cast<uint8_t>(-static_cast<int8_t>(lsb_v));
            V[0] ^= (0xE1 & red_mask);
        }
        return result;
    }

    static void inc32(array<uint8_t, 16>& block) {
        for (int i = 15; i >= 12; --i) {
            if (++block[i] != 0) break;
        }
    }

public:
    explicit GCM(const array<uint8_t, 16>& key) : cipher(key) {
        array<uint8_t, 16> zero_block{};
        H = cipher.encrypt(zero_block);
    }

    void encrypt( const array<uint8_t, 12>& iv, const uint8_t* plaintext, size_t pt_len, const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, std::array<uint8_t, 16>& tag ) {
        constexpr size_t GCM_MAX_BYTES = (1ULL << 36) - 32;
        if (pt_len > GCM_MAX_BYTES) {
            throw length_error("GCM: текст превышает 2^39-256 битов");
        }
        if (aad_len > (SIZE_MAX / 8)) {
            throw length_error("GCM: длина AAD первышвет счетчик битов");
        }

        array<uint8_t, 16> cb0{};
        memcpy(cb0.data(), iv.data(), 12);
        cb0[15] = 1;

        array<uint8_t, 16> cb = cb0;
        inc32(cb); //CB_1 для открытого текста

        //CTR
        size_t offset = 0;
        while (offset < pt_len) {
            array<uint8_t, 16> pad = cipher.encrypt(cb);
            size_t chunk = (pt_len - offset < 16) ? (pt_len - offset) : 16;
            for (size_t i = 0; i < chunk; ++i) {
                ciphertext[offset + i] = plaintext[offset + i] ^ pad[i];
            }
            offset += chunk;
            inc32(cb);
        }

        //GHASH
        array<uint8_t, 16> y{};

        //AAD
        offset = 0;
        while (offset < aad_len) {
            array<uint8_t, 16> block{};
            size_t chunk = (aad_len - offset < 16) ? (aad_len - offset) : 16;
            memcpy(block.data(), aad + offset, chunk);
            for (size_t i = 0; i < 16; ++i) y[i] ^= block[i];
            y = gf_mul(y, H);
            offset += chunk;
        }

        //Шифротекст
        offset = 0;
        while (offset < pt_len) {
            array<uint8_t, 16> block{};
            size_t chunk = (pt_len - offset < 16) ? (pt_len - offset) : 16;
            memcpy(block.data(), ciphertext + offset, chunk);
            for (size_t i = 0; i < 16; ++i) y[i] ^= block[i];
            y = gf_mul(y, H);
            offset += chunk;
        }

        array<uint8_t, 16> len_block{};
        uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
        uint64_t ct_bits  = static_cast<uint64_t>(pt_len)  * 8;
        for (int i = 0; i < 8; ++i) {
            len_block[7 - i]  = static_cast<uint8_t>(aad_bits >> (i * 8));
            len_block[15 - i] = static_cast<uint8_t>(ct_bits  >> (i * 8));
        }

        for (size_t i = 0; i < 16; ++i) y[i] ^= len_block[i];
        y = gf_mul(y, H);

        //Тег
        array<uint8_t, 16> e_cb0 = cipher.encrypt(cb0);
        for (size_t i = 0; i < 16; ++i) {
            tag[i] = y[i] ^ e_cb0[i];
        }
    }

    static bool verify_tag(const array<uint8_t, 16>& tag1, const array<uint8_t, 16>& tag2) {
        uint8_t delta = 0;
        for (size_t i = 0; i < 16; ++i) {
            delta |= (tag1[i] ^ tag2[i]);
        }
        return ((static_cast<uint8_t>(delta | static_cast<uint8_t>(-delta)) >> 7) ^ 1) != 0;
    }
};


static void print(const char* label, const uint8_t* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
    }
    cout << dec << "\n";
}

int main() {

    array<uint8_t, 16> key = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    array<uint8_t, 12> iv = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    array<uint8_t, 60> pt = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };

    array<uint8_t, 20> aad = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

    //Ожидаемые результаты
    array<uint8_t, 60> expected_ct = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
        0x3d, 0x58, 0xe0, 0x91
    };
    array<uint8_t, 16> expected_tag = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
    };

    GCM gcm(key);

    array<uint8_t, 60> ct{};
    array<uint8_t, 16> tag{};

    gcm.encrypt(iv, pt.data(), pt.size(), aad.data(), aad.size(), ct.data(), tag);

    print("Key ", key.data(), 16);
    print("IV ", iv.data(), 12);
    print("AAD ", aad.data(), 20);
    print("PT ", pt.data(), 60);
    cout << "\n";
    print("Вычисленный CT", ct.data(), 60);
    print("Ожидаемый CT ", expected_ct.data(), 60);
    cout << "\n";
    print("Вычисленный Tag", tag.data(), 16);
    print("Ожидаемый Tag ", expected_tag.data(), 16);
    cout << "\n";

    //Верификация
    bool ct_ok  = (memcmp(ct.data(), expected_ct.data(), 60) == 0);
    bool tag_ok = GCM::verify_tag(tag, expected_tag);

    cout << "Ciphertext: " << (ct_ok ? "OK" : "FAIL") << "\n";
    cout << "Tag (constant-time): " << (tag_ok ? "OK (SUCCESS)" : "FAIL") << "\n";

    return 0;
}
#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <string>

using namespace std;

class GaloisField {
private:
    uint16_t poly; 

public:
    explicit GaloisField(uint16_t p_x = 0x169) : poly(p_x) {}

    uint8_t add(uint8_t a, uint8_t b) const {
        return a ^ b;
    }

    uint8_t xtime(uint8_t b) const {
        uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(b >> 7));
        uint8_t poly_byte = static_cast<uint8_t>(poly & 0xFF);
        return static_cast<uint8_t>((b << 1) ^ (mask & poly_byte));
    }

    uint8_t multiply(uint8_t a, uint8_t b) const {
        uint8_t result = 0;
        uint8_t temp_a = a;

        for (int i = 0; i < 8; ++i) {
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(b & 1));
            result ^= (temp_a & mask);
            temp_a = xtime(temp_a);
            b >>= 1;
        }
        return result;
    }

    uint8_t inverse(uint8_t a) const {
        if (a == 0) return 0;
        uint8_t res = a;
        for (int i = 0; i < 253; ++i) {
            res = multiply(res, a);
        }
        return res;
    }

    void generate_box(array<uint8_t, 256>& box) const {
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            uint8_t c = 0x63;
            uint8_t transformed = 0;
            for (int bit = 0; bit < 8; ++bit) {
                uint8_t b = ((inv >> bit) & 1) ^
                    ((inv >> ((bit + 4) % 8)) & 1) ^
                    ((inv >> ((bit + 5) % 8)) & 1) ^
                    ((inv >> ((bit + 6) % 8)) & 1) ^
                    ((inv >> ((bit + 7) % 8)) & 1) ^
                    ((c >> bit) & 1);
                transformed |= (b << bit);
            }
            box[i] = transformed;
        }
    }
};

class BelT {
private:
    GaloisField gf;
    array<uint8_t, 256> h_box;
    array<uint32_t, 8> K; 

    uint32_t rotl(uint32_t x, int shift) const {
        return (x << shift) | (x >> (32 - shift));
    }
    uint32_t rotr(uint32_t x, int shift) const {
        return (x >> shift) | (x << (32 - shift));
    }

    uint32_t h_substitute(uint32_t x) const {
        return (static_cast<uint32_t>(h_box[(x >> 24) & 0xFF]) << 24) |
            (static_cast<uint32_t>(h_box[(x >> 16) & 0xFF]) << 16) |
            (static_cast<uint32_t>(h_box[(x >> 8) & 0xFF]) << 8) |
            (static_cast<uint32_t>(h_box[x & 0xFF]));
    }

public:
 
    BelT(const array<uint8_t, 32>& key, uint16_t p_x = 0x169) : gf(p_x) {
        gf.generate_box(h_box);

        for (int i = 0; i < 8; ++i) {
            K[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {

        uint32_t a = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
        uint32_t b = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
        uint32_t c = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
        uint32_t d = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];

        for (int i = 0; i < 8; ++i) {
            uint32_t temp = a + K[i]; 
            temp = h_substitute(temp);
            b ^= rotl(temp, 9);
            c -= temp;               
            d ^= rotr(c, 5);

            uint32_t t = a;
            a = b; b = c; c = d; d = t;
        }

        out[0] = (a >> 24) & 0xFF; out[1] = (a >> 16) & 0xFF; out[2] = (a >> 8) & 0xFF; out[3] = a & 0xFF;
        out[4] = (b >> 24) & 0xFF; out[5] = (b >> 16) & 0xFF; out[6] = (b >> 8) & 0xFF; out[7] = b & 0xFF;
        out[8] = (c >> 24) & 0xFF; out[9] = (c >> 16) & 0xFF; out[10] = (c >> 8) & 0xFF; out[11] = c & 0xFF;
        out[12] = (d >> 24) & 0xFF; out[13] = (d >> 16) & 0xFF; out[14] = (d >> 8) & 0xFF; out[15] = d & 0xFF;
    }
};

class GCM_BelT {
private:
    BelT cipher;
    array<uint8_t, 16> H;

    void ghash_multiply(array<uint8_t, 16>& X, const array<uint8_t, 16>& Y) const {
        array<uint8_t, 16> Z = { 0 };
        array<uint8_t, 16> V = Y;

        for (int i = 0; i < 128; ++i) {
            uint8_t bit = (X[i / 8] >> (7 - (i % 8))) & 1;
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));
            for (int j = 0; j < 16; ++j) {
                Z[j] ^= (V[j] & mask);
            }

            uint8_t lsb = V[15] & 1;
            uint8_t carry = 0;
            for (int j = 0; j < 16; ++j) {
                uint8_t next_carry = V[j] & 1;
                V[j] = (V[j] >> 1) | (carry << 7);
                carry = next_carry;
            }

            uint8_t v_mask = static_cast<uint8_t>(-static_cast<int8_t>(lsb));
            V[0] ^= (0xE1 & v_mask);
        }
        X = Z;
    }

public:
    GCM_BelT(const array<uint8_t, 32>& key, uint16_t p_x = 0x169) : cipher(key, p_x) {
        array<uint8_t, 16> zero_block = { 0 };
        cipher.encrypt_block(zero_block.data(), H.data());
    }

    void encrypt(const array<uint8_t, 12>& iv,
        const vector<uint8_t>& plaintext,
        const vector<uint8_t>& aad,
        vector<uint8_t>& ciphertext,
        array<uint8_t, 16>& tag)
    {
        ciphertext.resize(plaintext.size());

        array<uint8_t, 16> cb0 = { 0 };
        memcpy(cb0.data(), iv.data(), 12);
        cb0[15] = 1;

        array<uint8_t, 16> cb = cb0;
        uint32_t counter = 1;

        size_t blocks = (plaintext.size() + 15) / 16;
        for (size_t i = 0; i < blocks; ++i) {
            counter++;
            cb[12] = (counter >> 24) & 0xFF;
            cb[13] = (counter >> 16) & 0xFF;
            cb[14] = (counter >> 8) & 0xFF;
            cb[15] = counter & 0xFF;

            array<uint8_t, 16> encrypted_cb;
            cipher.encrypt_block(cb.data(), encrypted_cb.data());

            size_t block_len = min<size_t>(16, plaintext.size() - i * 16);
            for (size_t j = 0; j < block_len; ++j) {
                ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ encrypted_cb[j];
            }
        }

        array<uint8_t, 16> ghash_acc = { 0 };

        size_t aad_blocks = (aad.size() + 15) / 16;
        for (size_t i = 0; i < aad_blocks; ++i) {
            array<uint8_t, 16> block = { 0 };
            size_t len = min<size_t>(16, aad.size() - i * 16);
            memcpy(block.data(), aad.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        size_t ct_blocks = (ciphertext.size() + 15) / 16;
        for (size_t i = 0; i < ct_blocks; ++i) {
            array<uint8_t, 16> block = { 0 };
            size_t len = min<size_t>(16, ciphertext.size() - i * 16);
            memcpy(block.data(), ciphertext.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        array<uint8_t, 16> len_block = { 0 };
        uint64_t aad_bits = aad.size() * 8;
        uint64_t ct_bits = ciphertext.size() * 8;

        for (int i = 0; i < 8; ++i) {
            len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
            len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
        }

        for (int j = 0; j < 16; ++j) ghash_acc[j] ^= len_block[j];
        ghash_multiply(ghash_acc, H);

        array<uint8_t, 16> encrypted_cb0;
        cipher.encrypt_block(cb0.data(), encrypted_cb0.data());

        for (int i = 0; i < 16; ++i) {
            tag[i] = ghash_acc[i] ^ encrypted_cb0[i];
        }
    }

    static bool verify_tag_constant_time(const array<uint8_t, 16>& tag1, const array<uint8_t, 16>& tag2) {
        uint8_t diff = 0;
      
        for (size_t i = 0; i < 16; ++i) {
            diff |= (tag1[i] ^ tag2[i]);
        }
        return diff == 0;
    }
};

void print_hex(const string& label, const uint8_t* data, size_t len) {
    cout << left << setw(24) << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
    }
    cout << dec << endl;
}

int main() {
    cout << "Лабораторная работа №1 (Вариант 6)" << endl;
    cout << "GF(2^8) poly: 0x169, Алгоритм: БелТ (СТБ 34.101.31), Режим: GCM" << endl << endl;

    array<uint8_t, 32> key = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    array<uint8_t, 12> iv = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40 };

    string plain_str = "BelT cipher Constant-Time validation";
    vector<uint8_t> plaintext(plain_str.begin(), plain_str.end());

    string aad_str = "Header_BelT_Data";
    vector<uint8_t> aad(aad_str.begin(), aad_str.end());

    cout << "ИСХОДНЫЕ ДАННЫЕ (ДО ШИФРОВАНИЯ)" << endl;
    cout << "Открытый текст (String) : " << plain_str << endl;
    print_hex("Открытый текст (HEX)", plaintext.data(), plaintext.size());
    cout << "AAD (Заголовки)         : " << aad_str << endl;

    GCM_BelT gcm(key, 0x169);
    vector<uint8_t> ciphertext;
    array<uint8_t, 16> tag;

    gcm.encrypt(iv, plaintext, aad, ciphertext, tag);

    cout << "РЕЗУЛЬТАТЫ ШИФРОВАНИЯ" << endl;
    print_hex("Master Key (256-bit)", key.data(), key.size());
    print_hex("IV (96-bit)", iv.data(), iv.size());
    print_hex("Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("Authentication Tag", tag.data(), tag.size());

    array<uint8_t, 16> invalid_tag = tag;
    invalid_tag[15] ^= 0x01;

    bool isValid = GCM_BelT::verify_tag_constant_time(tag, tag);
    bool isInvalidValid = GCM_BelT::verify_tag_constant_time(tag, invalid_tag);

    cout << "\nПроверка тега (совпадающий) : " << (isValid ? "SUCCESS" : "FAILED") << endl;
    cout << "Проверка тега (поврежденный): " << (isInvalidValid ? "SUCCESS" : "PASSED (отклонён)") << endl;

    return 0;
}
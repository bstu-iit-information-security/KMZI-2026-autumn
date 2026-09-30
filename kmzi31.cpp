#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <algorithm>

using namespace std;

class GaloisField {
private:
    uint16_t poly;
public:
    explicit GaloisField(uint16_t p_x = 0x1C3) : poly(p_x) {}
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
        return res;
    }

    void generate_sbox(array<uint8_t, 256>& sbox) const {
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            uint8_t s = inv;
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
            sbox[i] = transformed;
        }
    }
};

class BelT {
private:
    GaloisField gf;
    array<uint8_t, 256> sbox;
    array<uint32_t, 32> round_keys;
    array<uint32_t, 8> h_box;

    uint32_t rotl(uint32_t x, int n) const {
        return (x << n) | (x >> (32 - n));
    }

    uint32_t rotr(uint32_t x, int n) const {
        return (x >> n) | (x << (32 - n));
    }

    uint32_t sub_word(uint32_t word) const {
        uint32_t result = 0;
        for (int i = 0; i < 4; ++i) {
            uint8_t byte = (word >> (i * 8)) & 0xFF;
            result |= (static_cast<uint32_t>(sbox[byte]) << (i * 8));
        }
        return result;
    }

    void generate_h_box() {
        for (int i = 0; i < 8; ++i) {
            h_box[i] = 0;
            for (int j = 0; j < 4; ++j) {
                uint8_t index = (i * 4 + j) & 0xFF;
                h_box[i] |= (static_cast<uint32_t>(sbox[index]) << (j * 8));
            }
        }
    }

    uint32_t h_function(uint32_t x) const {
        uint32_t result = x;
        for (int i = 0; i < 8; ++i) {
            uint32_t temp = 0;
            for (int j = 0; j < 4; ++j) {
                uint8_t byte = (result >> (j * 8)) & 0xFF;
                temp |= (static_cast<uint32_t>(sbox[byte]) << (j * 8));
            }
            result = temp ^ h_box[i];
        }
        return result;
    }

    uint32_t g_function(uint32_t x, uint32_t key) const {
        uint32_t temp = x ^ key;
        return h_function(temp);
    }

    void key_expansion(const array<uint8_t, 32>& key) {
        for (int i = 0; i < 8; ++i) {
            round_keys[i] = 0;
            for (int j = 0; j < 4; ++j) {
                round_keys[i] |= (static_cast<uint32_t>(key[i * 4 + j]) << (j * 8));
            }
        }

        for (int i = 0; i < 24; ++i) {
            uint32_t temp = round_keys[i + 7];
            uint32_t rotated = rotl(temp, 9);
            uint32_t substituted = sub_word(rotated);
            uint32_t constant = 0;
            uint32_t c_val = 0x01;
            for (int bit = 0; bit < 32; ++bit) {
                uint8_t bit_val = (c_val >> bit) & 1;
                constant |= (static_cast<uint32_t>(bit_val) << bit);
            }
            uint32_t g_result = g_function(substituted, round_keys[i]);
            round_keys[i + 8] = g_result ^ round_keys[i];
        }

        for (int i = 0; i < 16; ++i) {
            uint32_t temp = round_keys[i * 2 + 1];
            round_keys[i * 2 + 1] = round_keys[i * 2];
            round_keys[i * 2] = temp;
        }
    }

    void sub_bytes(array<uint8_t, 16>& state) const {
        for (int i = 0; i < 16; ++i) {
            state[i] = sbox[state[i]];
        }
    }

    void shift_rows(array<uint8_t, 16>& state) const {
        array<uint8_t, 16> temp = state;
        state[0] = temp[0];
        state[1] = temp[5];
        state[2] = temp[10];
        state[3] = temp[15];
        state[4] = temp[4];
        state[5] = temp[9];
        state[6] = temp[14];
        state[7] = temp[3];
        state[8] = temp[8];
        state[9] = temp[13];
        state[10] = temp[2];
        state[11] = temp[7];
        state[12] = temp[12];
        state[13] = temp[1];
        state[14] = temp[6];
        state[15] = temp[11];
    }

    void mix_columns(array<uint8_t, 16>& state) const {
        for (int c = 0; c < 4; ++c) {
            int idx = c * 4;
            uint8_t a0 = state[idx];
            uint8_t a1 = state[idx + 1];
            uint8_t a2 = state[idx + 2];
            uint8_t a3 = state[idx + 3];
            state[idx] = gf.multiply(0x02, a0) ^ gf.multiply(0x03, a1) ^ a2 ^ a3;
            state[idx + 1] = a0 ^ gf.multiply(0x02, a1) ^ gf.multiply(0x03, a2) ^ a3;
            state[idx + 2] = a0 ^ a1 ^ gf.multiply(0x02, a2) ^ gf.multiply(0x03, a3);
            state[idx + 3] = gf.multiply(0x03, a0) ^ a1 ^ a2 ^ gf.multiply(0x02, a3);
        }
    }

    void add_round_key(array<uint8_t, 16>& state, int round) const {
        uint32_t key0 = round_keys[round * 2];
        uint32_t key1 = round_keys[round * 2 + 1];
        for (int i = 0; i < 4; ++i) {
            state[i] ^= (key0 >> (i * 8)) & 0xFF;
            state[i + 4] ^= (key0 >> (i * 8 + 8)) & 0xFF;
            state[i + 8] ^= (key1 >> (i * 8)) & 0xFF;
            state[i + 12] ^= (key1 >> (i * 8 + 8)) & 0xFF;
        }
    }

public:
    BelT(const array<uint8_t, 32>& key, uint16_t p_x = 0x1C3) : gf(p_x) {
        gf.generate_sbox(sbox);
        generate_h_box();
        key_expansion(key);
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const {
        array<uint8_t, 16> state;
        memcpy(state.data(), in, 16);

        for (int round = 0; round < 8; ++round) {
            add_round_key(state, round);
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
        }

        add_round_key(state, 8);
        memcpy(out, state.data(), 16);
    }
};

class GCM_BelT {
private:
    BelT belt;
    array<uint8_t, 16> H;

    void ghash_multiply(array<uint8_t, 16>& X, const array<uint8_t, 16>& Y) const {
        array<uint8_t, 16> Z;
        Z.fill(0);
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
    GCM_BelT(const array<uint8_t, 32>& key, uint16_t p_x = 0x1C3) : belt(key, p_x) {
        array<uint8_t, 16> zero_block;
        zero_block.fill(0);
        belt.encrypt_block(zero_block.data(), H.data());
    }

    void encrypt(const array<uint8_t, 12>& iv,
        const vector<uint8_t>& plaintext,
        const vector<uint8_t>& aad,
        vector<uint8_t>& ciphertext,
        array<uint8_t, 16>& tag) {

        ciphertext.resize(plaintext.size());

        array<uint8_t, 16> cb0;
        cb0.fill(0);
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
            belt.encrypt_block(cb.data(), encrypted_cb.data());

            size_t block_len = min<size_t>(16, plaintext.size() - i * 16);
            for (size_t j = 0; j < block_len; ++j) {
                ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ encrypted_cb[j];
            }
        }

        array<uint8_t, 16> ghash_acc;
        ghash_acc.fill(0);

        size_t aad_blocks = (aad.size() + 15) / 16;
        for (size_t i = 0; i < aad_blocks; ++i) {
            array<uint8_t, 16> block;
            block.fill(0);
            size_t len = min<size_t>(16, aad.size() - i * 16);
            memcpy(block.data(), aad.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        size_t ct_blocks = (ciphertext.size() + 15) / 16;
        for (size_t i = 0; i < ct_blocks; ++i) {
            array<uint8_t, 16> block;
            block.fill(0);
            size_t len = min<size_t>(16, ciphertext.size() - i * 16);
            memcpy(block.data(), ciphertext.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        array<uint8_t, 16> len_block;
        len_block.fill(0);
        uint64_t aad_bits = aad.size() * 8;
        uint64_t ct_bits = ciphertext.size() * 8;

        for (int i = 0; i < 8; ++i) {
            len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
            len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
        }

        for (int j = 0; j < 16; ++j) ghash_acc[j] ^= len_block[j];
        ghash_multiply(ghash_acc, H);

        array<uint8_t, 16> encrypted_cb0;
        belt.encrypt_block(cb0.data(), encrypted_cb0.data());

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
    cout << left << setw(25) << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
    }
    cout << dec << setfill(' ') << endl;
}

int main() {
    array<uint8_t, 32> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    array<uint8_t, 12> iv = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0x10, 0x20, 0x30, 0x40
    };

    string plain_str = "eto text dlya BelT shifrovania s constant time";
    vector<uint8_t> plaintext(plain_str.begin(), plain_str.end());

    string aad_str = "zagolovki dlya BelT";
    vector<uint8_t> aad(aad_str.begin(), aad_str.end());

    cout << "\n=== ORIGINAL DATA ===" << endl;
    cout << "Plaintext (String): " << plain_str << endl;
    print_hex("Plaintext (HEX)", plaintext.data(), plaintext.size());
    cout << "AAD: " << aad_str << endl;

    GCM_BelT gcm(key, 0x1C3);
    vector<uint8_t> ciphertext;
    array<uint8_t, 16> tag;

    gcm.encrypt(iv, plaintext, aad, ciphertext, tag);

    cout << "\n=== ENCRYPTION RESULTS ===" << endl;
    print_hex("Master Key", key.data(), key.size());
    print_hex("IV (96-bit)", iv.data(), iv.size());
    print_hex("Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("Authentication Tag", tag.data(), tag.size());

    array<uint8_t, 16> invalid_tag = tag;
    invalid_tag[15] ^= 0x01;

    bool isValid = GCM_BelT::verify_tag_constant_time(tag, tag);
    bool isInvalidValid = GCM_BelT::verify_tag_constant_time(tag, invalid_tag);

    cout << "\n=== TAG VERIFICATION ===" << endl;
    cout << "Valid tag:   " << (isValid ? "SUCCESS" : "FAILED") << endl;
    cout << "Invalid tag: " << (isInvalidValid ? "SUCCESS" : "PASSED (rejected)") << endl;

    return 0;
}
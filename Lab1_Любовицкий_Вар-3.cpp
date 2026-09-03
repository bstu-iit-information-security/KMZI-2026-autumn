#include <iostream>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>

using namespace std;

class GaloisField
{
private:
    uint16_t poly;
public:
    explicit GaloisField(uint16_t p_x = 0x11D) : poly(p_x) {}

    uint8_t add(uint8_t a, uint8_t b) const
    {
        return a ^ b;
    }

    uint8_t xtime(uint8_t b) const
    {
        uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(b >> 7));
        uint8_t poly_byte = static_cast<uint8_t>(poly & 0xFF);
        return static_cast<uint8_t>((b << 1) ^ (mask & poly_byte));
    }

    uint8_t multiply(uint8_t a, uint8_t b) const
    {
        uint8_t result = 0;
        uint8_t temp_a = a;

        for (int i = 0; i < 8; ++i)
        {
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(b & 1));
            result ^= (temp_a & mask);
            temp_a = xtime(temp_a);
            b >>= 1;
        }
        return result;
    }

    uint8_t inverse(uint8_t a) const
    {
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

    void generate_sbox(array<uint8_t, 256>& sbox) const
    {
        for (int i = 0; i < 256; ++i)
        {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            uint8_t s = inv;
            uint8_t c = 0x63;
            uint8_t transformed = 0;

            for (int bit = 0; bit < 8; ++bit)
            {
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

class AES128
{
private:
    GaloisField gf;
    array<uint8_t, 256> sbox;
    array<uint8_t, 176> round_keys;
    void sub_bytes(array<uint8_t, 16>& state) const
    {
        for (int i = 0; i < 16; ++i)
        {
            state[i] = sbox[state[i]];
        }
    }

    void shift_rows(array<uint8_t, 16>& state) const
    {
        array<uint8_t, 16> temp = state;
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        state[3] = temp[15];
        state[7] = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }

    void mix_columns(array<uint8_t, 16>& state) const
    {
        for (int c = 0; c < 4; ++c)
        {
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

    void add_round_key(array<uint8_t, 16>& state, int round) const
    {
        for (int i = 0; i < 16; ++i)
        {
            state[i] ^= round_keys[round * 16 + i];
        }
    }

    void key_expansion(const array<uint8_t, 16>& key)
    {
        memcpy(round_keys.data(), key.data(), 16);

        uint8_t rcon = 0x01;
        int bytes_generated = 16;

        while (bytes_generated < 176)
        {
            array<uint8_t, 4> temp;
            for (int i = 0; i < 4; ++i)
            {
                temp[i] = round_keys[bytes_generated - 4 + i];
            }

            if (bytes_generated % 16 == 0)
            {
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];

                temp[0] ^= rcon;
                rcon = gf.xtime(rcon);
            }

            for (int i = 0; i < 4; ++i)
            {
                round_keys[bytes_generated] = round_keys[bytes_generated - 16] ^ temp[i];
                bytes_generated++;
            }
        }
    }

public:
    AES128(const array<uint8_t, 16>& key, uint16_t p_x = 0x11D) : gf(p_x)
    {
        gf.generate_sbox(sbox);
        key_expansion(key);
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) const
    {
        array<uint8_t, 16> state;
        memcpy(state.data(), in, 16);

        add_round_key(state, 0);

        for (int round = 1; round < 10; ++round)
        {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }

        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, 10);

        memcpy(out, state.data(), 16);
    }
};

class GCM_AES128
{
private:
    AES128 aes;
    array<uint8_t, 16> H;

    void ghash_multiply(array<uint8_t, 16>& X, const array<uint8_t, 16>& Y) const
    {
        array<uint8_t, 16> Z = { 0 };
        array<uint8_t, 16> V = Y;

        for (int i = 0; i < 128; ++i)
        {
            uint8_t bit = (X[i / 8] >> (7 - (i % 8))) & 1;
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));
            for (int j = 0; j < 16; ++j)
            {
                Z[j] ^= (V[j] & mask);
            }

            uint8_t lsb = V[15] & 1;
            uint8_t carry = 0;
            for (int j = 0; j < 16; ++j)
            {
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
    GCM_AES128(const array<uint8_t, 16>& key, uint16_t p_x = 0x11D) : aes(key, p_x)
    {
        array<uint8_t, 16> zero_block = { 0 };
        aes.encrypt_block(zero_block.data(), H.data());
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
        for (size_t i = 0; i < blocks; ++i)
        {
            counter++;
            cb[12] = (counter >> 24) & 0xFF;
            cb[13] = (counter >> 16) & 0xFF;
            cb[14] = (counter >> 8) & 0xFF;
            cb[15] = counter & 0xFF;

            array<uint8_t, 16> encrypted_cb;
            aes.encrypt_block(cb.data(), encrypted_cb.data());

            size_t block_len = min<size_t>(16, plaintext.size() - i * 16);
            for (size_t j = 0; j < block_len; ++j)
            {
                ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ encrypted_cb[j];
            }
        }

        array<uint8_t, 16> ghash_acc = { 0 };

        size_t aad_blocks = (aad.size() + 15) / 16;
        for (size_t i = 0; i < aad_blocks; ++i)
        {
            array<uint8_t, 16> block = { 0 };
            size_t len = min<size_t>(16, aad.size() - i * 16);
            memcpy(block.data(), aad.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        size_t ct_blocks = (ciphertext.size() + 15) / 16;
        for (size_t i = 0; i < ct_blocks; ++i)
        {
            array<uint8_t, 16> block = { 0 };
            size_t len = min<size_t>(16, ciphertext.size() - i * 16);
            memcpy(block.data(), ciphertext.data() + i * 16, len);

            for (int j = 0; j < 16; ++j) ghash_acc[j] ^= block[j];
            ghash_multiply(ghash_acc, H);
        }

        array<uint8_t, 16> len_block = { 0 };
        uint64_t aad_bits = aad.size() * 8;
        uint64_t ct_bits = ciphertext.size() * 8;

        for (int i = 0; i < 8; ++i)
        {
            len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
            len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;
        }

        for (int j = 0; j < 16; ++j) ghash_acc[j] ^= len_block[j];
        ghash_multiply(ghash_acc, H);

        array<uint8_t, 16> encrypted_cb0;
        aes.encrypt_block(cb0.data(), encrypted_cb0.data());

        for (int i = 0; i < 16; ++i)
        {
            tag[i] = ghash_acc[i] ^ encrypted_cb0[i];
        }
    }

    static bool verify_tag_constant_time(const array<uint8_t, 16>& tag1, const array<uint8_t, 16>& tag2)
    {
        uint8_t diff = 0;
        for (size_t i = 0; i < 16; ++i)
        {
            diff |= (tag1[i] ^ tag2[i]);
        }
        return diff == 0;
    }
};

void print_hex(const string& label, const uint8_t* data, size_t len)
{
    cout << left << setw(20) << label << ": ";
    for (size_t i = 0; i < len; ++i)
    {
        cout << hex << setw(2) << static_cast<int>(data[i]) << " ";
    }
    cout << dec << endl;
}

int main()
{
    array<uint8_t, 16> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    array<uint8_t, 12> iv = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40 };

    string plain_str = "eto text kakoy to tipo shifrovat nado po horoshemu";
    vector<uint8_t> plaintext(plain_str.begin(), plain_str.end());

    string aad_str = "zagolovki";
    vector<uint8_t> aad(aad_str.begin(), aad_str.end());

    cout << "=== ИСХОДНЫЕ ДАННЫЕ (ДО ШИФРОВАНИЯ) ===" << endl;
    cout << "Открытый текст (String): " << plain_str << endl;
    print_hex("Открытый текст (HEX)", plaintext.data(), plaintext.size());
    cout << "AAD (Заголовки):         " << aad_str << endl;

    GCM_AES128 gcm(key, 0x11D);
    vector<uint8_t> ciphertext;
    array<uint8_t, 16> tag;

    gcm.encrypt(iv, plaintext, aad, ciphertext, tag);

    cout << "=== РЕЗУЛЬТАТЫ ШИФРОВАНИЯ ===" << endl;
    print_hex("Master Key", key.data(), key.size());
    print_hex("IV (96-bit)", iv.data(), iv.size());
    print_hex("Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("Authentication Tag", tag.data(), tag.size());

    array<uint8_t, 16> invalid_tag = tag;
    invalid_tag[15] ^= 0x01;

    bool isValid = GCM_AES128::verify_tag_constant_time(tag, tag);
    bool isInvalidValid = GCM_AES128::verify_tag_constant_time(tag, invalid_tag);

    cout << "\nПроверка тега (совпадающий): " << (isValid ? "SUCCESS" : "FAILED") << endl;
    cout << "Проверка тега (поврежденный): " << (isInvalidValid ? "SUCCESS" : "PASSED (отклонён)") << endl;

}

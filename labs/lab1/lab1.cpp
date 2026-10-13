#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>

inline void store_be32(uint8_t* dst, uint32_t v) {
    dst[0] = static_cast<uint8_t>(v >> 24);
    dst[1] = static_cast<uint8_t>(v >> 16);
    dst[2] = static_cast<uint8_t>(v >> 8);
    dst[3] = static_cast<uint8_t>(v);
}

inline void store_be64(uint8_t* dst, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[7 - i] = static_cast<uint8_t>(v >> (i * 8));
    }
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::cout << std::left << std::setw(16) << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << hex[data[i] >> 4] << hex[data[i] & 0x0F] << ' ';
    }
    std::cout << '\n';
}

class GaloisField {
public:
    explicit GaloisField(uint16_t p_x = 0x11D) : poly(p_x) {}

    uint8_t add(uint8_t a, uint8_t b) {
        return a ^ b;
    }

    uint8_t multiply(uint8_t a, uint8_t b) {
        uint8_t res = 0;
        uint8_t p_byte = static_cast<uint8_t>(poly & 0xFF);

        for (int i = 0; i < 8; ++i) {
            uint8_t b_mask = static_cast<uint8_t>(-(b & 1));
            res ^= (a & b_mask);

            uint8_t high_bit_mask = static_cast<uint8_t>(-((a >> 7) & 1));
            a = static_cast<uint8_t>((a << 1) ^ (p_byte & high_bit_mask));
            b >>= 1;
        }
        return res;
    }

    uint8_t inverse(uint8_t a) {
        if (a == 0) return 0;

        uint8_t res = 1;
        uint8_t base = a;
        uint8_t power = 254;

        while (power > 0) {
            if (power & 1) res = multiply(res, base);
            base = multiply(base, base);
            power >>= 1;
        }
        return res;
    }

    std::array<uint8_t, 256> generate_sbox() {
        std::array<uint8_t, 256> sbox{};
        for (int i = 0; i < 256; ++i) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));

            uint8_t b = inv;
            sbox[i] = static_cast<uint8_t>(
                b ^
                ((b << 1) | (b >> 7)) ^
                ((b << 2) | (b >> 6)) ^
                ((b << 3) | (b >> 5)) ^
                ((b << 4) | (b >> 4)) ^
                0x63
            );
        }
        return sbox;
    }

private:
    uint16_t poly;
};

static std::array<uint8_t, 256> sbox_cache;
static bool sbox_ready = false;

static void ensure_sbox() {
    if (!sbox_ready) {
        sbox_cache = GaloisField(0x11D).generate_sbox();
        sbox_ready = true;
    }
}

class AES128_Var3 {
public:
    explicit AES128_Var3(const uint8_t key[16]) {
        ensure_sbox();
        key_expansion(key);
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint8_t state[16];
        std::memcpy(state, in, 16);

        add_round_key(state, &round_keys[0]);

        for (int r = 1; r < 10; ++r) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns_ct(state);
            add_round_key(state, &round_keys[r * 16]);
        }

        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, &round_keys[10 * 16]);

        std::memcpy(out, state, 16);
    }

private:
    uint8_t xtime_ct(uint8_t b) {
        uint8_t mask = static_cast<uint8_t>(-(b >> 7));
        return static_cast<uint8_t>((b << 1) ^ (mask & 0x1D));
    }

    uint8_t mul_02(uint8_t b) { return xtime_ct(b); }
    uint8_t mul_03(uint8_t b) { return static_cast<uint8_t>(xtime_ct(b) ^ b); }

    void key_expansion(const uint8_t key[16]) {
        std::memcpy(round_keys.data(), key, 16);

        uint8_t rcon = 0x01;
        size_t bytes_generated = 16;

        while (bytes_generated < 176) {
            uint8_t t0 = round_keys[bytes_generated - 4];
            uint8_t t1 = round_keys[bytes_generated - 3];
            uint8_t t2 = round_keys[bytes_generated - 2];
            uint8_t t3 = round_keys[bytes_generated - 1];

            if (bytes_generated % 16 == 0) {
                uint8_t t = t0;
                t0 = sbox_cache[t1];
                t1 = sbox_cache[t2];
                t2 = sbox_cache[t3];
                t3 = sbox_cache[t];
                t0 ^= rcon;
                rcon = xtime_ct(rcon);
            }

            round_keys[bytes_generated]     = static_cast<uint8_t>(round_keys[bytes_generated - 16] ^ t0);
            round_keys[bytes_generated + 1] = static_cast<uint8_t>(round_keys[bytes_generated - 15] ^ t1);
            round_keys[bytes_generated + 2] = static_cast<uint8_t>(round_keys[bytes_generated - 14] ^ t2);
            round_keys[bytes_generated + 3] = static_cast<uint8_t>(round_keys[bytes_generated - 13] ^ t3);
            bytes_generated += 4;
        }
    }

    void sub_bytes(uint8_t state[16]) {
        for (int i = 0; i < 16; ++i) state[i] = sbox_cache[state[i]];
    }

    void shift_rows(uint8_t state[16]) {
        uint8_t shift_map[16] = {
             0,  5, 10, 15,
             4,  9, 14,  3,
             8, 13,  2,  7,
            12,  1,  6, 11
        };
        uint8_t tmp[16];
        std::memcpy(tmp, state, 16);
        for (int i = 0; i < 16; ++i) state[i] = tmp[shift_map[i]];
    }

    void mix_columns_ct(uint8_t state[16]) {
        for (int c = 0; c < 4; ++c) {
            int i = c * 4;
            uint8_t s0 = state[i];
            uint8_t s1 = state[i + 1];
            uint8_t s2 = state[i + 2];
            uint8_t s3 = state[i + 3];

            state[i]     = static_cast<uint8_t>(mul_02(s0) ^ mul_03(s1) ^ s2 ^ s3);
            state[i + 1] = static_cast<uint8_t>(s0 ^ mul_02(s1) ^ mul_03(s2) ^ s3);
            state[i + 2] = static_cast<uint8_t>(s0 ^ s1 ^ mul_02(s2) ^ mul_03(s3));
            state[i + 3] = static_cast<uint8_t>(mul_03(s0) ^ s1 ^ s2 ^ mul_02(s3));
        }
    }

    void add_round_key(uint8_t state[16], const uint8_t* rkey) {
        for (int i = 0; i < 16; ++i) state[i] ^= rkey[i];
    }

    std::array<uint8_t, 176> round_keys;
};

class GCMMode {
public:
    explicit GCMMode(const uint8_t key[16]) : cipher(key) {
        uint8_t zero_block[16] = {0};
        cipher.encrypt_block(zero_block, H.data());
    }

    void encrypt(const uint8_t iv[12],
                 const uint8_t* plaintext, size_t pt_len,
                 const uint8_t* aad,       size_t aad_len,
                 uint8_t* ciphertext, uint8_t tag[16]) {
        uint8_t cb0[16] = {0};
        std::memcpy(cb0, iv, 12);
        store_be32(cb0 + 12, 1);

        uint8_t ek_cb0[16];
        cipher.encrypt_block(cb0, ek_cb0);

        uint32_t counter = 2;
        size_t blocks = (pt_len + 15) / 16;
        for (size_t i = 0; i < blocks; ++i) {
            uint8_t cb[16] = {0};
            std::memcpy(cb, iv, 12);
            store_be32(cb + 12, counter++);

            uint8_t gamma[16];
            cipher.encrypt_block(cb, gamma);

            size_t remaining = pt_len - i * 16;
            size_t chunk = (remaining < 16) ? remaining : 16;
            for (size_t j = 0; j < chunk; ++j) {
                ciphertext[i * 16 + j] = static_cast<uint8_t>(plaintext[i * 16 + j] ^ gamma[j]);
            }
        }

        uint8_t ghash_out[16];
        ghash(aad, aad_len, ciphertext, pt_len, ghash_out);

        for (int i = 0; i < 16; ++i) {
            tag[i] = static_cast<uint8_t>(ghash_out[i] ^ ek_cb0[i]);
        }
    }

    static bool verify_tag_constant_time(const uint8_t tag1[16], const uint8_t tag2[16]) {
        uint8_t diff = 0;
        for (int i = 0; i < 16; ++i) {
            diff |= static_cast<uint8_t>(tag1[i] ^ tag2[i]);
        }
        return diff == 0;
    }

private:
    void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t res[16]) {
        uint8_t z[16] = {0};
        uint8_t v[16];
        std::memcpy(v, y, 16);

        for (int i = 0; i < 128; ++i) {
            uint8_t mask = static_cast<uint8_t>(-((x[i / 8] >> (7 - (i % 8))) & 1));
            for (int j = 0; j < 16; ++j) z[j] ^= (v[j] & mask);

            uint8_t lsb = v[15] & 1;
            uint8_t carry = 0;
            for (int j = 0; j < 16; ++j) {
                uint8_t next_carry = v[j] & 1;
                v[j] = static_cast<uint8_t>((v[j] >> 1) | (carry << 7));
                carry = next_carry;
            }

            uint8_t red_mask = static_cast<uint8_t>(-lsb);
            v[0] ^= (0xE1 & red_mask);
        }
        std::memcpy(res, z, 16);
    }

    void ghash(const uint8_t* aad, size_t aad_len,
               const uint8_t* cipher, size_t cipher_len,
               uint8_t out_tag[16]) {
        uint8_t y[16] = {0};

        auto process_data = [&](const uint8_t* data, size_t len) {
            size_t blocks = (len + 15) / 16;
            for (size_t i = 0; i < blocks; ++i) {
                uint8_t block[16] = {0};
                size_t remaining = len - i * 16;
                size_t chunk = (remaining < 16) ? remaining : 16;
                std::memcpy(block, data + i * 16, chunk);

                for (int j = 0; j < 16; ++j) y[j] ^= block[j];

                uint8_t tmp[16];
                gf128_mul(y, H.data(), tmp);
                std::memcpy(y, tmp, 16);
            }
        };

        if (aad_len > 0)    process_data(aad, aad_len);
        if (cipher_len > 0) process_data(cipher, cipher_len);

        uint8_t len_block[16] = {0};
        store_be64(len_block,     static_cast<uint64_t>(aad_len) * 8);
        store_be64(len_block + 8, static_cast<uint64_t>(cipher_len) * 8);

        for (int j = 0; j < 16; ++j) y[j] ^= len_block[j];
        gf128_mul(y, H.data(), out_tag);
    }

    AES128_Var3 cipher;
    std::array<uint8_t, 16> H;
};

int main() {
    uint8_t key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    uint8_t iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
        0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };

    const char* pt_str  = "AES-128 GCM Mode Constant-Time Test Message";
    const char* aad_str = "Additional Authenticated Data";
    size_t pt_len  = std::strlen(pt_str);
    size_t aad_len = std::strlen(aad_str);

    uint8_t plaintext[64]  = {0};
    uint8_t aad[64]        = {0};
    uint8_t ciphertext[64] = {0};
    uint8_t tag[16];

    std::memcpy(plaintext, pt_str,  pt_len);
    std::memcpy(aad,       aad_str, aad_len);

    GCMMode gcm(key);
    gcm.encrypt(iv, plaintext, pt_len,
                aad, aad_len,
                ciphertext, tag);


    print_hex("Plaintext",  plaintext,  pt_len);
    print_hex("AAD",        aad,        aad_len);
    print_hex("Ciphertext", ciphertext, pt_len);
    print_hex("Tag",        tag, 16);
    std::cout << '\n';

    uint8_t corrupted_tag[16];
    std::memcpy(corrupted_tag, tag, 16);
    corrupted_tag[15] ^= 0x01; 

    const bool ok_original  = GCMMode::verify_tag_constant_time(tag, tag);
    const bool ok_corrupted = GCMMode::verify_tag_constant_time(tag, corrupted_tag);

    std::cout << "\nTag check (original) : " << (ok_original  ? "PASS" : "FAIL") << "\n";
    std::cout << "Tag check (corrupted): " << (!ok_corrupted ? "REJECTED (OK)" : "FAIL") << "\n";

    return 0;
}
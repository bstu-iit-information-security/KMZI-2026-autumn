#include <iostream>
#include <cstdint>
#include <iomanip>


class GaloisField {
private:
    uint16_t poly_;
    uint8_t sbox_[256];

public:
    explicit GaloisField(uint16_t p) : poly_(p) {
        generateSBox();
    }

    inline uint8_t add(uint8_t a, uint8_t b) const {
        return a ^ b;
    }

    uint8_t multiply(uint8_t a, uint8_t b) const {
        uint8_t res = 0;
        uint8_t p_byte = poly_ & 0xFF;

        for (int i = 0; i < 8; i++) {
            uint8_t mask_b = -(b & 1);
            res ^= (a & mask_b);

            uint8_t mask_a = -((a >> 7) & 1);
            a = (a << 1) ^ (mask_a & p_byte);

            b >>= 1;
        }
        return res;
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

    const uint8_t* getSBox() const {
        return sbox_;
    }

private:
    void generateSBox() {
        for (int i = 0; i < 256; i++) {
            uint8_t inv = inverse(static_cast<uint8_t>(i));
            uint8_t affine = 0;
            for (int bit = 0; bit < 8; bit++) {
                uint8_t b_val = ((inv >> bit) & 1) ^
                    ((inv >> ((bit + 4) % 8)) & 1) ^
                    ((inv >> ((bit + 5) % 8)) & 1) ^
                    ((inv >> ((bit + 6) % 8)) & 1) ^
                    ((inv >> ((bit + 7) % 8)) & 1) ^
                    ((0x63 >> bit) & 1);
                affine |= (b_val << bit);
            }
            sbox_[i] = affine;
        }
    }
};

class AES128 {
private:
    GaloisField gf_;
    uint8_t roundKeys_[176];

    void expandKey(const uint8_t* key) {
        for (int i = 0; i < 16; i++) {
            roundKeys_[i] = key[i];
        }

        uint8_t rcon = 0x01;
        const uint8_t* sbox = gf_.getSBox();

        for (int i = 16; i < 176; i += 4) {
            uint8_t temp[4] = { roundKeys_[i - 4], roundKeys_[i - 3], roundKeys_[i - 2], roundKeys_[i - 1] };

            if (i % 16 == 0) {
                uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                temp[0] = sbox[temp[0]]; temp[1] = sbox[temp[1]]; temp[2] = sbox[temp[2]]; temp[3] = sbox[temp[3]];
                temp[0] ^= rcon;
                rcon = gf_.multiply(rcon, 0x02);
            }
            roundKeys_[i + 0] = roundKeys_[i - 16] ^ temp[0];
            roundKeys_[i + 1] = roundKeys_[i - 15] ^ temp[1];
            roundKeys_[i + 2] = roundKeys_[i - 14] ^ temp[2];
            roundKeys_[i + 3] = roundKeys_[i - 13] ^ temp[3];
        }
    }

    void addRoundKey(uint8_t* state, const uint8_t* rk) const {
        for (int i = 0; i < 16; i++) state[i] ^= rk[i];
    }

    void subBytes(uint8_t* state) const {
        const uint8_t* sbox = gf_.getSBox();
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
    }

    void shiftRows(uint8_t* state) const {
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;

        temp = state[2]; state[2] = state[10]; state[10] = temp;

        temp = state[6]; state[6] = state[14]; state[14] = temp;

        temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
    }

    void mixColumns(uint8_t* state) const {
        uint8_t next_st[16];
        for (int c = 0; c < 4; c++) {
            uint8_t s0 = state[c * 4 + 0], s1 = state[c * 4 + 1];
            uint8_t s2 = state[c * 4 + 2], s3 = state[c * 4 + 3];

            uint8_t m2_s0 = gf_.multiply(0x02, s0), m3_s0 = gf_.add(m2_s0, s0);
            uint8_t m2_s1 = gf_.multiply(0x02, s1), m3_s1 = gf_.add(m2_s1, s1);
            uint8_t m2_s2 = gf_.multiply(0x02, s2), m3_s2 = gf_.add(m2_s2, s2);
            uint8_t m2_s3 = gf_.multiply(0x02, s3), m3_s3 = gf_.add(m2_s3, s3);

            next_st[c * 4 + 0] = m2_s0 ^ m3_s1 ^ s2 ^ s3;
            next_st[c * 4 + 1] = s0 ^ m2_s1 ^ m3_s2 ^ s3;
            next_st[c * 4 + 2] = s0 ^ s1 ^ m2_s2 ^ m3_s3;
            next_st[c * 4 + 3] = m3_s0 ^ s1 ^ s2 ^ m2_s3;
        }
        for (int i = 0; i < 16; i++) {
            state[i] = next_st[i];
        }
    }

public:
    explicit AES128(const uint8_t* key, uint16_t poly = 0x1F5) : gf_(poly) {
        expandKey(key);
    }

    void encryptBlock(uint8_t* state) const {
        addRoundKey(state, &roundKeys_[0]);
        for (int r = 1; r < 10; r++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, &roundKeys_[r * 16]);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, &roundKeys_[10 * 16]);
    }
};

class GCM {
private:
    AES128 cipher_;
    uint8_t H_[16];

    static uint64_t getU64BE(const uint8_t* b) {
        uint64_t res = 0;
        for (int i = 0; i < 8; i++) res = (res << 8) | b[i];
        return res;
    }

    static void putU64BE(uint8_t* b, uint64_t v) {
        for (int i = 7; i >= 0; i--) { b[i] = v & 0xFF; v >>= 8; }
    }

    void multiplyGF128_SWAR(const uint8_t* x, const uint8_t* y, uint8_t* out) const {
        uint64_t R = 0xE100000000000000ULL;
        uint64_t Z0 = 0, Z1 = 0;
        uint64_t V0 = getU64BE(y);
        uint64_t V1 = getU64BE(y + 8);
        uint64_t X0 = getU64BE(x);
        uint64_t X1 = getU64BE(x + 8);

        for (int i = 0; i < 128; i++) {
            uint64_t use_X1 = (i >> 6);
            uint64_t use_X0 = 1 ^ use_X1;
            uint64_t shift = 63 - (i & 63);

            uint64_t bit = ((X0 * use_X0 + X1 * use_X1) >> shift) & 1;
            uint64_t mask = -(int64_t)bit;
            Z0 ^= (V0 & mask);
            Z1 ^= (V1 & mask);

            uint64_t v_lsb = V1 & 1;
            uint64_t v_mask = -(int64_t)v_lsb;

            V1 = (V1 >> 1) | (V0 << 63);
            V0 = (V0 >> 1) ^ (R & v_mask);
        }
        putU64BE(out, Z0);
        putU64BE(out + 8, Z1);
    }

    void ghash(uint8_t* Y, const uint8_t* data, size_t len) const {
        size_t blocks = len / 16;
        for (size_t i = 0; i < blocks; i++) {
            for (int j = 0; j < 16; j++) Y[j] ^= data[i * 16 + j];
            multiplyGF128_SWAR(Y, H_, Y);
        }
        if (len % 16 != 0) {
            for (size_t j = 0; j < len % 16; j++) Y[j] ^= data[blocks * 16 + j];
            multiplyGF128_SWAR(Y, H_, Y);
        }
    }

    void incrementCounter(uint8_t* cb) const {
        for (int i = 15; i >= 12; i--) {
            cb[i]++;
            if (cb[i] != 0) break;
        }
    }

public:
    explicit GCM(const uint8_t* key) : cipher_(key, 0x11D) {
        for (int i = 0; i < 16; i++) H_[i] = 0;
        cipher_.encryptBlock(H_);
    }

    void encrypt_and_authenticate(
        const uint8_t* iv, size_t iv_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ptxt, size_t ptxt_len,
        uint8_t* ctxt,
        uint8_t* tag_out) const
    {
        uint8_t J0[16] = { 0 };
        if (iv_len == 12) {
            for (size_t i = 0; i < 12; i++) J0[i] = iv[i];
            J0[15] = 1;
        } else {
            ghash(J0, iv, iv_len);
            uint8_t iv_len_block[16] = { 0 };
            putU64BE(iv_len_block + 8, static_cast<uint64_t>(iv_len) * 8);
            ghash(J0, iv_len_block, 16);
        }

        uint8_t CB[16];
        for (int i = 0; i < 16; i++) CB[i] = J0[i];
        for (size_t offset = 0; offset < ptxt_len; offset += 16) {
            incrementCounter(CB);
            uint8_t e_k[16];
            for (int i = 0; i < 16; i++) e_k[i] = CB[i];

            cipher_.encryptBlock(e_k);

            size_t block_size = (ptxt_len - offset < 16) ? (ptxt_len - offset) : 16;
            for (size_t i = 0; i < block_size; i++) {
                ctxt[offset + i] = ptxt[offset + i] ^ e_k[i];
            }
        }

        uint8_t Y[16] = { 0 };
        ghash(Y, aad, aad_len);
        ghash(Y, ctxt, ptxt_len);

        uint8_t len_block[16] = { 0 };
        putU64BE(len_block, static_cast<uint64_t>(aad_len * 8));
        putU64BE(len_block + 8, static_cast<uint64_t>(ptxt_len * 8));
        ghash(Y, len_block, 16);

        cipher_.encryptBlock(J0);
        for (int i = 0; i < 16; i++) {
            tag_out[i] = Y[i] ^ J0[i];
        }
    }

    static bool constantTimeVerifyTag(const uint8_t* tag1, const uint8_t* tag2) {
        uint8_t accumulator = 0;
        for (int i = 0; i < 16; i++) {
            accumulator |= (tag1[i] ^ tag2[i]);
        }
        return (accumulator == 0);
    }
};

void printHex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n";
}


int main() {
    std::cout << "Cypher: AES-128 | Polinome: 0x11D | Optimisation: MixColumns without branches (xtime)\n\n";

    GaloisField gf(0x11D);
    std::cout << "[*] GF(2^8) Zero element inversion: 0x"
        << std::hex << std::setw(2) << std::setfill('0')
        << (int)gf.inverse(0x00) << std::dec << " (expecting 0x00)\n\n";

    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    uint8_t iv[12] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B };
    uint8_t aad[8] = { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 };
    uint8_t ptxt[20] = {  'V', 'A', 'B', 'I', ' S', 'C', 'H', 'V', 'I', 'C', 'H'};

    uint8_t ctxt[20] = { 0 };
    uint8_t tag[16] = { 0 };

    printHex("Key ", key, 16);
    printHex("Vector (IV)", iv, 12);
    printHex("Auxiliary data (AAD) ", aad, 8);
    printHex("Open text    ", ptxt, 20);
    std::cout << "-------------------------------------------\n";

    GCM gcm(key);
    gcm.encrypt_and_authenticate(iv, 12, aad, 8, ptxt, 20, ctxt, tag);

    printHex("Cypher-text (C)    ", ctxt, 20);
    printHex("Tag        ", tag, 16);

    uint8_t received_tag[16];
    for (int i = 0; i < 16; i++) received_tag[i] = tag[i];

    bool isValid = GCM::constantTimeVerifyTag(tag, received_tag);
    std::cout << "[*] Correct tag test:   " << (isValid ? "SUCCESS" : "ERROR") << "\n";

    received_tag[0] ^= 0x01;
    bool isValidBad = GCM::constantTimeVerifyTag(tag, received_tag);
    std::cout << "[*] Damaged tag test: " << (isValidBad ? "SUCCESS" : "DENIED") << "\n";

    return 0;
}
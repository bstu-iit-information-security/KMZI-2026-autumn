#include "gcm.h"

GCM::GCM(const AES128& cipher) : cipher_(cipher) {
    uint8_t zero[16] = { 0 };
    cipher_.encryptBlock(zero, h_);
}

void GCM::gf128Multiply(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) const {
    uint8_t v[16];
    for (int i = 0; i < 16; ++i) {
        v[i] = y[i];
    }
    uint8_t z[16] = { 0 };

    for (int i = 0; i < 128; ++i) {
        int byteIndex = i / 8;
        int bitIndex = 7 - (i % 8);
        uint8_t bit = static_cast<uint8_t>((x[byteIndex] >> bitIndex) & 1);
        uint8_t mask = static_cast<uint8_t>(static_cast<uint8_t>(0) - bit);

        for (int j = 0; j < 16; ++j) {
            z[j] = static_cast<uint8_t>(z[j] ^ (mask & v[j]));
        }

        uint8_t lsb = static_cast<uint8_t>(v[15] & 1);
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = static_cast<uint8_t>(v[0] >> 1);

        uint8_t lsbMask = static_cast<uint8_t>(static_cast<uint8_t>(0) - lsb);
        v[0] = static_cast<uint8_t>(v[0] ^ (lsbMask & 0xE1));
    }

    for (int i = 0; i < 16; ++i) {
        result[i] = z[i];
    }
}

void GCM::ghash(const uint8_t* aad, size_t aadLen, const uint8_t* data, size_t dataLen, uint8_t result[16]) const {
    uint8_t y[16] = { 0 };

    size_t aadBlocks = (aadLen + 15) / 16;
    for (size_t b = 0; b < aadBlocks; ++b) {
        uint8_t block[16] = { 0 };
        size_t offset = b * 16;
        size_t remaining = aadLen - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            block[i] = aad[offset + i];
        }
        uint8_t xored[16];
        for (int i = 0; i < 16; ++i) {
            xored[i] = static_cast<uint8_t>(y[i] ^ block[i]);
        }
        gf128Multiply(xored, h_, y);
    }

    size_t dataBlocks = (dataLen + 15) / 16;
    for (size_t b = 0; b < dataBlocks; ++b) {
        uint8_t block[16] = { 0 };
        size_t offset = b * 16;
        size_t remaining = dataLen - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            block[i] = data[offset + i];
        }
        uint8_t xored[16];
        for (int i = 0; i < 16; ++i) {
            xored[i] = static_cast<uint8_t>(y[i] ^ block[i]);
        }
        gf128Multiply(xored, h_, y);
    }

    uint8_t lengthBlock[16] = { 0 };
    uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
    uint64_t dataBits = static_cast<uint64_t>(dataLen) * 8;
    for (int i = 0; i < 8; ++i) {
        lengthBlock[7 - i] = static_cast<uint8_t>((aadBits >> (8 * i)) & 0xFF);
        lengthBlock[15 - i] = static_cast<uint8_t>((dataBits >> (8 * i)) & 0xFF);
    }
    uint8_t xored[16];
    for (int i = 0; i < 16; ++i) {
        xored[i] = static_cast<uint8_t>(y[i] ^ lengthBlock[i]);
    }
    gf128Multiply(xored, h_, y);

    for (int i = 0; i < 16; ++i) {
        result[i] = y[i];
    }
}

void GCM::computeJ0(const uint8_t iv[12], uint8_t j0[16]) const {
    for (int i = 0; i < 12; ++i) {
        j0[i] = iv[i];
    }
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;
}

void GCM::incrementCounter(uint8_t block[16]) const {
    for (int i = 15; i >= 12; --i) {
        block[i] = static_cast<uint8_t>(block[i] + 1);
        if (block[i] != 0) {
            break;
        }
    }
}

void GCM::ctrProcess(const uint8_t j0[16], const uint8_t* input, size_t len, uint8_t* output) const {
    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) {
        counter[i] = j0[i];
    }
    incrementCounter(counter);

    size_t blocks = (len + 15) / 16;
    for (size_t b = 0; b < blocks; ++b) {
        uint8_t keystream[16];
        cipher_.encryptBlock(counter, keystream);

        size_t offset = b * 16;
        size_t remaining = len - offset;
        size_t chunk = remaining < 16 ? remaining : 16;
        for (size_t i = 0; i < chunk; ++i) {
            output[offset + i] = static_cast<uint8_t>(input[offset + i] ^ keystream[i]);
        }

        incrementCounter(counter);
    }
}

bool GCM::constantTimeEqual(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

void GCM::encrypt(const uint8_t iv[12],
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* plaintext, size_t ptLen,
                   uint8_t* ciphertext,
                   uint8_t tag[16]) const {
    uint8_t j0[16];
    computeJ0(iv, j0);

    ctrProcess(j0, plaintext, ptLen, ciphertext);

    uint8_t s[16];
    ghash(aad, aadLen, ciphertext, ptLen, s);

    uint8_t ek0[16];
    cipher_.encryptBlock(j0, ek0);

    for (int i = 0; i < 16; ++i) {
        tag[i] = static_cast<uint8_t>(s[i] ^ ek0[i]);
    }
}

bool GCM::decrypt(const uint8_t iv[12],
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* ciphertext, size_t ctLen,
                   const uint8_t tag[16],
                   uint8_t* plaintext) const {
    uint8_t j0[16];
    computeJ0(iv, j0);

    uint8_t s[16];
    ghash(aad, aadLen, ciphertext, ctLen, s);

    uint8_t ek0[16];
    cipher_.encryptBlock(j0, ek0);

    uint8_t computedTag[16];
    for (int i = 0; i < 16; ++i) {
        computedTag[i] = static_cast<uint8_t>(s[i] ^ ek0[i]);
    }

    bool valid = constantTimeEqual(computedTag, tag);

    ctrProcess(j0, ciphertext, ctLen, plaintext);

    return valid;
}

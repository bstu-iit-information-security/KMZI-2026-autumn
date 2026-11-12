#include <cstddef>
#include <cstdint>

namespace belt {
void encryptBlock(const uint8_t input[16], const uint8_t key[32], uint8_t output[16]);
}

namespace gcm {

static void increment32(uint8_t counter[16]) {
    for (int i = 15; i >= 12; --i) {
        ++counter[i];
        if (counter[i] != 0) {
            break;
        }
    }
}

static void multiplyGF128(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) {
    uint8_t z[16]{};
    uint8_t v[16];

    for (int i = 0; i < 16; ++i) {
        v[i] = y[i];
    }

    for (int bitIndex = 0; bitIndex < 128; ++bitIndex) {
        const uint8_t bit = static_cast<uint8_t>((x[bitIndex / 8] >> (7 - (bitIndex % 8))) & 1u);
        const uint8_t bitMask = static_cast<uint8_t>(0u - bit);

        for (int i = 0; i < 16; ++i) {
            z[i] ^= static_cast<uint8_t>(v[i] & bitMask);
        }

        const uint8_t leastBit = static_cast<uint8_t>(v[15] & 1u);
        uint8_t carry = 0;

        for (int i = 0; i < 16; ++i) {
            const uint8_t nextCarry = static_cast<uint8_t>(v[i] & 1u);
            v[i] = static_cast<uint8_t>((v[i] >> 1) | (carry << 7));
            carry = nextCarry;
        }

        const uint8_t reductionMask = static_cast<uint8_t>(0u - leastBit);
        v[0] ^= static_cast<uint8_t>(0xE1u & reductionMask);
    }

    for (int i = 0; i < 16; ++i) {
        result[i] = z[i];
    }
}

static void ghashUpdate(uint8_t state[16], const uint8_t* data, std::size_t length, const uint8_t h[16]) {
    while (length > 0) {
        uint8_t block[16]{};
        const std::size_t blockLength = length < 16 ? length : 16;

        for (std::size_t i = 0; i < blockLength; ++i) {
            block[i] = data[i];
        }

        for (int i = 0; i < 16; ++i) {
            state[i] ^= block[i];
        }

        uint8_t product[16];
        multiplyGF128(state, h, product);
        for (int i = 0; i < 16; ++i) {
            state[i] = product[i];
        }

        data += blockLength;
        length -= blockLength;
    }
}

static void ghash(const uint8_t h[16],
                  const uint8_t* aad, std::size_t aadLength,
                  const uint8_t* ciphertext, std::size_t ciphertextLength,
                  uint8_t result[16]) {
    uint8_t state[16]{};

    ghashUpdate(state, aad, aadLength, h);
    ghashUpdate(state, ciphertext, ciphertextLength, h);

    uint8_t lengthBlock[16]{};
    const uint64_t aadBits = static_cast<uint64_t>(aadLength) * 8u;
    const uint64_t ciphertextBits = static_cast<uint64_t>(ciphertextLength) * 8u;

    for (int i = 0; i < 8; ++i) {
        lengthBlock[7 - i] = static_cast<uint8_t>(aadBits >> (8 * i));
        lengthBlock[15 - i] = static_cast<uint8_t>(ciphertextBits >> (8 * i));
    }

    for (int i = 0; i < 16; ++i) {
        state[i] ^= lengthBlock[i];
    }

    multiplyGF128(state, h, result);
}

void encrypt(const uint8_t* plaintext, std::size_t plaintextLength,
             const uint8_t* aad, std::size_t aadLength,
             const uint8_t key[32], const uint8_t iv[12],
             uint8_t* ciphertext, uint8_t tag[16]) {
    uint8_t zeroBlock[16]{};
    uint8_t h[16];
    belt::encryptBlock(zeroBlock, key, h);

    uint8_t j0[16]{};
    for (int i = 0; i < 12; ++i) {
        j0[i] = iv[i];
    }
    j0[15] = 1;

    uint8_t counter[16];
    for (int i = 0; i < 16; ++i) {
        counter[i] = j0[i];
    }

    std::size_t offset = 0;
    while (offset < plaintextLength) {
        increment32(counter);

        uint8_t gamma[16];
        belt::encryptBlock(counter, key, gamma);

        const std::size_t blockLength = (plaintextLength - offset < 16)
                                      ? plaintextLength - offset
                                      : 16;

        for (std::size_t i = 0; i < blockLength; ++i) {
            ciphertext[offset + i] = static_cast<uint8_t>(plaintext[offset + i] ^ gamma[i]);
        }

        offset += blockLength;
    }

    uint8_t hash[16];
    ghash(h, aad, aadLength, ciphertext, plaintextLength, hash);

    uint8_t encryptedJ0[16];
    belt::encryptBlock(j0, key, encryptedJ0);

    for (int i = 0; i < 16; ++i) {
        tag[i] = static_cast<uint8_t>(encryptedJ0[i] ^ hash[i]);
    }
}

bool constantTimeTagEqual(const uint8_t expected[16], const uint8_t received[16]) {
    uint8_t difference = 0;

    for (int i = 0; i < 16; ++i) {
        difference |= static_cast<uint8_t>(expected[i] ^ received[i]);
    }

    return difference == 0;
}

}

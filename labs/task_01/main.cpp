#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>

namespace gf256 {
uint8_t add(uint8_t a, uint8_t b);
uint8_t multiply(uint8_t a, uint8_t b, uint16_t polynomial);
uint8_t inverse(uint8_t a, uint16_t polynomial);
std::array<uint8_t, 256> generateSBox(uint16_t polynomial);
}

namespace belt {
void encryptBlock(const uint8_t input[16], const uint8_t key[32], uint8_t output[16]);
}

namespace gcm {
void encrypt(const uint8_t* plaintext, std::size_t plaintextLength,
             const uint8_t* aad, std::size_t aadLength,
             const uint8_t key[32], const uint8_t iv[12],
             uint8_t* ciphertext, uint8_t tag[16]);
bool constantTimeTagEqual(const uint8_t expected[16], const uint8_t received[16]);
}

static void printHex(const uint8_t* data, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(data[i]);
    }
    std::cout << std::dec << '\n';
}

int main() {
    constexpr uint16_t POLYNOMIAL = 0x169;

    const uint8_t a = 0x53;
    const uint8_t b = 0xCA;
    const uint8_t invA = gf256::inverse(a, POLYNOMIAL);

    std::cout << "GF(2^8) add:      0x" << std::hex
              << static_cast<unsigned>(gf256::add(a, b)) << '\n';
    std::cout << "GF(2^8) multiply: 0x"
              << static_cast<unsigned>(gf256::multiply(a, b, POLYNOMIAL)) << '\n';
    std::cout << "inverse(0x53):    0x"
              << static_cast<unsigned>(invA) << '\n';
    std::cout << "check a*a^-1:    0x"
              << static_cast<unsigned>(gf256::multiply(a, invA, POLYNOMIAL)) << "\n\n";

    const auto sBox = gf256::generateSBox(POLYNOMIAL);
    std::cout << "Generated S-box, first 16 bytes:\n";
    printHex(sBox.data(), 16);
    std::cout << '\n';

    const uint8_t beltKey[32] = {
        0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,
        0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
        0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,
        0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6
    };

    const uint8_t beltPlaintext[16] = {
        0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,
        0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4
    };

    uint8_t beltCiphertext[16];
    belt::encryptBlock(beltPlaintext, beltKey, beltCiphertext);

    std::cout << "BelT test vector ciphertext:\n";
    printHex(beltCiphertext, 16);
    std::cout << "Expected:\n69cca1c93557c9e3d66bc3e0fa88fa6e\n\n";

    const uint8_t iv[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,
        0x06,0x07,0x08,0x09,0x0A,0x0B
    };

    const uint8_t aad[] = {'l','a','b','-','a','a','d'};
    const uint8_t plaintext[] = {
        'C','r','y','p','t','o','g','r','a','p','h','y',' ','l','a','b'
    };

    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t tag[16];

    gcm::encrypt(plaintext, sizeof(plaintext),
                 aad, sizeof(aad),
                 beltKey, iv,
                 ciphertext, tag);

    std::cout << "GCM ciphertext:\n";
    printHex(ciphertext, sizeof(ciphertext));
    std::cout << "GCM tag:\n";
    printHex(tag, 16);

    uint8_t receivedTag[16];
    for (int i = 0; i < 16; ++i) {
        receivedTag[i] = tag[i];
    }

    std::cout << "Tag valid: "
              << (gcm::constantTimeTagEqual(tag, receivedTag) ? "yes" : "no") << '\n';

    receivedTag[0] ^= 0x01;
    std::cout << "Changed tag valid: "
              << (gcm::constantTimeTagEqual(tag, receivedTag) ? "yes" : "no") << '\n';

    return 0;
}

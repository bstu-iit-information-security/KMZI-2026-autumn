#include "gcm.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <stdexcept>

namespace kmzi {

static std::vector<std::uint8_t> from_hex(const std::string& text) {
    if ((text.size() & 1U) != 0) {
        throw std::invalid_argument("hex input must contain an even number of characters");
    }
    std::vector<std::uint8_t> result;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    }
    return result;
}

static void print_hex(const std::vector<std::uint8_t>& value) {
    for (std::uint8_t byte : value) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
    }
    std::cout << std::dec << '\n';
}

static void self_test() {
    const GaloisField field(0x171);
    if (field.inverse(0) != 0 || field.multiply(0x57, 0x83) != 0x9d ||
        field.multiply(0x53, field.inverse(0x53)) != 1) {
        throw std::runtime_error("GF(2^8) self-test failed");
    }
    
    Block key{};
    AES128 cipher(key);
    const Block encrypted = cipher.encrypt(Block{});
    if (encrypted == Block{}) {
        throw std::runtime_error("AES self-test failed");
    }
    
    BitSlicedSubBytes sub_bytes(field);
    for (unsigned value = 0; value < 256; ++value) {
        Block sliced{};
        sliced.fill(static_cast<std::uint8_t>(value));
        sub_bytes.apply(sliced);
        if (sliced[0] != field.sbox(static_cast<std::uint8_t>(value))) {
            throw std::runtime_error("bit-sliced SubBytes self-test failed");
        }
    }
    
    GCM gcm(cipher);
    const std::array<std::uint8_t, 12> nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    const std::vector<std::uint8_t> plaintext = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    const auto sealed = gcm.encrypt(plaintext, {}, nonce);
    if (gcm.decrypt(sealed.first, nonce) != plaintext || !gcm.verify_tag(sealed.second, sealed.second)) {
        throw std::runtime_error("GCM self-test failed");
    }
    std::cout << "Self-tests passed\n";
}

} // namespace kmzi

int main(int argc, char** argv) {
    try {
        if (argc == 1) {
            kmzi::self_test();
            std::cout << "Usage: lab1 <key-32-hex> <nonce-24-hex> <plaintext-hex> [aad-hex]\n";
            return 0;
        }
        if (argc < 4 || argc > 5) {
            std::cerr << "Usage: lab1 <key-32-hex> <nonce-24-hex> <plaintext-hex> [aad-hex]\n";
            return 2;
        }
        const auto key_bytes = kmzi::from_hex(argv[1]);
        const auto nonce_bytes = kmzi::from_hex(argv[2]);
        const auto plaintext = kmzi::from_hex(argv[3]);
        const auto aad = argc == 5 ? kmzi::from_hex(argv[4]) : std::vector<std::uint8_t>{};
        
        if (key_bytes.size() != 16 || nonce_bytes.size() != 12) {
            throw std::invalid_argument("key must be 16 bytes and nonce must be 12 bytes");
        }
        
        kmzi::Block key{};
        std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
        std::array<std::uint8_t, 12> nonce{};
        std::copy(nonce_bytes.begin(), nonce_bytes.end(), nonce.begin());
        
        const kmzi::AES128 cipher(key);
        const kmzi::GCM gcm(cipher);
        const auto result = gcm.encrypt(plaintext, aad, nonce);
        
        std::cout << "ciphertext: ";
        kmzi::print_hex(result.first);
        std::cout << "tag: ";
        kmzi::print_hex(std::vector<std::uint8_t>(result.second.begin(), result.second.end()));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
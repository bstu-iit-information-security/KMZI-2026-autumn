#pragma once
#include "aes.h"
#include <vector>
#include <cstdint>

namespace kmzi {

class GCM {
public:
    explicit GCM(const AES128& cipher);
    std::pair<std::vector<std::uint8_t>, Block> encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const std::vector<std::uint8_t>& aad,
        const std::array<std::uint8_t, 12>& nonce) const;
    std::vector<std::uint8_t> decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const std::array<std::uint8_t, 12>& nonce) const;
    bool verify_tag(const Block& expected, const Block& actual) const;

private:
    const AES128& cipher_;
    Block hash_subkey_{};
    static Block xor_block(const Block& a, const Block& b);
    static void increment(Block& counter);
    static Block load_block(const std::vector<std::uint8_t>& data, std::size_t offset);
    Block multiply128(const Block& x, const Block& y) const;
    Block ghash(const std::vector<std::uint8_t>& aad, const std::vector<std::uint8_t>& ciphertext) const;
};

} // namespace kmzi
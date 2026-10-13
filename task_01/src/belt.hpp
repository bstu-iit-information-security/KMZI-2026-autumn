#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "galois_field.hpp"

class BeltCipher {
public:
    static constexpr std::size_t kBlockSize = 16;
    static constexpr std::size_t kKeySize = 32;

    using Block = std::array<uint8_t, kBlockSize>;
    using Key = std::array<uint8_t, kKeySize>;

    BeltCipher(const Key& key, const GaloisField& field);

    Block encryptBlock(const Block& in) const;

private:
    uint32_t g(uint32_t u, unsigned r) const;

    SBox sbox_;
    std::array<uint32_t, 8> theta_;
};

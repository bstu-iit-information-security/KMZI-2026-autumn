#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "belt.hpp"

class Gcm {
public:
    using Block = BeltCipher::Block;
    using Iv = std::array<uint8_t, 12>;

    struct Sealed {
        std::vector<uint8_t> ciphertext;
        Block tag;
    };

    explicit Gcm(const BeltCipher& cipher);

    Sealed encrypt(const Iv& iv,
                   const std::vector<uint8_t>& aad,
                   const std::vector<uint8_t>& plaintext) const;

    bool decrypt(const Iv& iv,
                 const std::vector<uint8_t>& aad,
                 const std::vector<uint8_t>& ciphertext,
                 const Block& tag,
                 std::vector<uint8_t>& plaintext) const;

    static Block multiply(const Block& x, const Block& h);
    static Block ghash(const Block& h,
                       const std::vector<uint8_t>& aad,
                       const std::vector<uint8_t>& ciphertext);

private:
    Block counterBlock(const Iv& iv, uint32_t counter) const;
    std::vector<uint8_t> ctr(const Iv& iv, const std::vector<uint8_t>& data) const;
    Block computeTag(const Iv& iv,
                     const std::vector<uint8_t>& aad,
                     const std::vector<uint8_t>& ciphertext) const;

    const BeltCipher& cipher_;
    Block h_;
};

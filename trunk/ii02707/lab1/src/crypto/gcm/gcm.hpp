#pragma once

#include <array>

#include <belt.hpp>

namespace crypto {

class GCM {
public:
    static constexpr size_t kBlockBytes = 16;
    static constexpr size_t kTagBytes   = 16;
    static constexpr size_t kNonceBytes = 12;

    using Block = std::array<uint8_t, kBlockBytes>;
    using Tag   = std::array<uint8_t, kTagBytes>;

    GCM() = default;

    void init(const Belt& cipher, const uint8_t key[Belt::kKeyBytes],
              const GF256& gf) noexcept;

    void encrypt(const uint8_t* aad, size_t aad_len,
                 const uint8_t* plaintext, size_t pt_len,
                 const uint8_t nonce[kNonceBytes],
                 uint8_t* ciphertext,
                 Tag& tag) const noexcept;

    bool decrypt(const uint8_t* aad, size_t aad_len,
                 const uint8_t* ciphertext, size_t ct_len,
                 const uint8_t nonce[kNonceBytes],
                 const Tag& expected_tag,
                 uint8_t* plaintext) const noexcept;

    [[nodiscard]] static bool ct_compare(const Tag& a, const Tag& b) noexcept;

private:
    const Belt* cipher_{nullptr};

    Block H_{};

    void encrypt_block(const Block& in, Block& out) const noexcept;

    [[nodiscard]] Block ghash(const uint8_t* aad, size_t aad_len,
                              const uint8_t* ct, size_t ct_len) const noexcept;

    [[nodiscard]] Block gf128_mul(const Block& x, const Block& y) const noexcept;

    static void build_counter_block(const uint8_t nonce[kNonceBytes],
                                    uint32_t counter,
                                    Block& out) noexcept;

    static void inc32(Block& counter_block) noexcept;

    static Block xor_blocks(const Block& a, const Block& b) noexcept;

    static void load_block(const uint8_t* src, size_t offset, Block& out) noexcept;

    static void store_block(const Block& in, uint8_t* dst, size_t offset) noexcept;
};

}
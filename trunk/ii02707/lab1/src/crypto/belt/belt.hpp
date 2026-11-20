#pragma once

#include <array>

#include <gf256.hpp>

namespace crypto {

class Belt {
public:
    static constexpr size_t kBlockBytes = 16;
    static constexpr size_t kKeyBytes   = 32;
    static constexpr size_t kRounds     = 8;

    explicit Belt(const GF256& gf) noexcept;

    void encrypt(const uint8_t in[kBlockBytes], uint8_t out[kBlockBytes]) const noexcept;

    void decrypt(const uint8_t in[kBlockBytes], uint8_t out[kBlockBytes]) const noexcept;

    [[nodiscard]] static const uint8_t* reference_key() noexcept;

private:
    std::array<uint32_t, 8> subkeys_{};

    std::array<uint8_t, 256> h_box_{};

    void build_h_box(const GF256& gf) noexcept;
    void expand_key() noexcept;

    [[nodiscard]] uint8_t h(uint8_t b) const noexcept { return h_box_[b]; }

    [[nodiscard]] uint32_t G(uint32_t a, uint32_t k, int round) const noexcept;

    void round_forward(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                       uint32_t k, int round) const noexcept;

    void round_backward(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
                        uint32_t k, int round) const noexcept;

    static void bytes_to_words(const uint8_t in[16],
                               uint32_t& a, uint32_t& b,
                               uint32_t& c, uint32_t& d) noexcept;

    static void words_to_bytes(uint32_t a, uint32_t b,
                               uint32_t c, uint32_t d,
                               uint8_t out[16]) noexcept;
};

}
#pragma once

#include <array>

namespace crypto {

class GF256 {
public:
    explicit GF256(uint16_t p_x) noexcept;

    [[nodiscard]] static uint8_t add(uint8_t a, uint8_t b) noexcept {
        return static_cast<uint8_t>(a ^ b);
    }

    [[nodiscard]] uint8_t multiply(uint8_t a, uint8_t b) const noexcept;

    [[nodiscard]] uint8_t xtime(uint8_t b) const noexcept;

    [[nodiscard]] uint8_t inverse(uint8_t a) const noexcept;

    void build_sbox() noexcept;

    [[nodiscard]] uint8_t sbox(uint8_t b) const noexcept {
        return sbox_[b];
    }

    [[nodiscard]] uint8_t inv_sbox(uint8_t b) const noexcept {
        return inv_sbox_[b];
    }

    [[nodiscard]] uint16_t modulus() const noexcept { return p_x_; }

    [[nodiscard]] static bool is_irreducible(uint16_t p_x) noexcept;

private:
    uint16_t p_x_;
    std::array<uint8_t, 256> sbox_{};
    std::array<uint8_t, 256> inv_sbox_{};

    static constexpr uint8_t kAffineConst = 0x63; // c = 01100011
};

}
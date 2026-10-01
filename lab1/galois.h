#pragma once
#include <array>
#include <cstdint>
#include <stdexcept>

namespace kmzi {

class GaloisField {
public:
    explicit GaloisField(std::uint16_t polynomial);
    static std::uint8_t add(std::uint8_t a, std::uint8_t b);
    std::uint8_t multiply(std::uint8_t a, std::uint8_t b) const;
    std::uint8_t inverse(std::uint8_t value) const;
    std::uint8_t sbox(std::uint8_t value) const;
    std::array<std::uint8_t, 256> make_sbox() const;

private:
    std::uint16_t polynomial_;
    std::uint8_t xtime(std::uint8_t value) const;
    static std::uint8_t affine(std::uint8_t value);
};

} // namespace kmzi
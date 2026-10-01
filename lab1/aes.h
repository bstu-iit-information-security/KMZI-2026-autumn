#pragma once
#include "galois.h"
#include <array>
#include <cstdint>

namespace kmzi {

using Block = std::array<std::uint8_t, 16>;

class BitSlicedSubBytes {
public:
    explicit BitSlicedSubBytes(const GaloisField& field);
    void apply(Block& state) const;

private:
    const GaloisField& field_;
    std::array<std::uint16_t, 8> multiply(
        const std::array<std::uint16_t, 8>& a,
        const std::array<std::uint16_t, 8>& b) const;
};

class AES128 {
public:
    explicit AES128(const Block& key, std::uint16_t polynomial = 0x171);
    Block encrypt(const Block& input) const;

private:
    GaloisField field_;
    BitSlicedSubBytes sub_bytes_;
    std::array<Block, 11> round_keys_{};

    void expand_key(const Block& key);
    std::uint8_t rcon_value(unsigned round) const;
    void add_round_key(Block& state, unsigned round) const;
    static void shift_rows(Block& state);
    void mix_columns(Block& state) const;
};

} // namespace kmzi
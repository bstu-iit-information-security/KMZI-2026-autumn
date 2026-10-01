#include "aes.h"

namespace kmzi {

BitSlicedSubBytes::BitSlicedSubBytes(const GaloisField& field) : field_(field) {}

void BitSlicedSubBytes::apply(Block& state) const {
    std::array<std::uint16_t, 8> planes{};
    for (unsigned lane = 0; lane < 16; ++lane) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            planes[bit] |= static_cast<std::uint16_t>(((state[lane] >> bit) & 1U) << lane);
        }
    }

    std::array<std::uint16_t, 8> inverse{};
    inverse[0] = 0xffffU;
    const std::array<std::uint16_t, 8> base = planes;
    
    for (int bit = 7; bit >= 0; --bit) {
        inverse = multiply(inverse, inverse);
        const std::uint16_t exp_bit = (254U >> bit) & 1U;
        const std::uint16_t mask = 0U - exp_bit; // Маска вместо if
        std::array<std::uint16_t, 8> temp = multiply(inverse, base);
        for (unsigned i = 0; i < 8; ++i) {
            inverse[i] = (temp[i] & mask) | (inverse[i] & ~mask);
        }
    }

    for (unsigned bit = 0; bit < 8; ++bit) {
        std::uint16_t transformed = ((0x63U >> bit) & 1U) != 0U ? 0xffffU : 0U;
        transformed ^= inverse[bit] ^ inverse[(bit + 4) & 7U] ^
                       inverse[(bit + 5) & 7U] ^ inverse[(bit + 6) & 7U] ^
                       inverse[(bit + 7) & 7U];
        for (unsigned lane = 0; lane < 16; ++lane) {
            state[lane] = static_cast<std::uint8_t>(
                (state[lane] & static_cast<std::uint8_t>(~(1U << bit))) |
                (((transformed >> lane) & 1U) << bit));
        }
    }
}

std::array<std::uint16_t, 8> BitSlicedSubBytes::multiply(
    const std::array<std::uint16_t, 8>& a,
    const std::array<std::uint16_t, 8>& b) const {
    std::array<std::uint16_t, 15> product{};
    for (unsigned i = 0; i < 8; ++i) {
        for (unsigned j = 0; j < 8; ++j) {
            product[i + j] ^= a[i] & b[j];
        }
    }
    for (int degree = 14; degree >= 8; --degree) {
        const std::uint16_t high = product[degree];
        product[degree - 8] ^= high;
        product[degree - 2] ^= high;
        product[degree - 3] ^= high;
        product[degree - 4] ^= high;
    }
    std::array<std::uint16_t, 8> result{};
    for (unsigned bit = 0; bit < 8; ++bit) {
        result[bit] = product[bit];
    }
    return result;
}

AES128::AES128(const Block& key, std::uint16_t polynomial)
    : field_(polynomial), sub_bytes_(field_) {
    expand_key(key);
}

Block AES128::encrypt(const Block& input) const {
    Block state = input;
    add_round_key(state, 0);
    for (unsigned round = 1; round < 10; ++round) {
        sub_bytes_.apply(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round);
    }
    sub_bytes_.apply(state);
    shift_rows(state);
    add_round_key(state, 10);
    return state;
}

void AES128::expand_key(const Block& key) {
    round_keys_[0] = key;
    for (unsigned round = 1; round <= 10; ++round) {
        const Block& previous = round_keys_[round - 1];
        std::uint8_t t0 = field_.sbox(previous[13]);
        std::uint8_t t1 = field_.sbox(previous[14]);
        std::uint8_t t2 = field_.sbox(previous[15]);
        std::uint8_t t3 = field_.sbox(previous[12]);
        t0 ^= rcon_value(round);
        round_keys_[round][0] = previous[0] ^ t0;
        round_keys_[round][1] = previous[1] ^ t1;
        round_keys_[round][2] = previous[2] ^ t2;
        round_keys_[round][3] = previous[3] ^ t3;
        for (unsigned i = 4; i < 16; ++i) {
            round_keys_[round][i] = previous[i] ^ round_keys_[round][i - 4];
        }
    }
}

std::uint8_t AES128::rcon_value(unsigned round) const {
    std::uint8_t value = 1;
    for (unsigned i = 1; i < round; ++i) {
        value = field_.multiply(value, 2);
    }
    return value;
}

void AES128::add_round_key(Block& state, unsigned round) const {
    for (unsigned i = 0; i < 16; ++i) {
        state[i] ^= round_keys_[round][i];
    }
}

void AES128::shift_rows(Block& state) {
    Block result{};
    for (unsigned row = 0; row < 4; ++row) {
        for (unsigned col = 0; col < 4; ++col) {
            result[4 * col + row] = state[4 * ((col + row) % 4) + row];
        }
    }
    state = result;
}

void AES128::mix_columns(Block& state) const {
    for (unsigned col = 0; col < 4; ++col) {
        const std::uint8_t a0 = state[4 * col];
        const std::uint8_t a1 = state[4 * col + 1];
        const std::uint8_t a2 = state[4 * col + 2];
        const std::uint8_t a3 = state[4 * col + 3];
        state[4 * col] = field_.multiply(a0, 2) ^ field_.multiply(a1, 3) ^ a2 ^ a3;
        state[4 * col + 1] = a0 ^ field_.multiply(a1, 2) ^ field_.multiply(a2, 3) ^ a3;
        state[4 * col + 2] = a0 ^ a1 ^ field_.multiply(a2, 2) ^ field_.multiply(a3, 3);
        state[4 * col + 3] = field_.multiply(a0, 3) ^ a1 ^ a2 ^ field_.multiply(a3, 2);
    }
}

} // namespace kmzi
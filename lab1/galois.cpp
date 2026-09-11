#include "galois.h"

namespace kmzi {

GaloisField::GaloisField(std::uint16_t polynomial) : polynomial_(polynomial) {
    if ((polynomial_ & 0x100U) == 0) {
        throw std::invalid_argument("GF(2^8) polynomial must have degree 8");
    }
}

std::uint8_t GaloisField::add(std::uint8_t a, std::uint8_t b) {
    return static_cast<std::uint8_t>(a ^ b);
}

std::uint8_t GaloisField::multiply(std::uint8_t a, std::uint8_t b) const {
    std::uint16_t product = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
        const std::uint16_t mask = static_cast<std::uint16_t>(0U - static_cast<unsigned>(b & 1U));
        product ^= static_cast<std::uint16_t>(a) & mask;
        b >>= 1;
        a = xtime(a);
        product = static_cast<std::uint16_t>(product & 0x1ffU);
    }
    return static_cast<std::uint8_t>(product);
}

std::uint8_t GaloisField::inverse(std::uint8_t value) const {
    std::uint8_t result = 1;
    std::uint8_t base = value;
    // BRANCHLESS возведение в степень 254
    for (int bit = 7; bit >= 0; --bit) {
        result = multiply(result, result);
        const std::uint8_t exp_bit = (254U >> bit) & 1U;
        const std::uint8_t mask = static_cast<std::uint8_t>(0U - exp_bit);
        std::uint8_t temp = multiply(result, base);
        result = (temp & mask) | (result & ~mask);
    }
    // BRANCHLESS обработка нуля (гарантирует возврат 0 без if)
    std::uint8_t zero_mask = static_cast<std::uint8_t>(0U - (value == 0));
    return result & ~zero_mask;
}

std::uint8_t GaloisField::sbox(std::uint8_t value) const {
    return affine(inverse(value));
}

std::array<std::uint8_t, 256> GaloisField::make_sbox() const {
    std::array<std::uint8_t, 256> result{};
    for (unsigned i = 0; i < result.size(); ++i) {
        result[i] = sbox(static_cast<std::uint8_t>(i));
    }
    return result;
}

std::uint8_t GaloisField::xtime(std::uint8_t value) const {
    const std::uint8_t carry = static_cast<std::uint8_t>(value >> 7);
    const std::uint8_t mask = static_cast<std::uint8_t>(0U - carry);
    const std::uint8_t reduction = static_cast<std::uint8_t>(polynomial_ & 0xffU);
    return static_cast<std::uint8_t>((value << 1U) ^ (reduction & mask));
}

std::uint8_t GaloisField::affine(std::uint8_t value) {
    std::uint8_t result = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
        const unsigned parity = ((value >> bit) ^ (value >> ((bit + 4) & 7U)) ^
             (value >> ((bit + 5) & 7U)) ^ (value >> ((bit + 6) & 7U)) ^
             (value >> ((bit + 7) & 7U)) ^ (0x63U >> bit)) & 1U;
        result |= static_cast<std::uint8_t>(parity << bit);
    }
    return result;
}

} // namespace kmzi
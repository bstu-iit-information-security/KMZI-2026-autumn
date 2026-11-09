#include "galois_field.hpp"

#include <stdexcept>

#include "ct_utils.hpp"

namespace {

constexpr std::array<uint8_t, 8> kAffineRows = {0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8};
constexpr uint8_t kAffineConstant = 0x63;

int degree(uint32_t v) {
    int d = -1;
    while (v != 0) {
        ++d;
        v >>= 1;
    }
    return d;
}

uint32_t polyMod(uint32_t a, uint32_t m) {
    const int dm = degree(m);
    for (int d = degree(a); d >= dm; d = degree(a)) {
        a ^= m << (d - dm);
    }
    return a;
}

uint8_t parity(uint8_t v) {
    v = static_cast<uint8_t>(v ^ (v >> 4));
    v = static_cast<uint8_t>(v ^ (v >> 2));
    v = static_cast<uint8_t>(v ^ (v >> 1));
    return static_cast<uint8_t>(v & 1u);
}

}

GaloisField::GaloisField(uint16_t p_x) : p_x_(p_x) {
    if (!isIrreducible(p_x)) {
        throw std::invalid_argument("p(x) is not an irreducible polynomial of degree 8");
    }
}

uint16_t GaloisField::modulus() const {
    return p_x_;
}

uint8_t GaloisField::add(uint8_t a, uint8_t b) {
    return static_cast<uint8_t>(a ^ b);
}

uint8_t GaloisField::multiply(uint8_t a, uint8_t b, uint16_t p_x) {
    const uint8_t reduction = static_cast<uint8_t>(p_x & 0xFFu);
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = static_cast<uint8_t>(result ^ (a & ct::mask8(b)));
        b = static_cast<uint8_t>(b >> 1);
        const uint8_t high = ct::mask8(static_cast<uint8_t>(a >> 7));
        a = static_cast<uint8_t>((a << 1) ^ (reduction & high));
    }
    return result;
}

uint8_t GaloisField::inverse(uint8_t a, uint16_t p_x) {
    uint8_t result = 1;
    uint8_t square = a;
    for (int i = 1; i < 8; ++i) {
        square = multiply(square, square, p_x);
        result = multiply(result, square, p_x);
    }
    return result;
}

bool GaloisField::isIrreducible(uint16_t p_x) {
    if (degree(p_x) != 8) {
        return false;
    }
    for (int d = 1; d <= 4; ++d) {
        const uint32_t lo = 1u << d;
        const uint32_t hi = 1u << (d + 1);
        for (uint32_t q = lo; q < hi; ++q) {
            if (polyMod(p_x, q) == 0) {
                return false;
            }
        }
    }
    return true;
}

SBox GaloisField::generateSBox() const {
    SBox table{};
    for (unsigned x = 0; x < 256; ++x) {
        const uint8_t inv = inverse(static_cast<uint8_t>(x), p_x_);
        uint8_t out = 0;
        for (unsigned i = 0; i < 8; ++i) {
            const uint8_t bit = static_cast<uint8_t>(
                parity(static_cast<uint8_t>(kAffineRows[i] & inv)) ^ ((kAffineConstant >> i) & 1u));
            out = static_cast<uint8_t>(out | (bit << i));
        }
        table[x] = out;
    }
    return table;
}

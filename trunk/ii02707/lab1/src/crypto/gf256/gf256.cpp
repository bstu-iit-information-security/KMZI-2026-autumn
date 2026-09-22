#include <gf256.hpp>

namespace crypto {

GF256::GF256(uint16_t p_x) noexcept : p_x_(p_x) {
    if ((p_x & 0x100) == 0 || !is_irreducible(p_x)) {
        p_x_ = 0x12B;
    }
    build_sbox();
}

uint8_t GF256::xtime(uint8_t b) const noexcept {
    const uint8_t hi   = static_cast<uint8_t>(b >> 7);
    const uint8_t mask = static_cast<uint8_t>(0u - static_cast<unsigned>(hi));
    const uint8_t red  = static_cast<uint8_t>(p_x_ & 0xFF);

    const uint8_t shifted = static_cast<uint8_t>(b << 1);
    const uint8_t xor_val = static_cast<uint8_t>(mask & red);
    return static_cast<uint8_t>(shifted ^ xor_val);
}

uint8_t GF256::multiply(uint8_t a, uint8_t b) const noexcept {
    uint8_t result = 0;
    uint8_t aa = a;
    uint8_t bb = b;

    for (int i = 0; i < 8; ++i) {
        const uint8_t bit = static_cast<uint8_t>(bb & 1u);
        const uint8_t mask = static_cast<uint8_t>(0u - static_cast<unsigned>(bit));
        result = static_cast<uint8_t>(result ^ (aa & mask));

        aa = xtime(aa);
        bb = static_cast<uint8_t>(bb >> 1);
    }
    return result;
}

uint8_t GF256::inverse(uint8_t a) const noexcept {
    const uint8_t a2   = multiply(a, a);
    const uint8_t a4   = multiply(a2, a2);
    const uint8_t a8   = multiply(a4, a4);
    const uint8_t a16  = multiply(a8, a8);
    const uint8_t a32  = multiply(a16, a16);
    const uint8_t a64  = multiply(a32, a32);
    const uint8_t a128 = multiply(a64, a64);

    uint8_t res = a2;
    res = multiply(res, a4);
    res = multiply(res, a8);
    res = multiply(res, a16);
    res = multiply(res, a32);
    res = multiply(res, a64);
    res = multiply(res, a128);
    return res;
}

void GF256::build_sbox() noexcept {
    auto rotl8 = [](uint8_t v, int n) -> uint8_t {
        return static_cast<uint8_t>((v << n) | (v >> (8 - n)));
    };

    for (int i = 0; i < 256; ++i) {
        const uint8_t b   = static_cast<uint8_t>(i);
        const uint8_t inv = inverse(b);
        const uint8_t s   = static_cast<uint8_t>(
            inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3)
                ^ rotl8(inv, 4) ^ kAffineConst);
        sbox_[i] = s;
        inv_sbox_[s] = b;
    }
}

bool GF256::is_irreducible(uint16_t p_x) noexcept {
    static constexpr uint16_t divisors[] = {
        0x2, 0x3,                    // x,     x+1
        0x7,                         // x^2+x+1
        0xB, 0xD,                    // x^3+x+1, x^3+x^2+1
        0x13, 0x19, 0x1F             // x^4+x+1, x^4+x^3+1, x^4+x^3+x^2+x+1
    };
    for (uint16_t d : divisors) {
        uint16_t r = p_x;
        int deg_r = 15; while (deg_r > 0 && !((r >> deg_r) & 1)) --deg_r;
        int deg_d = 15; while (deg_d > 0 && !((d >> deg_d) & 1)) --deg_d;
        while (deg_r >= deg_d && r) {
            r ^= static_cast<uint16_t>(d << (deg_r - deg_d));
            deg_r = 15; while (deg_r > 0 && !((r >> deg_r) & 1)) --deg_r;
        }
        if (r == 0) return false;
    }
    return true;
}


}
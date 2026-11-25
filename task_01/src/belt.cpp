#include "belt.hpp"

#include "ct_utils.hpp"

namespace {

uint32_t loadWord(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void storeWord(uint8_t* p, uint32_t w) {
    p[0] = static_cast<uint8_t>(w);
    p[1] = static_cast<uint8_t>(w >> 8);
    p[2] = static_cast<uint8_t>(w >> 16);
    p[3] = static_cast<uint8_t>(w >> 24);
}

}

BeltCipher::BeltCipher(const Key& key, const GaloisField& field)
    : sbox_(field.generateSBox()), theta_{} {
    for (std::size_t i = 0; i < theta_.size(); ++i) {
        theta_[i] = loadWord(key.data() + 4 * i);
    }
}

uint32_t BeltCipher::g(uint32_t u, unsigned r) const {
    const uint32_t y = static_cast<uint32_t>(sbox_[u & 0xFFu]) |
                       (static_cast<uint32_t>(sbox_[(u >> 8) & 0xFFu]) << 8) |
                       (static_cast<uint32_t>(sbox_[(u >> 16) & 0xFFu]) << 16) |
                       (static_cast<uint32_t>(sbox_[(u >> 24) & 0xFFu]) << 24);
    return ct::rotl32(y, r);
}

BeltCipher::Block BeltCipher::encryptBlock(const Block& in) const {
    uint32_t a = loadWord(in.data());
    uint32_t b = loadWord(in.data() + 4);
    uint32_t c = loadWord(in.data() + 8);
    uint32_t d = loadWord(in.data() + 12);

    for (uint32_t i = 1; i <= 8; ++i) {
        const std::size_t base = 7u * (i - 1u);
        const uint32_t k1 = theta_[(base + 0) % 8];
        const uint32_t k2 = theta_[(base + 1) % 8];
        const uint32_t k3 = theta_[(base + 2) % 8];
        const uint32_t k4 = theta_[(base + 3) % 8];
        const uint32_t k5 = theta_[(base + 4) % 8];
        const uint32_t k6 = theta_[(base + 5) % 8];
        const uint32_t k7 = theta_[(base + 6) % 8];

        b ^= g(a + k1, 5);
        c ^= g(d + k2, 21);
        a -= g(b + k3, 13);
        const uint32_t e = g(b + c + k4, 21) ^ i;
        b += e;
        c -= e;
        d += g(c + k5, 13);
        b ^= g(a + k6, 21);
        c ^= g(d + k7, 5);

        uint32_t t = a;
        a = b;
        b = t;
        t = c;
        c = d;
        d = t;
        t = b;
        b = c;
        c = t;
    }

    Block out{};
    storeWord(out.data(), b);
    storeWord(out.data() + 4, d);
    storeWord(out.data() + 8, a);
    storeWord(out.data() + 12, c);
    return out;
}

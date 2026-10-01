#include <belt.hpp>

namespace crypto {

namespace {

constexpr uint8_t kReferenceKey[Belt::kKeyBytes] = {
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
    0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37,
    0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
};

[[nodiscard]] inline uint32_t rotl32(uint32_t x, unsigned n) noexcept {
    n &= 31u;
    return (x << n) | (x >> ((32u - n) & 31u));
}

[[nodiscard]] inline uint32_t rotr32(uint32_t x, unsigned n) noexcept {
    n &= 31u;
    return (x >> n) | (x << ((32u - n) & 31u));
}

}

const uint8_t* Belt::reference_key() noexcept {
    return kReferenceKey;
}

Belt::Belt(const GF256& gf) noexcept {
    build_h_box(gf);
    expand_key();
}

void Belt::build_h_box(const GF256& gf) noexcept {
    auto rotl8 = [](uint8_t v, int n) -> uint8_t {
        return static_cast<uint8_t>((v << n) | (v >> (8 - n)));
    };
    for (int i = 0; i < 256; ++i) {
        const uint8_t b   = static_cast<uint8_t>(i);
        const uint8_t inv = gf.inverse(b);
        h_box_[i] = static_cast<uint8_t>(inv ^ rotl8(inv, 1)
                                       ^ rotl8(inv, 2) ^ rotl8(inv, 3)
                                       ^ 0xA6);
    }
}

void Belt::expand_key() noexcept {
    for (size_t i = 0; i < 8; ++i) {
        subkeys_[i] = static_cast<uint32_t>(kReferenceKey[4 * i + 0])
                    | (static_cast<uint32_t>(kReferenceKey[4 * i + 1]) << 8)
                    | (static_cast<uint32_t>(kReferenceKey[4 * i + 2]) << 16)
                    | (static_cast<uint32_t>(kReferenceKey[4 * i + 3]) << 24);
    }
}

uint32_t Belt::G(uint32_t a, uint32_t k, int round) const noexcept {
    uint32_t x = a ^ k;
    uint8_t bytes[4] = {
        static_cast<uint8_t>(x & 0xFF),
        static_cast<uint8_t>((x >> 8) & 0xFF),
        static_cast<uint8_t>((x >> 16) & 0xFF),
        static_cast<uint8_t>((x >> 24) & 0xFF),
    };
    for (auto& by : bytes) by = h(by);
    x = static_cast<uint32_t>(bytes[0])
      | (static_cast<uint32_t>(bytes[1]) << 8)
      | (static_cast<uint32_t>(bytes[2]) << 16)
      | (static_cast<uint32_t>(bytes[3]) << 24);
    return rotl32(x, static_cast<unsigned>(round + 1));
}

void Belt::round_forward(uint32_t& a, uint32_t& b,
                         uint32_t& c, uint32_t& d,
                         uint32_t k, int round) const noexcept {
    b ^= G(a, k, round);
    a = static_cast<uint32_t>(a + b + 1u);
    const uint32_t t = a;
    a = b;
    b = c;
    c = d;
    d = t;
}

void Belt::round_backward(uint32_t& a, uint32_t& b,
                          uint32_t& c, uint32_t& d,
                          uint32_t k, int round) const noexcept {
    const uint32_t t = d;
    d = c;
    c = b;
    b = a;
    a = t;
    a = static_cast<uint32_t>(a - b - 1u);
    b ^= G(a, k, round);
}

void Belt::bytes_to_words(const uint8_t in[16],
                          uint32_t& a, uint32_t& b,
                          uint32_t& c, uint32_t& d) noexcept {
    a = static_cast<uint32_t>(in[0])
      | (static_cast<uint32_t>(in[1]) << 8)
      | (static_cast<uint32_t>(in[2]) << 16)
      | (static_cast<uint32_t>(in[3]) << 24);
    b = static_cast<uint32_t>(in[4])
      | (static_cast<uint32_t>(in[5]) << 8)
      | (static_cast<uint32_t>(in[6]) << 16)
      | (static_cast<uint32_t>(in[7]) << 24);
    c = static_cast<uint32_t>(in[8])
      | (static_cast<uint32_t>(in[9]) << 8)
      | (static_cast<uint32_t>(in[10]) << 16)
      | (static_cast<uint32_t>(in[11]) << 24);
    d = static_cast<uint32_t>(in[12])
      | (static_cast<uint32_t>(in[13]) << 8)
      | (static_cast<uint32_t>(in[14]) << 16)
      | (static_cast<uint32_t>(in[15]) << 24);
}

void Belt::words_to_bytes(uint32_t a, uint32_t b,
                          uint32_t c, uint32_t d,
                          uint8_t out[16]) noexcept {
    out[0]  = static_cast<uint8_t>(a & 0xFF);
    out[1]  = static_cast<uint8_t>((a >> 8) & 0xFF);
    out[2]  = static_cast<uint8_t>((a >> 16) & 0xFF);
    out[3]  = static_cast<uint8_t>((a >> 24) & 0xFF);
    out[4]  = static_cast<uint8_t>(b & 0xFF);
    out[5]  = static_cast<uint8_t>((b >> 8) & 0xFF);
    out[6]  = static_cast<uint8_t>((b >> 16) & 0xFF);
    out[7]  = static_cast<uint8_t>((b >> 24) & 0xFF);
    out[8]  = static_cast<uint8_t>(c & 0xFF);
    out[9]  = static_cast<uint8_t>((c >> 8) & 0xFF);
    out[10] = static_cast<uint8_t>((c >> 16) & 0xFF);
    out[11] = static_cast<uint8_t>((c >> 24) & 0xFF);
    out[12] = static_cast<uint8_t>(d & 0xFF);
    out[13] = static_cast<uint8_t>((d >> 8) & 0xFF);
    out[14] = static_cast<uint8_t>((d >> 16) & 0xFF);
    out[15] = static_cast<uint8_t>((d >> 24) & 0xFF);
}

void Belt::encrypt(const uint8_t in[kBlockBytes],
                   uint8_t out[kBlockBytes]) const noexcept {
    uint32_t a, b, c, d;
    bytes_to_words(in, a, b, c, d);

    for (int r = 0; r < static_cast<int>(kRounds); ++r) {
        const uint32_t k = subkeys_[r % 8];
        round_forward(a, b, c, d, k, r);
    }

    words_to_bytes(a, b, c, d, out);
}

void Belt::decrypt(const uint8_t in[kBlockBytes],
                   uint8_t out[kBlockBytes]) const noexcept {
    uint32_t a, b, c, d;
    bytes_to_words(in, a, b, c, d);

    for (int r = static_cast<int>(kRounds) - 1; r >= 0; --r) {
        const uint32_t k = subkeys_[r % 8];
        round_backward(a, b, c, d, k, r);
    }

    words_to_bytes(a, b, c, d, out);
}

}
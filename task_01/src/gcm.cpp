#include "gcm.hpp"

#include <algorithm>

#include "ct_utils.hpp"

namespace {

void absorb(Gcm::Block& y, const Gcm::Block& h, const std::vector<uint8_t>& data) {
    for (std::size_t offset = 0; offset < data.size(); offset += 16) {
        const std::size_t chunk = std::min<std::size_t>(16, data.size() - offset);
        Gcm::Block x{};
        std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
                  data.begin() + static_cast<std::ptrdiff_t>(offset + chunk),
                  x.begin());
        for (std::size_t i = 0; i < 16; ++i) {
            y[i] = static_cast<uint8_t>(y[i] ^ x[i]);
        }
        y = Gcm::multiply(y, h);
    }
}

void storeLength(uint8_t* p, uint64_t bits) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
    }
}

}

Gcm::Gcm(const BeltCipher& cipher) : cipher_(cipher), h_(cipher.encryptBlock(Block{})) {}

Gcm::Block Gcm::multiply(const Block& x, const Block& h) {
    Block z{};
    Block v = h;
    for (unsigned i = 0; i < 128; ++i) {
        const uint8_t bit = static_cast<uint8_t>((x[i >> 3] >> (7u - (i & 7u))) & 1u);
        const uint8_t take = ct::mask8(bit);
        for (std::size_t j = 0; j < 16; ++j) {
            z[j] = static_cast<uint8_t>(z[j] ^ (v[j] & take));
        }
        const uint8_t lsb = static_cast<uint8_t>(v[15] & 1u);
        uint8_t carry = 0;
        for (std::size_t j = 0; j < 16; ++j) {
            const uint8_t next = static_cast<uint8_t>(v[j] & 1u);
            v[j] = static_cast<uint8_t>((v[j] >> 1) | (carry << 7));
            carry = next;
        }
        v[0] = static_cast<uint8_t>(v[0] ^ (0xE1u & ct::mask8(lsb)));
    }
    return z;
}

Gcm::Block Gcm::ghash(const Block& h,
                      const std::vector<uint8_t>& aad,
                      const std::vector<uint8_t>& ciphertext) {
    Block y{};
    absorb(y, h, aad);
    absorb(y, h, ciphertext);

    Block lengths{};
    storeLength(lengths.data(), static_cast<uint64_t>(aad.size()) * 8u);
    storeLength(lengths.data() + 8, static_cast<uint64_t>(ciphertext.size()) * 8u);
    for (std::size_t i = 0; i < 16; ++i) {
        y[i] = static_cast<uint8_t>(y[i] ^ lengths[i]);
    }
    return multiply(y, h);
}

Gcm::Block Gcm::counterBlock(const Iv& iv, uint32_t counter) const {
    Block cb{};
    std::copy(iv.begin(), iv.end(), cb.begin());
    cb[12] = static_cast<uint8_t>(counter >> 24);
    cb[13] = static_cast<uint8_t>(counter >> 16);
    cb[14] = static_cast<uint8_t>(counter >> 8);
    cb[15] = static_cast<uint8_t>(counter);
    return cb;
}

std::vector<uint8_t> Gcm::ctr(const Iv& iv, const std::vector<uint8_t>& data) const {
    std::vector<uint8_t> out(data.size());
    uint32_t counter = 2;
    for (std::size_t offset = 0; offset < data.size(); offset += 16) {
        const Block stream = cipher_.encryptBlock(counterBlock(iv, counter));
        ++counter;
        const std::size_t chunk = std::min<std::size_t>(16, data.size() - offset);
        for (std::size_t i = 0; i < chunk; ++i) {
            out[offset + i] = static_cast<uint8_t>(data[offset + i] ^ stream[i]);
        }
    }
    return out;
}

Gcm::Block Gcm::computeTag(const Iv& iv,
                           const std::vector<uint8_t>& aad,
                           const std::vector<uint8_t>& ciphertext) const {
    const Block s = ghash(h_, aad, ciphertext);
    const Block mask = cipher_.encryptBlock(counterBlock(iv, 1));
    Block tag{};
    for (std::size_t i = 0; i < 16; ++i) {
        tag[i] = static_cast<uint8_t>(s[i] ^ mask[i]);
    }
    return tag;
}

Gcm::Sealed Gcm::encrypt(const Iv& iv,
                         const std::vector<uint8_t>& aad,
                         const std::vector<uint8_t>& plaintext) const {
    Sealed sealed;
    sealed.ciphertext = ctr(iv, plaintext);
    sealed.tag = computeTag(iv, aad, sealed.ciphertext);
    return sealed;
}

bool Gcm::decrypt(const Iv& iv,
                  const std::vector<uint8_t>& aad,
                  const std::vector<uint8_t>& ciphertext,
                  const Block& tag,
                  std::vector<uint8_t>& plaintext) const {
    const Block expected = computeTag(iv, aad, ciphertext);
    const bool valid = ct::equal(expected.data(), tag.data(), tag.size());
    if (!valid) {
        plaintext.clear();
        return false;
    }
    plaintext = ctr(iv, ciphertext);
    return true;
}

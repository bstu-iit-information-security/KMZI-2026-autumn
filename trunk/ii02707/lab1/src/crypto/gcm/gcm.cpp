#include <gcm.hpp>

namespace crypto {

void GCM::load_block(const uint8_t* src, size_t offset, Block& out) noexcept {
    for (size_t i = 0; i < kBlockBytes; ++i) out[i] = src[offset + i];
}

void GCM::store_block(const Block& in, uint8_t* dst, size_t offset) noexcept {
    for (size_t i = 0; i < kBlockBytes; ++i) dst[offset + i] = in[i];
}

GCM::Block GCM::xor_blocks(const Block& a, const Block& b) noexcept {
    Block r{};
    for (size_t i = 0; i < kBlockBytes; ++i) {
        r[i] = static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return r;
}

void GCM::build_counter_block(const uint8_t nonce[kNonceBytes],
                              uint32_t counter, Block& out) noexcept {
    for (size_t i = 0; i < kNonceBytes; ++i) out[i] = nonce[i];
    out[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    out[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    out[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    out[15] = static_cast<uint8_t>(counter & 0xFF);
}

void GCM::inc32(Block& counter_block) noexcept {
    uint32_t c = (static_cast<uint32_t>(counter_block[12]) << 24)
               | (static_cast<uint32_t>(counter_block[13]) << 16)
               | (static_cast<uint32_t>(counter_block[14]) << 8)
               | (static_cast<uint32_t>(counter_block[15]));
    c += 1u;
    counter_block[12] = static_cast<uint8_t>((c >> 24) & 0xFF);
    counter_block[13] = static_cast<uint8_t>((c >> 16) & 0xFF);
    counter_block[14] = static_cast<uint8_t>((c >> 8) & 0xFF);
    counter_block[15] = static_cast<uint8_t>(c & 0xFF);
}

void GCM::init(const Belt& cipher, const uint8_t key[Belt::kKeyBytes],
               const GF256& gf) noexcept {
    (void)gf;
    cipher_ = &cipher;
    Block zero{};
    cipher_->encrypt(zero.data(), H_.data());
}

void GCM::encrypt_block(const Block& in, Block& out) const noexcept {
    cipher_->encrypt(in.data(), out.data());
}

GCM::Block GCM::gf128_mul(const Block& x, const Block& y) const noexcept {
    Block Z{};
    Block V = y;

    Block R{};
    R[0] = 0xE1;

    for (int i = 0; i < 128; ++i) {
        const uint8_t byte_i = x[static_cast<size_t>(i) >> 3];
        const uint8_t bit    = static_cast<uint8_t>((byte_i >> (7 - (i & 7))) & 1u);

        const uint8_t mask = static_cast<uint8_t>(0u - static_cast<unsigned>(bit));

        for (size_t j = 0; j < kBlockBytes; ++j) {
            Z[j] = static_cast<uint8_t>(Z[j] ^ (V[j] & mask));
        }

        const uint8_t lsb = static_cast<uint8_t>(V[kBlockBytes - 1] & 1u);
        const uint8_t rmask = static_cast<uint8_t>(0u - static_cast<unsigned>(lsb));

        uint8_t carry = 0;
        for (size_t j = 0; j < kBlockBytes; ++j) {
            const uint8_t cur = V[j];
            V[j] = static_cast<uint8_t>((cur >> 1) | (carry << 7));
            carry = static_cast<uint8_t>(cur & 1u);
        }

        for (size_t j = 0; j < kBlockBytes; ++j) {
            V[j] = static_cast<uint8_t>(V[j] ^ (R[j] & rmask));
        }
    }

    return Z;
}

GCM::Block GCM::ghash(const uint8_t* aad, size_t aad_len,
                      const uint8_t* ct, size_t ct_len) const noexcept {
    Block Y{};

    size_t off = 0;
    while (off < aad_len) {
        Block Xi{};
        const size_t take = (aad_len - off < kBlockBytes) ? (aad_len - off) : kBlockBytes;
        for (size_t i = 0; i < take; ++i) Xi[i] = aad[off + i];
        Y = gf128_mul(xor_blocks(Y, Xi), H_);
        off += take;
    }

    off = 0;
    while (off < ct_len) {
        Block Xi{};
        const size_t take = (ct_len - off < kBlockBytes) ? (ct_len - off) : kBlockBytes;
        for (size_t i = 0; i < take; ++i) Xi[i] = ct[off + i];
        Y = gf128_mul(xor_blocks(Y, Xi), H_);
        off += take;
    }

    Block len_block{};
    const uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8u;
    const uint64_t ct_bits  = static_cast<uint64_t>(ct_len) * 8u;
    for (int i = 0; i < 8; ++i) {
        len_block[i]     = static_cast<uint8_t>((aad_bits >> (56 - 8 * i)) & 0xFF);
        len_block[8 + i] = static_cast<uint8_t>((ct_bits  >> (56 - 8 * i)) & 0xFF);
    }
    Y = gf128_mul(xor_blocks(Y, len_block), H_);

    return Y;
}

void GCM::encrypt(const uint8_t* aad, size_t aad_len,
                  const uint8_t* plaintext, size_t pt_len,
                  const uint8_t nonce[kNonceBytes],
                  uint8_t* ciphertext,
                  Tag& tag) const noexcept {
    Block ctr{};
    build_counter_block(nonce, 2u, ctr);

    size_t off = 0;
    while (off < pt_len) {
        Block keystream{};
        encrypt_block(ctr, keystream);
        inc32(ctr);

        const size_t take = (pt_len - off < kBlockBytes) ? (pt_len - off) : kBlockBytes;
        for (size_t i = 0; i < take; ++i) {
            ciphertext[off + i] = static_cast<uint8_t>(plaintext[off + i] ^ keystream[i]);
        }
        off += take;
    }

    Block S = ghash(aad, aad_len, ciphertext, pt_len);

    Block cb0{};
    build_counter_block(nonce, 1u, cb0);
    Block ek0{};
    encrypt_block(cb0, ek0);

    Block tag_block = xor_blocks(S, ek0);
    for (size_t i = 0; i < kTagBytes; ++i) tag[i] = tag_block[i];
}

bool GCM::decrypt(const uint8_t* aad, size_t aad_len,
                  const uint8_t* ciphertext, size_t ct_len,
                  const uint8_t nonce[kNonceBytes],
                  const Tag& expected_tag,
                  uint8_t* plaintext) const noexcept {
    Block S = ghash(aad, aad_len, ciphertext, ct_len);
    Block cb0{};
    build_counter_block(nonce, 1u, cb0);
    Block ek0{};
    encrypt_block(cb0, ek0);
    Block tag_block = xor_blocks(S, ek0);

    Tag computed{};
    for (size_t i = 0; i < kTagBytes; ++i) computed[i] = tag_block[i];

    const bool ok = ct_compare(computed, expected_tag);
    if (!ok) {
        for (size_t i = 0; i < ct_len; ++i) plaintext[i] = 0;
        return false;
    }

    Block ctr{};
    build_counter_block(nonce, 2u, ctr);

    size_t off = 0;
    while (off < ct_len) {
        Block keystream{};
        encrypt_block(ctr, keystream);
        inc32(ctr);

        const size_t take = (ct_len - off < kBlockBytes) ? (ct_len - off) : kBlockBytes;
        for (size_t i = 0; i < take; ++i) {
            plaintext[off + i] = static_cast<uint8_t>(ciphertext[off + i] ^ keystream[i]);
        }
        off += take;
    }
    return true;
}

bool GCM::ct_compare(const Tag& a, const Tag& b) noexcept {
    uint8_t acc = 0;
    for (size_t i = 0; i < kTagBytes; ++i) {
        acc = static_cast<uint8_t>(acc | (a[i] ^ b[i]));
    }
    return acc == 0;
}

}
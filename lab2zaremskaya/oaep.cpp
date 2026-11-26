#include "oaep.hpp"

#include <cstring>

namespace rsa {
namespace {

constexpr std::size_t kDbLen = kModulusBytes - kHashLen - 1;

}  // namespace

void OaepEngine::hash(const uint8_t* data, std::size_t len, uint8_t out[kHashLen]) {
    sha512(data, len, out);
}

void OaepEngine::mgf1(const uint8_t* seed, std::size_t seed_len, uint8_t* mask, std::size_t mask_len) {
    std::size_t offset = 0;
    uint32_t counter = 0;
    while (offset < mask_len) {
        std::memcpy(mgf_block_, seed, seed_len);
        mgf_block_[seed_len] = static_cast<uint8_t>(counter >> 24);
        mgf_block_[seed_len + 1] = static_cast<uint8_t>(counter >> 16);
        mgf_block_[seed_len + 2] = static_cast<uint8_t>(counter >> 8);
        mgf_block_[seed_len + 3] = static_cast<uint8_t>(counter);
        hash(mgf_block_, seed_len + 4, mgf_hash_);
        std::size_t take = kHashLen;
        if (take > mask_len - offset) {
            take = mask_len - offset;
        }
        std::memcpy(mask + offset, mgf_hash_, take);
        offset += take;
        ++counter;
    }
}

OaepEngine::Delim OaepEngine::find_delimiter(const uint8_t* db, std::size_t db_len) {
  
    Delim d{};
    d.one_pos = 0;
    d.found = 0;
    d.ps_ok = 0xffffffffu;
    uint32_t still_ps = 0xffffffffu;
    for (std::size_t i = kHashLen; i < db_len; ++i) {
        const uint32_t is_zero = ct::eq_u8(db[i], 0x00);
        const uint32_t is_one = ct::eq_u8(db[i], 0x01);
        const uint32_t invalid = still_ps & ~is_zero & ~is_one;
        d.ps_ok &= ~invalid;
        const uint32_t take = still_ps & is_one;
        d.one_pos = ct::select(take, static_cast<uint32_t>(i), d.one_pos);
        d.found |= take;
        still_ps &= ~is_one;
    }
    return d;
}

bool OaepEngine::encode(const uint8_t* msg, std::size_t msg_len, uint8_t em[kModulusBytes]) {
    if (msg_len > kMaxMessage) {
        return false;
    }

    const uint8_t empty_label = 0;
    hash(&empty_label, 0, lhash_);  // Label = пустая строка

    std::memset(db_, 0, kDbLen);
    std::memcpy(db_, lhash_, kHashLen);
    const std::size_t ps_len = kDbLen - kHashLen - 1 - msg_len;
    db_[kHashLen + ps_len] = 0x01;
    if (msg_len != 0) {
        std::memcpy(db_ + kHashLen + ps_len + 1, msg, msg_len);
    }

    if (!random_bytes(seed_, kHashLen)) {
        return false;
    }

    mgf1(seed_, kHashLen, db_mask_, kDbLen);
    for (std::size_t i = 0; i < kDbLen; ++i) {
        masked_db_[i] = static_cast<uint8_t>(db_[i] ^ db_mask_[i]);
    }
    mgf1(masked_db_, kDbLen, seed_mask_, kHashLen);
    for (std::size_t i = 0; i < kHashLen; ++i) {
        seed_[i] = static_cast<uint8_t>(seed_[i] ^ seed_mask_[i]);  
    }

    em[0] = 0x00;
    std::memcpy(em + 1, seed_, kHashLen);
    std::memcpy(em + 1 + kHashLen, masked_db_, kDbLen);
    return true;
}

OaepResult OaepEngine::decode(const uint8_t em[kModulusBytes]) {
    OaepResult r{};
    r.ok = false;
    r.len = 0;
    std::memset(r.msg, 0, sizeof(r.msg));

    const uint8_t empty_label = 0;
    hash(&empty_label, 0, lhash_);

    const uint8_t* masked_seed = em + 1;
    const uint8_t* masked_db = em + 1 + kHashLen;
    std::memcpy(masked_db_, masked_db, kDbLen);

    mgf1(masked_db_, kDbLen, seed_mask_, kHashLen);
    for (std::size_t i = 0; i < kHashLen; ++i) {
        seed_[i] = static_cast<uint8_t>(masked_seed[i] ^ seed_mask_[i]);
    }
    mgf1(seed_, kHashLen, db_mask_, kDbLen);
    for (std::size_t i = 0; i < kDbLen; ++i) {
        db_[i] = static_cast<uint8_t>(masked_db_[i] ^ db_mask_[i]);
    }

    uint32_t good = ct::eq_u8(em[0], 0x00);

    const uint8_t hash_diff = ct::xor_accum(db_, lhash_, kHashLen);
    good &= ct::eq_u8(hash_diff, 0);

    const Delim delim = find_delimiter(db_, kDbLen);
    good &= delim.ps_ok;
    good &= delim.found;
    const uint32_t one_pos = delim.one_pos;

    const uint32_t mlen = static_cast<uint32_t>(kDbLen) - one_pos - 1u;

    for (std::size_t j = 0; j < kMaxMessage; ++j) {
        uint8_t v = 0;
        const uint32_t src = one_pos + 1u + static_cast<uint32_t>(j);
        for (std::size_t i = kHashLen; i < kDbLen; ++i) {
            const uint32_t match = ct::eq(static_cast<uint32_t>(i), src);
            v = static_cast<uint8_t>(v | (match & db_[i]));
        }
        const uint32_t in_range = ct::lt(static_cast<uint32_t>(j), mlen);
        r.msg[j] = ct::select_u8(in_range & good, v, 0);
    }

    r.len = ct::select(good, mlen, 0);
    r.ok = good == 0xffffffffu;
    return r;
}

bool rsa_oaep_encrypt(const uint8_t* msg, std::size_t msg_len, const KeyPair& kp,
                      uint8_t ct[kModulusBytes]) {
    OaepEngine eng;
    uint8_t em[kModulusBytes];
    if (!eng.encode(msg, msg_len, em)) {
        return false;
    }
    BigInt m = BigInt::from_bytes_be(em, kModulusBytes);
    BigInt c = rsa_encrypt_raw(m, kp);
    c.to_bytes_be(ct, kModulusBytes);
    return true;
}

OaepResult rsa_oaep_decrypt(const uint8_t ct[kModulusBytes], const KeyPair& kp) {
    BigInt c = BigInt::from_bytes_be(ct, kModulusBytes);
    BigInt m = rsa_decrypt_crt(c, kp);
    uint8_t em[kModulusBytes];
    m.to_bytes_be(em, kModulusBytes);
    OaepEngine eng;
    return eng.decode(em);
}

}  
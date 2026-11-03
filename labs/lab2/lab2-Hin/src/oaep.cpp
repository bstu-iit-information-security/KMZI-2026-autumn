#include "oaep.hpp"

#include "sha256.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <cstring>

namespace {

void mgf1(const uint8_t* seed, std::size_t seed_len, uint8_t* out, std::size_t out_len) {
    uint32_t counter = 0;
    std::size_t done = 0;
    while (done < out_len) {
        const uint8_t block[4] = {
            static_cast<uint8_t>(counter >> 24),
            static_cast<uint8_t>(counter >> 16),
            static_cast<uint8_t>(counter >> 8),
            static_cast<uint8_t>(counter),
        };
        Sha256 hash;
        hash.update(seed, seed_len);
        hash.update(block, 4);
        uint8_t digest[Sha256::kDigestLen];
        hash.final(digest);
        std::size_t take = Sha256::kDigestLen;
        if (take > out_len - done) {
            take = out_len - done;
        }
        std::memcpy(out + done, digest, take);
        done += take;
        ++counter;
    }
}

uint32_t byte_equal(uint8_t value, uint8_t expected) {
    uint32_t diff = static_cast<uint32_t>(value ^ expected);
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    return (diff & 1u) ^ 1u;
}

bool fill_db(const uint8_t* message, std::size_t message_len, const uint8_t* label, std::size_t label_len,
             uint8_t db[Oaep::kDbLen]) {
    if (message_len > static_cast<std::size_t>(Oaep::kMaxMessage)) {
        return false;
    }
    if ((message == nullptr && message_len != 0) || (label == nullptr && label_len != 0)) {
        return false;
    }
    Sha256::hash(label, label_len, db);
    const std::size_t zeros = static_cast<std::size_t>(Oaep::kMaxMessage) - message_len;
    std::memset(db + Oaep::kHashLen, 0, zeros);
    db[Oaep::kHashLen + zeros] = 0x01;
    if (message_len > 0) {
        std::memcpy(db + Oaep::kHashLen + zeros + 1, message, message_len);
    }
    return true;
}

}

bool Oaep::encode_with_seed(const uint8_t* message, std::size_t message_len, const uint8_t* label,
                            std::size_t label_len, const uint8_t seed[kHashLen], uint8_t em[kModulusBytes]) {
    uint8_t db[kDbLen];
    if (!fill_db(message, message_len, label, label_len, db)) {
        return false;
    }
    uint8_t db_mask[kDbLen];
    mgf1(seed, kHashLen, db_mask, kDbLen);
    for (int i = 0; i < kDbLen; ++i) {
        db[i] = static_cast<uint8_t>(db[i] ^ db_mask[i]);
    }
    uint8_t seed_mask[kHashLen];
    mgf1(db, kDbLen, seed_mask, kHashLen);
    em[0] = 0x00;
    for (int i = 0; i < kHashLen; ++i) {
        em[1 + i] = static_cast<uint8_t>(seed[i] ^ seed_mask[i]);
    }
    std::memcpy(em + 1 + kHashLen, db, kDbLen);
    return true;
}

bool Oaep::encode(const uint8_t* message, std::size_t message_len, const uint8_t* label, std::size_t label_len,
                  uint8_t em[kModulusBytes]) {
    uint8_t seed[kHashLen];
    HCRYPTPROV provider = 0;
    if (!CryptAcquireContextA(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return false;
    }
    const BOOL random_ok = CryptGenRandom(provider, kHashLen, seed);
    CryptReleaseContext(provider, 0);
    if (random_ok != TRUE) {
        return false;
    }
    return encode_with_seed(message, message_len, label, label_len, seed, em);
}

bool Oaep::decode(const uint8_t em[kModulusBytes], const uint8_t* label, std::size_t label_len,
                  uint8_t message[kMaxMessage], std::size_t& message_len) {
    std::memset(message, 0, kMaxMessage);
    message_len = 0;
    if (label == nullptr && label_len != 0) {
        return false;
    }

    uint8_t lhash[kHashLen];
    Sha256::hash(label, label_len, lhash);

    const uint8_t* masked_seed = em + 1;
    const uint8_t* masked_db = em + 1 + kHashLen;
    uint8_t seed[kHashLen];
    uint8_t seed_mask[kHashLen];
    mgf1(masked_db, kDbLen, seed_mask, kHashLen);
    for (int i = 0; i < kHashLen; ++i) {
        seed[i] = static_cast<uint8_t>(masked_seed[i] ^ seed_mask[i]);
    }
    uint8_t db[kDbLen];
    uint8_t db_mask[kDbLen];
    mgf1(seed, kHashLen, db_mask, kDbLen);
    for (int i = 0; i < kDbLen; ++i) {
        db[i] = static_cast<uint8_t>(masked_db[i] ^ db_mask[i]);
    }

    uint32_t bad = em[0];
    for (int i = 0; i < kHashLen; ++i) {
        bad |= static_cast<uint32_t>(db[i] ^ lhash[i]);
    }

    std::size_t one_index = 0;
    uint32_t looking = 1;
    for (int i = kHashLen; i < kDbLen; ++i) {
        const uint32_t is_one = byte_equal(db[i], 0x01);
        const uint32_t is_zero = byte_equal(db[i], 0x00);
        const uint32_t found_here = looking & is_one;
        const std::size_t pick = static_cast<std::size_t>(0) - static_cast<std::size_t>(found_here);
        one_index = (static_cast<std::size_t>(i) & pick) | (one_index & ~pick);
        bad |= looking & (1u - is_one) & (1u - is_zero);
        looking &= 1u - is_one;
    }
    bad |= looking;

    const uint32_t good = bad == 0u ? 1u : 0u;
    const std::size_t msg_len = static_cast<std::size_t>(kDbLen) - one_index - 1;
    for (int i = 0; i < kMaxMessage; ++i) {
        const uint32_t in_message = static_cast<std::size_t>(i) < msg_len ? 1u : 0u;
        const uint32_t take = in_message & good;
        const std::size_t src = one_index + 1 + static_cast<std::size_t>(i);
        const uint32_t in_db = src < static_cast<std::size_t>(kDbLen) ? 1u : 0u;
        const std::size_t idx = src & (static_cast<std::size_t>(0) - static_cast<std::size_t>(in_db));
        const uint8_t mask = static_cast<uint8_t>(0u - take);
        message[i] = static_cast<uint8_t>(db[idx] & mask);
    }
    message_len = msg_len * good;
    return good == 1u;
}

#include "oaep.hpp"

#include "sha256.hpp"

#include <cstring>
#include <sys/random.h>

namespace {

uint32_t ct_is_zero_u8(uint8_t x) {
    uint32_t v = x;
    v |= v >> 4;
    v |= v >> 2;
    v |= v >> 1;
    return (v & 1u) ^ 1u;
}

uint32_t ct_is_zero_u32(uint32_t x) {
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    return (x & 1u) ^ 1u;
}

uint32_t ct_eq_u8(uint8_t a, uint8_t b) {
    return ct_is_zero_u8(static_cast<uint8_t>(a ^ b));
}

uint32_t ct_lt_size(std::size_t a, std::size_t b) {
    return static_cast<uint32_t>((static_cast<unsigned long long>(a) -
                                  static_cast<unsigned long long>(b)) >>
                                 63);
}

uint8_t mask8(uint32_t bit) {
    return static_cast<uint8_t>(-static_cast<int8_t>(bit & 1u));
}

void mgf1(const uint8_t* seed, std::size_t seed_len, uint8_t* out, std::size_t out_len) {
    uint32_t counter = 0;
    std::size_t done = 0;
    while (done < out_len) {
        uint8_t ctr[4] = {
            static_cast<uint8_t>(counter >> 24),
            static_cast<uint8_t>(counter >> 16),
            static_cast<uint8_t>(counter >> 8),
            static_cast<uint8_t>(counter),
        };
        Sha256 ctx;
        ctx.update(seed, seed_len);
        ctx.update(ctr, 4);
        uint8_t dig[Sha256::kDigestLen];
        ctx.final(dig);
        std::size_t n = Sha256::kDigestLen;
        if (n > out_len - done) {
            n = out_len - done;
        }
        std::memcpy(out + done, dig, n);
        done += n;
        ++counter;
    }
}

void secure_wipe(void* ptr, std::size_t n) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = 0;
    }
}

void xor_buf(uint8_t* dst, const uint8_t* src, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = static_cast<uint8_t>(dst[i] ^ src[i]);
    }
}

bool fill_db(const uint8_t* message, std::size_t message_len, const uint8_t* label,
             std::size_t label_len, uint8_t db[Oaep::kDbLen]) {
    if (message_len > static_cast<std::size_t>(Oaep::kMaxMessage)) {
        return false;
    }
    if ((message == nullptr && message_len != 0) || (label == nullptr && label_len != 0)) {
        return false;
    }
    uint8_t lhash[Oaep::kHashLen];
    Sha256::hash(label, label_len, lhash);
    std::memcpy(db, lhash, Oaep::kHashLen);
    const std::size_t ps_len = static_cast<std::size_t>(Oaep::kMaxMessage) - message_len;
    std::memset(db + Oaep::kHashLen, 0, ps_len);
    db[Oaep::kHashLen + ps_len] = 0x01;
    if (message_len > 0) {
        std::memcpy(db + Oaep::kHashLen + ps_len + 1, message, message_len);
    }
    secure_wipe(lhash, sizeof(lhash));
    return true;
}

void unmask(const std::array<uint8_t, Oaep::kModulusBytes>& em, uint8_t db[Oaep::kDbLen],
            uint8_t seed[Oaep::kHashLen]) {
    const uint8_t* masked_seed = em.data() + 1;
    const uint8_t* masked_db = em.data() + 1 + Oaep::kHashLen;

    uint8_t seed_mask[Oaep::kHashLen];
    mgf1(masked_db, Oaep::kDbLen, seed_mask, Oaep::kHashLen);
    for (int i = 0; i < Oaep::kHashLen; ++i) {
        seed[i] = static_cast<uint8_t>(masked_seed[i] ^ seed_mask[i]);
    }

    uint8_t db_mask[Oaep::kDbLen];
    mgf1(seed, Oaep::kHashLen, db_mask, Oaep::kDbLen);
    std::memcpy(db, masked_db, Oaep::kDbLen);
    xor_buf(db, db_mask, Oaep::kDbLen);
    secure_wipe(seed_mask, sizeof(seed_mask));
    secure_wipe(db_mask, sizeof(db_mask));
}

}

bool Oaep::encode_with_seed(const uint8_t* message, std::size_t message_len, const uint8_t* label,
                            std::size_t label_len, const uint8_t seed[kHashLen],
                            std::array<uint8_t, kModulusBytes>& em) {
    uint8_t db[kDbLen];
    if (!fill_db(message, message_len, label, label_len, db)) {
        return false;
    }

    uint8_t db_mask[kDbLen];
    mgf1(seed, kHashLen, db_mask, kDbLen);
    xor_buf(db, db_mask, kDbLen);

    uint8_t seed_mask[kHashLen];
    mgf1(db, kDbLen, seed_mask, kHashLen);

    em[0] = 0x00;
    for (int i = 0; i < kHashLen; ++i) {
        em[static_cast<std::size_t>(1 + i)] = static_cast<uint8_t>(seed[i] ^ seed_mask[i]);
    }
    std::memcpy(em.data() + 1 + kHashLen, db, kDbLen);

    secure_wipe(db, sizeof(db));
    secure_wipe(db_mask, sizeof(db_mask));
    secure_wipe(seed_mask, sizeof(seed_mask));
    return true;
}

bool Oaep::encode(const uint8_t* message, std::size_t message_len, const uint8_t* label,
                  std::size_t label_len, std::array<uint8_t, kModulusBytes>& em) {
    uint8_t seed[kHashLen];
    if (getentropy(seed, kHashLen) != 0) {
        return false;
    }
    const bool ok = encode_with_seed(message, message_len, label, label_len, seed, em);
    secure_wipe(seed, sizeof(seed));
    return ok;
}

bool Oaep::decode(const std::array<uint8_t, kModulusBytes>& em, const uint8_t* label,
                  std::size_t label_len, std::array<uint8_t, kMaxMessage>& message,
                  std::size_t& message_len) {
    if (label == nullptr && label_len != 0) {
        message.fill(0);
        message_len = 0;
        return false;
    }

    uint8_t lhash[kHashLen];
    Sha256::hash(label, label_len, lhash);

    uint8_t db[kDbLen];
    uint8_t seed[kHashLen];
    // MGF1 выполняется всегда, в том числе для заведомо битого EM.
    unmask(em, db, seed);

    uint32_t bad = em[0];
    for (int i = 0; i < kHashLen; ++i) {
        bad |= static_cast<uint32_t>(db[i] ^ lhash[i]);
    }

    // Безусловный поиск разделителя 0x01. looking остаётся 1, пока разделитель
    // не найден; после этого остальные байты — сообщение и не проверяются.
    std::size_t one_index = 0;
    uint32_t looking = 1;
    for (std::size_t i = static_cast<std::size_t>(kHashLen); i < static_cast<std::size_t>(kDbLen); ++i) {
        const uint32_t is_one = ct_eq_u8(db[i], 0x01);
        const uint32_t is_zero = ct_eq_u8(db[i], 0x00);
        const uint32_t found_here = looking & is_one;
        const std::size_t pick = 0ull - static_cast<std::size_t>(found_here);
        one_index = (i & pick) | (one_index & ~pick);
        looking = looking & (1u - is_one);
        bad |= looking & (1u - is_zero);
    }
    bad |= looking;

    // 1 только если ни одна проверка не взвела аккумулятор. Без ветвления.
    const uint32_t good_bit = ct_is_zero_u32(bad);

    const std::size_t msg_len = static_cast<std::size_t>(kDbLen) - one_index - 1;
    for (std::size_t i = 0; i < static_cast<std::size_t>(kMaxMessage); ++i) {
        const uint32_t take = ct_lt_size(i, msg_len) & good_bit;
        const std::size_t src = one_index + 1 + i;
        const uint32_t in_range = ct_lt_size(src, static_cast<std::size_t>(kDbLen));
        const std::size_t idx = src & (0ull - static_cast<std::size_t>(in_range));
        message[i] = static_cast<uint8_t>(db[idx] & mask8(take));
    }
    message_len = msg_len * good_bit;

    secure_wipe(lhash, sizeof(lhash));
    secure_wipe(db, sizeof(db));
    secure_wipe(seed, sizeof(seed));
    return good_bit == 1u;
}

bool Oaep::decode_variable_time(const std::array<uint8_t, kModulusBytes>& em, const uint8_t* label,
                                std::size_t label_len, std::array<uint8_t, kMaxMessage>& message,
                                std::size_t& message_len) {
    message.fill(0);
    message_len = 0;
    if (em[0] != 0x00) {
        return false;
    }

    uint8_t lhash[kHashLen];
    Sha256::hash(label, label_len, lhash);
    uint8_t db[kDbLen];
    uint8_t seed[kHashLen];
    unmask(em, db, seed);

    if (std::memcmp(db, lhash, kHashLen) != 0) {
        secure_wipe(lhash, sizeof(lhash));
        secure_wipe(db, sizeof(db));
        secure_wipe(seed, sizeof(seed));
        return false;
    }

    std::size_t i = static_cast<std::size_t>(kHashLen);
    for (; i < static_cast<std::size_t>(kDbLen); ++i) {
        if (db[i] == 0x00) {
            continue;
        }
        if (db[i] != 0x01) {
            secure_wipe(lhash, sizeof(lhash));
            secure_wipe(db, sizeof(db));
            secure_wipe(seed, sizeof(seed));
            return false;
        }
        break;
    }
    if (i >= static_cast<std::size_t>(kDbLen) || db[i] != 0x01) {
        secure_wipe(lhash, sizeof(lhash));
        secure_wipe(db, sizeof(db));
        secure_wipe(seed, sizeof(seed));
        return false;
    }
    const std::size_t msg_len = static_cast<std::size_t>(kDbLen) - (i + 1);
    if (msg_len > static_cast<std::size_t>(kMaxMessage)) {
        secure_wipe(lhash, sizeof(lhash));
        secure_wipe(db, sizeof(db));
        secure_wipe(seed, sizeof(seed));
        return false;
    }
    if (msg_len > 0) {
        std::memcpy(message.data(), db + i + 1, msg_len);
    }
    message_len = msg_len;
    secure_wipe(lhash, sizeof(lhash));
    secure_wipe(db, sizeof(db));
    secure_wipe(seed, sizeof(seed));
    return true;
}

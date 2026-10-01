#pragma once
#include "sha512.h"
#include "bigint.h"
#include "rsa_crt.h"
#include <array>
#include <random>
#include <cstring>
#include <algorithm>

constexpr size_t HLEN = 64; // SHA-512
constexpr size_t DB_LEN = RSA_KEY_BYTES - HLEN - 1;
constexpr size_t MAX_MSG_LEN = RSA_KEY_BYTES - 2 * HLEN - 2;

// === MGF1 с фиксированными буферами (без heap-аллокаций) ===
inline void mgf1_sha512(const uint8_t* seed, size_t seed_len,
                        uint8_t* mask, size_t mask_len) {
    static constexpr size_t MAX_SEED = HLEN;
    std::array<uint8_t, MAX_SEED + 4> temp_buf{};
    std::memcpy(temp_buf.data(), seed, seed_len);

    uint8_t hash_buf[HLEN];
    size_t generated = 0;
    uint32_t counter = 0;
    while (generated < mask_len) {
        temp_buf[seed_len + 0] = static_cast<uint8_t>((counter >> 24) & 0xFF);
        temp_buf[seed_len + 1] = static_cast<uint8_t>((counter >> 16) & 0xFF);
        temp_buf[seed_len + 2] = static_cast<uint8_t>((counter >> 8) & 0xFF);
        temp_buf[seed_len + 3] = static_cast<uint8_t>(counter & 0xFF);
        SHA512::hash(temp_buf.data(), seed_len + 4, hash_buf);
        size_t to_copy = std::min(HLEN, mask_len - generated);
        std::memcpy(mask + generated, hash_buf, to_copy);
        generated += to_copy;
        counter++;
    }
}

// === OAEP encode: все буферы — фиксированные std::array ===
inline bool oaep_encode(const uint8_t* msg, size_t msg_len,
                        uint8_t* em, std::mt19937_64& rng) {
    if (msg_len > MAX_MSG_LEN) return false;

    uint8_t lHash[HLEN];
    static const uint8_t empty_label[1] = {0};
    SHA512::hash(empty_label, 0, lHash);

    // DB = lHash || PS || 0x01 || M
    std::array<uint8_t, DB_LEN> db{};
    std::memcpy(db.data(), lHash, HLEN);
    size_t ps_len = DB_LEN - HLEN - 1 - msg_len;
    db[HLEN + ps_len] = 0x01;
    std::memcpy(db.data() + HLEN + ps_len + 1, msg, msg_len);

    // seed
    std::array<uint8_t, HLEN> seed{};
    for (size_t i = 0; i < HLEN; ++i) seed[i] = static_cast<uint8_t>(rng() & 0xFF);

    // maskedDB = DB ^ MGF1(seed, DB_LEN)
    std::array<uint8_t, DB_LEN> dbMask{};
    mgf1_sha512(seed.data(), HLEN, dbMask.data(), DB_LEN);
    uint8_t* maskedDB = em + 1 + HLEN;
    for (size_t i = 0; i < DB_LEN; ++i) maskedDB[i] = db[i] ^ dbMask[i];

    // maskedSeed = seed ^ MGF1(maskedDB, HLEN)
    std::array<uint8_t, HLEN> seedMask{};
    mgf1_sha512(maskedDB, DB_LEN, seedMask.data(), HLEN);
    uint8_t* maskedSeed = em + 1;
    for (size_t i = 0; i < HLEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    em[0] = 0x00;
    return true;
}

// === OAEP decode: constant-time, без early exit, фиксированные буферы ===
inline bool oaep_decode_constant_time(const uint8_t* em,
                                      uint8_t* out_msg, size_t& out_msg_len) {
    uint8_t lHash[HLEN];
    static const uint8_t empty_label[1] = {0};
    SHA512::hash(empty_label, 0, lHash);

    const uint8_t* maskedSeed = em + 1;
    const uint8_t* maskedDB   = em + 1 + HLEN;

    // seed = maskedSeed ^ MGF1(maskedDB, HLEN)
    std::array<uint8_t, HLEN> seedMask{};
    mgf1_sha512(maskedDB, DB_LEN, seedMask.data(), HLEN);
    std::array<uint8_t, HLEN> seed{};
    for (size_t i = 0; i < HLEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    // DB = maskedDB ^ MGF1(seed, DB_LEN)
    std::array<uint8_t, DB_LEN> dbMask{};
    mgf1_sha512(seed.data(), HLEN, dbMask.data(), DB_LEN);
    std::array<uint8_t, DB_LEN> db{};
    for (size_t i = 0; i < DB_LEN; ++i) db[i] = maskedDB[i] ^ dbMask[i];

    // Аккумулятор ошибки (constant-time)
    uint8_t error_mask = em[0]; // должен быть 0x00
    for (size_t i = 0; i < HLEN; ++i) error_mask |= (db[i] ^ lHash[i]);

    // Поиск разделителя 0x01 (constant-time)
    size_t one_pos = 0;
    uint8_t found_one = 0;
    uint8_t bad_ps = 0;
    for (size_t i = HLEN; i < DB_LEN; ++i) {
        uint8_t is_one  = (db[i] == 0x01) ? 1 : 0;
        uint8_t is_zero = (db[i] == 0x00) ? 1 : 0;
        uint8_t before  = static_cast<uint8_t>(~found_one & 1);
        // до разделителя допустимы только 0x00
        bad_ps |= static_cast<uint8_t>(before & ~is_zero & ~is_one);
        one_pos |= i & static_cast<size_t>(is_one & before);
        found_one |= is_one;
    }
    error_mask |= bad_ps;
    error_mask |= static_cast<uint8_t>(found_one ^ 1);

    size_t msg_start = one_pos + 1;
    size_t extracted_len = (DB_LEN > msg_start) ? (DB_LEN - msg_start) : 0;
    if (extracted_len > MAX_MSG_LEN) extracted_len = MAX_MSG_LEN;

    // === ИСПРАВЛЕНО: ограничение размера вывода ===
    // Записываем всегда MAX_MSG_LEN байт (безусловно), маскируя ошибки.
    uint8_t ok = static_cast<uint8_t>(error_mask == 0 ? 1 : 0);
    uint8_t ok_mask = static_cast<uint8_t>(0) - ok;

    for (size_t i = 0; i < MAX_MSG_LEN; ++i) {
        size_t db_idx = msg_start + i;
        uint8_t byte = (db_idx < DB_LEN) ? db[db_idx] : 0;
        uint8_t len_mask = (i < extracted_len) ? 0xFF : 0x00;
        out_msg[i] = static_cast<uint8_t>(byte & len_mask & ok_mask);
    }

    out_msg_len = ok ? extracted_len : 0;
    return ok != 0;
}
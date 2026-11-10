#include "oaep.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "ct_utils.hpp"
#include "sha256.hpp"

namespace oaep {

// ---------------------------------------------------------------------------
// MGF1. Число итераций зависит только от ПУБЛИЧНЫХ длин, обращения к массивам --
// последовательные, индексы не зависят от секретных значений.
// ---------------------------------------------------------------------------
void mgf1_sha256(const uint8_t* z, size_t z_len, uint8_t* mask, size_t mask_len) {
    uint8_t block[sha::SHA256_LEN];
    uint32_t counter = 0;
    size_t pos = 0;
    while (pos < mask_len) {
        uint8_t c[4] = {static_cast<uint8_t>(counter >> 24), static_cast<uint8_t>(counter >> 16),
                        static_cast<uint8_t>(counter >> 8), static_cast<uint8_t>(counter)};
        sha::Sha256 h;
        h.update(z, z_len);
        h.update(c, 4);
        h.finish(block);
        size_t take = mask_len - pos;
        if (take > sha::SHA256_LEN) take = sha::SHA256_LEN;
        for (size_t i = 0; i < take; ++i) mask[pos + i] = block[i];
        pos += take;
        ++counter;
    }
    ct::secure_zero(block, sizeof(block));
}

// ---------------------------------------------------------------------------
// Упаковка
//   DB = lHash || PS(0x00...) || 0x01 || M
//   EM = 0x00 || (seed xor MGF(maskedDB)) || (DB xor MGF(seed))
// ---------------------------------------------------------------------------
int encode_with_seed(uint8_t em[K], const uint8_t* msg, size_t msg_len,
                     const uint8_t* label, size_t label_len,
                     const uint8_t seed[HLEN]) {
    if (msg_len > MAX_MSG) return -1;  // длина публична

    uint8_t db[DBLEN];
    uint8_t db_mask[DBLEN];
    uint8_t seed_mask[HLEN];

    // lHash = Hash(label)
    sha::sha256(label, label_len, db);  // пишем сразу в начало DB
    // PS: нули, длина k - len(M) - 2*hLen - 2
    const size_t ps_len = K - msg_len - 2 * HLEN - 2;
    std::memset(db + HLEN, 0x00, ps_len);
    db[HLEN + ps_len] = 0x01;
    if (msg_len) std::memcpy(db + HLEN + ps_len + 1, msg, msg_len);

    // maskedDB = DB xor MGF1(seed, k-hLen-1)
    mgf1_sha256(seed, HLEN, db_mask, DBLEN);
    for (size_t i = 0; i < DBLEN; ++i) db[i] ^= db_mask[i];

    // maskedSeed = seed xor MGF1(maskedDB, hLen)
    mgf1_sha256(db, DBLEN, seed_mask, HLEN);

    em[0] = 0x00;
    for (size_t i = 0; i < HLEN; ++i) em[1 + i] = seed[i] ^ seed_mask[i];
    std::memcpy(em + 1 + HLEN, db, DBLEN);

    ct::secure_zero(db_mask, sizeof(db_mask));
    ct::secure_zero(seed_mask, sizeof(seed_mask));
    ct::secure_zero(db, sizeof(db));
    return 0;
}

int encode(uint8_t em[K], const uint8_t* msg, size_t msg_len,
           const uint8_t* label, size_t label_len) {
    uint8_t seed[HLEN];
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) throw std::runtime_error("cannot open /dev/urandom");
    size_t got = std::fread(seed, 1, HLEN, f);
    std::fclose(f);
    if (got != HLEN) throw std::runtime_error("short read from /dev/urandom");
    int rc = encode_with_seed(em, msg, msg_len, label, label_len, seed);
    ct::secure_zero(seed, sizeof(seed));
    return rc;
}

// ---------------------------------------------------------------------------
// Распаковка: CONSTANT-TIME, без раннего выхода.
//
// Идея: любая проблема не вызывает `return`, а лишь "пачкает" аккумулятор
// ошибки `bad` (|= / XOR). Выполняются ВСЕ шаги, независимо от того, валиден
// EM или нет. Единственное решение (успех/ошибка) принимается в самом конце
// арифметикой, а не ветвлением.
// ---------------------------------------------------------------------------
int decode(uint8_t* out, size_t* out_len, const uint8_t em[K],
           const uint8_t* label, size_t label_len) {
    uint8_t lhash[HLEN];
    sha::sha256(label, label_len, lhash);

    // 1) Первый байт EM обязан быть 0x00.
    uint32_t bad = em[0];

    const uint8_t* masked_seed = em + 1;
    const uint8_t* masked_db = em + 1 + HLEN;

    // 2) Снимаем маски (всегда, даже если EM уже "битый")
    uint8_t seed_mask[HLEN], seed[HLEN], db_mask[DBLEN], db[DBLEN];
    mgf1_sha256(masked_db, DBLEN, seed_mask, HLEN);
    for (size_t i = 0; i < HLEN; ++i) seed[i] = masked_seed[i] ^ seed_mask[i];
    mgf1_sha256(seed, HLEN, db_mask, DBLEN);
    for (size_t i = 0; i < DBLEN; ++i) db[i] = masked_db[i] ^ db_mask[i];

    // 3) Сравнение lHash: XOR-аккумулятор по ВСЕМ 32 байтам, без раннего выхода.
    uint32_t diff = 0;
    for (size_t i = 0; i < HLEN; ++i) diff |= static_cast<uint32_t>(db[i] ^ lhash[i]);
    bad |= diff;

    // 4) Безусловный поиск разделителя 0x01 после PS (нулей).
    //    looking = "ещё читаем PS". Первый ненулевой байт должен быть 0x01.
    uint32_t looking = 0xFFFFFFFFu;
    uint32_t idx = 0;
    for (size_t i = HLEN; i < DBLEN; ++i) {
        const uint32_t b = db[i];
        const uint32_t is0 = ct::eq_mask(b, 0x00);
        const uint32_t is1 = ct::eq_mask(b, 0x01);
        const uint32_t found_now = looking & is1;
        idx = ct::select(found_now, static_cast<uint32_t>(i), idx);
        bad |= looking & ~(is0 | is1);  // ненулевой и не 0x01 -- ошибка
        looking &= is0;                 // остановились на первом ненулевом
    }
    bad |= looking;  // looking всё ещё "истина" => разделителя нет

    const uint32_t valid = ct::zero_mask(bad);  // все единицы <=> ошибок нет

    // 5) Безопасное извлечение M: сдвигаем DB влево на (idx+1) байт
    //    последовательностью условных сдвигов 256,128,...,1 (по маске).
    const uint32_t start = ct::select(valid, idx + 1, static_cast<uint32_t>(DBLEN));
    const uint32_t mlen = static_cast<uint32_t>(DBLEN) - start;  // 0 при ошибке

    uint8_t tmp[DBLEN];
    for (uint32_t s = 256; s >= 1; s >>= 1) {
        const uint32_t m = ct::nonzero_mask(start & s);
        for (size_t i = 0; i < DBLEN; ++i) {
            const uint32_t shifted = (i + s < DBLEN) ? db[i + s] : 0u;  // условие по ПУБЛИЧНОМУ i
            tmp[i] = static_cast<uint8_t>(ct::select(m, shifted, db[i]));
        }
        std::memcpy(db, tmp, DBLEN);
    }

    // 6) Копируем в выход ровно MAX_MSG байт; байты за пределами mlen и всё при
    //    ошибке зануляются маской (никаких ветвлений).
    for (size_t j = 0; j < MAX_MSG; ++j) {
        const uint32_t keep = valid & ct::lt_mask(static_cast<uint32_t>(j), mlen);
        out[j] = static_cast<uint8_t>(db[j] & keep);
    }
    *out_len = static_cast<size_t>(mlen & valid);

    ct::secure_zero(seed_mask, sizeof(seed_mask));
    ct::secure_zero(seed, sizeof(seed));
    ct::secure_zero(db_mask, sizeof(db_mask));
    ct::secure_zero(db, sizeof(db));
    ct::secure_zero(tmp, sizeof(tmp));

    // Итог: valid = 0xFFFFFFFF -> 0,  valid = 0 -> -1  (арифметика, не `if`)
    return static_cast<int>(valid & 1u) - 1;
}

}  // namespace oaep

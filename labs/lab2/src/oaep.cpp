#include "oaep.hpp"
#include "sha512.hpp"
#include "random.hpp"
#include "ct.hpp"
#include <cstring>

namespace oaep {

void mgf1(const uint8_t* z, size_t zlen, uint8_t* out, size_t outlen) {
    uint8_t h[Sha512::DIGEST];
    uint32_t counter = 0;
    for (size_t off = 0; off < outlen; off += Sha512::DIGEST, ++counter) {
        Sha512 s;
        s.update(z, zlen);
        const uint8_t c[4] = {uint8_t(counter >> 24), uint8_t(counter >> 16),
                              uint8_t(counter >> 8),  uint8_t(counter)};
        s.update(c, 4);
        s.final(h);
        size_t n = outlen - off < Sha512::DIGEST ? outlen - off : Sha512::DIGEST;
        std::memcpy(out + off, h, n);
    }
    ct::secure_zero(h, sizeof h);
}

bool encode(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen,
            const uint8_t seed[HLEN], uint8_t em[K]) {
    if (mlen > MAX_MSG) return false;
    uint8_t db[DB_LEN], mask[DB_LEN], seedMask[HLEN];

    Sha512::hash(label, llen, db);                                   // lHash
    const size_t ps = DB_LEN - HLEN - 1 - mlen;                      // = k - mLen - 2hLen - 2
    std::memset(db + HLEN, 0x00, ps);                                // PS
    db[HLEN + ps] = 0x01;
    if (mlen) std::memcpy(db + HLEN + ps + 1, msg, mlen);

    mgf1(seed, HLEN, mask, DB_LEN);                                  // dbMask
    for (size_t i = 0; i < DB_LEN; ++i) db[i] ^= mask[i];            // maskedDB
    mgf1(db, DB_LEN, seedMask, HLEN);                                // seedMask
    em[0] = 0x00;
    for (size_t i = 0; i < HLEN; ++i) em[1 + i] = seed[i] ^ seedMask[i];   // maskedSeed
    std::memcpy(em + 1 + HLEN, db, DB_LEN);

    ct::secure_zero(db, sizeof db); ct::secure_zero(mask, sizeof mask); ct::secure_zero(seedMask, sizeof seedMask);
    return true;
}

uint32_t decode(const uint8_t em[K], const uint8_t* label, size_t llen,
                uint8_t out[MAX_MSG], size_t* outlen) {
    uint8_t seed[HLEN], seedMask[HLEN], db[DB_LEN], mask[DB_LEN], lhash[HLEN];
    uint8_t buf_a[DB_LEN], buf_b[DB_LEN];

    Sha512::hash(label, llen, lhash);

    // seed = maskedSeed ^ MGF1(maskedDB); DB = maskedDB ^ MGF1(seed). Выполняется всегда.
    mgf1(em + 1 + HLEN, DB_LEN, seedMask, HLEN);
    for (size_t i = 0; i < HLEN; ++i) seed[i] = em[1 + i] ^ seedMask[i];
    mgf1(seed, HLEN, mask, DB_LEN);
    for (size_t i = 0; i < DB_LEN; ++i) db[i] = em[1 + HLEN + i] ^ mask[i];

    // Аккумулятор ошибок: XOR/OR всех отклонений, ни одной ранней ветки.
    uint32_t err = em[0];                                            // Y должен быть 0x00
    for (size_t i = 0; i < HLEN; ++i) err |= uint32_t(db[i] ^ lhash[i]);   // lHash' == lHash
    uint32_t bad = ct::nonzero_mask(err);

    // Безусловный поиск разделителя 0x01 в DB[HLEN..]: все байты PS обязаны быть 0x00
    uint32_t found = 0, idx = 0;
    for (size_t i = HLEN; i < DB_LEN; ++i) {
        uint32_t b = db[i];
        uint32_t is_one  = ct::eq_mask(b, 1u);
        uint32_t is_zero = ct::eq_mask(b, 0u);
        uint32_t first   = is_one & ~found;
        idx  = ct::select(first, uint32_t(i), idx);
        bad |= ~found & ~is_one & ~is_zero;                          // мусор в PS до разделителя
        found |= is_one;
    }
    bad |= ~found;                                                   // разделителя нет
    const uint32_t good = ~bad;

    // Безопасный перенос: сдвиг DB влево на (idx+1) байт ступенями по битам сдвига (9 ступеней, фикс. доступ к памяти)
    std::memcpy(buf_a, db, DB_LEN);
    const uint32_t shift = idx + 1;
    uint8_t* cur = buf_a; uint8_t* nxt = buf_b;
    for (unsigned t = 0; t < 9; ++t) {
        const size_t   step = size_t(1) << t;
        const uint32_t bit  = 0u - ((shift >> t) & 1u);
        for (size_t i = 0; i < DB_LEN; ++i) {
            uint32_t moved = (i + step < DB_LEN) ? cur[i + step] : 0u;   // условие на публичном индексе
            nxt[i] = static_cast<uint8_t>(ct::select(bit, moved, cur[i]));
        }
        uint8_t* tmp = cur; cur = nxt; nxt = tmp;
    }
    const uint32_t mlen = uint32_t(DB_LEN) - shift;                  // валидна только при good
    for (size_t j = 0; j < MAX_MSG; ++j) {
        uint32_t keep = ct::lt_mask(uint32_t(j), mlen) & good;
        out[j] = static_cast<uint8_t>(cur[j] & keep);
    }
    *outlen = ct::select(good, mlen, 0u);

    ct::secure_zero(seed, sizeof seed); ct::secure_zero(seedMask, sizeof seedMask);
    ct::secure_zero(db, sizeof db);     ct::secure_zero(mask, sizeof mask);
    ct::secure_zero(buf_a, sizeof buf_a); ct::secure_zero(buf_b, sizeof buf_b);
    return good & 1u;
}

bool encrypt(const PublicKey& pub, const uint8_t* msg, size_t mlen,
             const uint8_t* label, size_t llen, uint8_t ct_out[K]) {
    uint8_t seed[HLEN], em[K];
    random_bytes(seed, HLEN);
    if (!encode(msg, mlen, label, llen, seed, em)) return false;
    BigInt m, c;
    rsa::bytes_to_int(m, em, K);
    rsa::encrypt_raw(c, m, pub);
    rsa::int_to_bytes(c, ct_out, K);
    ct::secure_zero(seed, sizeof seed); ct::secure_zero(em, sizeof em);
    return true;
}

bool decrypt(const PrivateKey& prv, const uint8_t ct_in[K],
             const uint8_t* label, size_t llen, uint8_t out[MAX_MSG], size_t* outlen) {
    BigInt c, m;
    rsa::bytes_to_int(c, ct_in, K);
    *outlen = 0; std::memset(out, 0, MAX_MSG);
    if (mpz_cmp(c.get(), prv.n.get()) >= 0) return false;            // c >= N: публичная проверка
    rsa::decrypt_crt(m, c, prv);
    uint8_t em[K];
    rsa::int_to_bytes(m, em, K);
    uint32_t ok = decode(em, label, llen, out, outlen);
    ct::secure_zero(em, sizeof em);
    return ok != 0;                                                  // единый признак ошибки наружу
}

} // namespace oaep

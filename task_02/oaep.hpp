#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "sha3.hpp"
#include "rsa_core.hpp"

namespace oaep {

constexpr std::size_t K = 384;
constexpr std::size_t HLEN = 32;
constexpr std::size_t MAXMSG = K - 2 * HLEN - 2;
constexpr std::size_t DBLEN = K - HLEN - 1;

inline void secure_zero(void* p, std::size_t n) {
    volatile std::uint8_t* v = static_cast<volatile std::uint8_t*>(p);
    for (std::size_t i = 0; i < n; ++i) v[i] = 0;
}

inline std::uint32_t ct_mask_nonzero(std::uint32_t x) {
    return 0u - ((x | (0u - x)) >> 31);
}

inline std::uint32_t ct_mask_zero(std::uint32_t x) {
    return ~ct_mask_nonzero(x);
}

inline std::uint32_t ct_eq_mask(std::uint32_t a, std::uint32_t b) {
    return ct_mask_zero(a ^ b);
}

inline void mgf1(std::uint8_t* out, std::size_t olen, const std::uint8_t* z, std::size_t zlen) {
    std::uint8_t buf[DBLEN + 4];
    std::uint8_t digest[sha3::DIGEST];
    std::memcpy(buf, z, zlen);
    std::size_t produced = 0;
    for (std::uint32_t counter = 0; produced < olen; ++counter) {
        buf[zlen] = (std::uint8_t)(counter >> 24);
        buf[zlen + 1] = (std::uint8_t)(counter >> 16);
        buf[zlen + 2] = (std::uint8_t)(counter >> 8);
        buf[zlen + 3] = (std::uint8_t)counter;
        sha3::sha3_256(digest, buf, zlen + 4);
        std::size_t n = olen - produced < HLEN ? olen - produced : HLEN;
        std::memcpy(out + produced, digest, n);
        produced += n;
    }
    secure_zero(digest, sizeof(digest));
}

inline bool oaep_encode(std::uint8_t em[K], const std::uint8_t* msg, std::size_t mlen,
                        const std::uint8_t seed[HLEN]) {
    if (mlen > MAXMSG) return false;
    std::uint8_t db[DBLEN];
    std::uint8_t db_mask[DBLEN];
    std::uint8_t seed_mask[HLEN];
    sha3::sha3_256(db, nullptr, 0);
    std::size_t ps = MAXMSG - mlen;
    std::memset(db + HLEN, 0, ps);
    db[HLEN + ps] = 0x01;
    if (mlen != 0) std::memcpy(db + HLEN + ps + 1, msg, mlen);
    mgf1(db_mask, DBLEN, seed, HLEN);
    for (std::size_t i = 0; i < DBLEN; ++i) db[i] ^= db_mask[i];
    mgf1(seed_mask, HLEN, db, DBLEN);
    em[0] = 0x00;
    for (std::size_t i = 0; i < HLEN; ++i) em[1 + i] = seed[i] ^ seed_mask[i];
    std::memcpy(em + 1 + HLEN, db, DBLEN);
    secure_zero(db, sizeof(db));
    secure_zero(db_mask, sizeof(db_mask));
    secure_zero(seed_mask, sizeof(seed_mask));
    return true;
}

inline bool oaep_decode(std::uint8_t out[MAXMSG], std::size_t& outlen, const std::uint8_t em[K]) {
    std::uint8_t lhash[HLEN];
    std::uint8_t seed[HLEN];
    std::uint8_t seed_mask[HLEN];
    std::uint8_t db[DBLEN];
    std::uint8_t db_mask[DBLEN];
    sha3::sha3_256(lhash, nullptr, 0);
    const std::uint8_t* masked_seed = em + 1;
    const std::uint8_t* masked_db = em + 1 + HLEN;
    mgf1(seed_mask, HLEN, masked_db, DBLEN);
    for (std::size_t i = 0; i < HLEN; ++i) seed[i] = masked_seed[i] ^ seed_mask[i];
    mgf1(db_mask, DBLEN, seed, HLEN);
    for (std::size_t i = 0; i < DBLEN; ++i) db[i] = masked_db[i] ^ db_mask[i];
    std::uint32_t bad = em[0];
    for (std::size_t i = 0; i < HLEN; ++i) bad |= (std::uint32_t)(db[i] ^ lhash[i]);
    std::uint32_t found = 0;
    std::uint32_t idx = 0;
    for (std::size_t i = HLEN; i < DBLEN; ++i) {
        std::uint32_t b = db[i];
        std::uint32_t not_found = ~found;
        std::uint32_t is_one = ct_eq_mask(b, 1);
        std::uint32_t is_zero = ct_mask_zero(b);
        std::uint32_t first = is_one & not_found;
        bad |= (not_found & ~is_one & ~is_zero) & 1u;
        idx = (first & (std::uint32_t)(i + 1)) | (~first & idx);
        found |= first;
    }
    bad |= ~found & 1u;
    std::uint32_t good = ct_mask_zero(bad);
    for (std::size_t j = 0; j < MAXMSG; ++j) out[j] = 0;
    for (std::size_t s = HLEN + 1; s <= DBLEN; ++s) {
        std::uint32_t m = ct_eq_mask((std::uint32_t)s, idx);
        for (std::size_t j = 0; j < MAXMSG; ++j) {
            std::size_t pos = s + j;
            std::uint32_t byte = pos < DBLEN ? db[pos] : 0u;
            out[j] |= (std::uint8_t)(m & byte);
        }
    }
    for (std::size_t j = 0; j < MAXMSG; ++j) out[j] &= (std::uint8_t)good;
    outlen = (std::size_t)((std::uint32_t)(DBLEN - idx) & good);
    secure_zero(seed, sizeof(seed));
    secure_zero(seed_mask, sizeof(seed_mask));
    secure_zero(db, sizeof(db));
    secure_zero(db_mask, sizeof(db_mask));
    return (good & 1u) != 0;
}

inline bool oaep_encrypt(std::uint8_t ct[K], const std::uint8_t* msg, std::size_t mlen,
                         const rsa::PublicKey& pub) {
    std::uint8_t seed[HLEN];
    std::uint8_t em[K];
    rsa::random_bytes(seed, HLEN);
    if (!oaep_encode(em, msg, mlen, seed)) return false;
    bn::Big m, c;
    bn::from_bytes_be(m, em, K);
    bool ok = rsa::rsa_encrypt(c, m, pub);
    if (ok) bn::to_bytes_be(c, ct, K);
    secure_zero(seed, sizeof(seed));
    secure_zero(em, sizeof(em));
    return ok;
}

inline bool oaep_decrypt(std::uint8_t out[MAXMSG], std::size_t& outlen, const std::uint8_t ct[K],
                         const rsa::PrivateKey& prv) {
    std::uint8_t em[K];
    bn::Big c, m;
    bn::from_bytes_be(c, ct, K);
    if (!rsa::rsa_decrypt_blinded(m, c, prv)) return false;
    bn::to_bytes_be(m, em, K);
    bool ok = oaep_decode(out, outlen, em);
    secure_zero(em, sizeof(em));
    return ok;
}

}

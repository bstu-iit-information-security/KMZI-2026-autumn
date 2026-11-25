#include "oaep.hpp"
#include "ct.hpp"
#include "rng.hpp"
#include <cstring>

namespace {

constexpr size_t MGF_MAX_SEED = 256;

void mgf1(const uint8_t* seed, size_t seed_len, uint8_t* out, size_t out_len)
{
    uint8_t buf[MGF_MAX_SEED + 4];
    uint8_t digest[SHA256_DIGEST_SIZE];
    std::memcpy(buf, seed, seed_len);
    size_t produced = 0;
    for (uint32_t counter = 0; produced < out_len; counter++) {
        buf[seed_len] = static_cast<uint8_t>(counter >> 24);
        buf[seed_len + 1] = static_cast<uint8_t>(counter >> 16);
        buf[seed_len + 2] = static_cast<uint8_t>(counter >> 8);
        buf[seed_len + 3] = static_cast<uint8_t>(counter);
        sha256(buf, seed_len + 4, digest);
        size_t take = out_len - produced;
        if (take > SHA256_DIGEST_SIZE) {
            take = SHA256_DIGEST_SIZE;
        }
        std::memcpy(out + produced, digest, take);
        produced += take;
    }
    secure_zero(digest, sizeof(digest));
}

}

void oaep_encode(const uint8_t db[OAEP_DBLEN], const uint8_t seed[OAEP_HLEN], uint8_t em[OAEP_K])
{
    uint8_t db_mask[OAEP_DBLEN];
    uint8_t masked_db[OAEP_DBLEN];
    uint8_t seed_mask[OAEP_HLEN];
    mgf1(seed, OAEP_HLEN, db_mask, OAEP_DBLEN);
    for (size_t i = 0; i < OAEP_DBLEN; i++) {
        masked_db[i] = static_cast<uint8_t>(db[i] ^ db_mask[i]);
    }
    mgf1(masked_db, OAEP_DBLEN, seed_mask, OAEP_HLEN);
    em[0] = 0x00;
    for (size_t i = 0; i < OAEP_HLEN; i++) {
        em[1 + i] = static_cast<uint8_t>(seed[i] ^ seed_mask[i]);
    }
    std::memcpy(em + 1 + OAEP_HLEN, masked_db, OAEP_DBLEN);
    secure_zero(db_mask, sizeof(db_mask));
    secure_zero(seed_mask, sizeof(seed_mask));
}

bool oaep_pad(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen, uint8_t em[OAEP_K])
{
    if (mlen > OAEP_MAX_MSG) {
        return false;
    }
    uint8_t db[OAEP_DBLEN];
    uint8_t seed[OAEP_HLEN];
    std::memset(db, 0, sizeof(db));
    sha256(label, llen, db);
    size_t ps_len = OAEP_MAX_MSG - mlen;
    db[OAEP_HLEN + ps_len] = 0x01;
    if (mlen > 0) {
        std::memcpy(db + OAEP_HLEN + ps_len + 1, msg, mlen);
    }
    random_bytes(seed, OAEP_HLEN);
    oaep_encode(db, seed, em);
    secure_zero(db, sizeof(db));
    secure_zero(seed, sizeof(seed));
    return true;
}

void oaep_unpad(const uint8_t em[OAEP_K], const uint8_t* label, size_t llen, OaepResult& out)
{
    uint8_t lhash[OAEP_HLEN];
    uint8_t seed[OAEP_HLEN];
    uint8_t seed_mask[OAEP_HLEN];
    uint8_t db[OAEP_DBLEN];
    uint8_t db_mask[OAEP_DBLEN];
    const uint8_t* masked_seed = em + 1;
    const uint8_t* masked_db = em + 1 + OAEP_HLEN;

    sha256(label, llen, lhash);
    mgf1(masked_db, OAEP_DBLEN, seed_mask, OAEP_HLEN);
    for (size_t i = 0; i < OAEP_HLEN; i++) {
        seed[i] = static_cast<uint8_t>(masked_seed[i] ^ seed_mask[i]);
    }
    mgf1(seed, OAEP_HLEN, db_mask, OAEP_DBLEN);
    for (size_t i = 0; i < OAEP_DBLEN; i++) {
        db[i] = static_cast<uint8_t>(masked_db[i] ^ db_mask[i]);
    }

    uint32_t err = em[0];
    for (size_t i = 0; i < OAEP_HLEN; i++) {
        err |= static_cast<uint32_t>(db[i] ^ lhash[i]);
    }

    uint32_t looking = 0xFFFFFFFFu;
    uint32_t index = 0;
    for (size_t i = 0; i < OAEP_DBLEN - OAEP_HLEN; i++) {
        uint32_t b = db[OAEP_HLEN + i];
        uint32_t is_one = ct_eq(b, 1);
        uint32_t is_null = ct_is_zero(b);
        uint32_t found = looking & is_one;
        index = ct_select(found, static_cast<uint32_t>(i), index);
        looking &= ~is_one;
        err |= looking & ~is_null;
    }
    err |= looking;

    uint32_t valid = ct_is_zero(err);
    uint32_t start = static_cast<uint32_t>(OAEP_HLEN) + 1 + index;
    uint32_t mlen = static_cast<uint32_t>(OAEP_DBLEN) - start;

    for (size_t j = 0; j < OAEP_MAX_MSG; j++) {
        uint32_t acc = 0;
        for (size_t i = 0; i < OAEP_DBLEN; i++) {
            acc |= static_cast<uint32_t>(db[i]) & ct_eq(static_cast<uint32_t>(i), start + static_cast<uint32_t>(j));
        }
        uint32_t in_range = ct_lt(static_cast<uint32_t>(j), mlen);
        out.msg[j] = static_cast<uint8_t>(acc & in_range & valid);
    }
    out.len = mlen & valid;
    out.ok = valid & 1u;

    secure_zero(lhash, sizeof(lhash));
    secure_zero(seed, sizeof(seed));
    secure_zero(seed_mask, sizeof(seed_mask));
    secure_zero(db, sizeof(db));
    secure_zero(db_mask, sizeof(db_mask));
}

bool oaep_encrypt(const uint8_t* msg, size_t mlen, const uint8_t* label, size_t llen,
                  const PublicKey& key, uint8_t ct[OAEP_K])
{
    uint8_t em[OAEP_K];
    if (!oaep_pad(msg, mlen, label, llen, em)) {
        return false;
    }
    bool ok = rsa_encrypt_block(em, OAEP_K, ct, key);
    secure_zero(em, sizeof(em));
    return ok;
}

bool oaep_decrypt(const uint8_t ct[OAEP_K], const uint8_t* label, size_t llen,
                  const PrivateKey& key, OaepResult& out)
{
    uint8_t em[OAEP_K];
    if (!rsa_decrypt_block(ct, OAEP_K, em, key)) {
        std::memset(&out, 0, sizeof(out));
        return false;
    }
    oaep_unpad(em, label, llen, out);
    secure_zero(em, sizeof(em));
    return true;
}

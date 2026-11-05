#include "oaep.hpp"
#include "sha3.hpp"
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <algorithm>

std::vector<uint8_t>
OAEP::mgf1(const uint8_t* seed, size_t seedLen, size_t maskLen) {
    std::vector<uint8_t> T;
    T.reserve(maskLen);
    uint32_t counter = 0;
    while (T.size() < maskLen) {
        uint8_t C[4] = {
            uint8_t((counter >> 24) & 0xFF),
            uint8_t((counter >> 16) & 0xFF),
            uint8_t((counter >>  8) & 0xFF),
            uint8_t((counter >>  0) & 0xFF)
        };
        SHA3_256 ctx;
        ctx.update(seed, seedLen);
        ctx.update(C, 4);
        auto h = ctx.finalize();
        T.insert(T.end(), h.begin(), h.end());
        ++counter;
    }
    T.resize(maskLen);
    return T;
}

static void xor_bytes(uint8_t* dst, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; ++i) dst[i] ^= src[i];
}

static uint8_t ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= (a[i] ^ b[i]);
    return acc;
}

std::vector<uint8_t>
OAEP::pad(const uint8_t* message, size_t msgLen, size_t emLen,
          const uint8_t* label, size_t labelLen) {

    size_t hLen = HASH_LEN;
    if (msgLen > emLen - 2*hLen - 2)
        throw std::invalid_argument("OAEP::pad: message too long");

    SHA3_256 lctx;
    if (label && labelLen) lctx.update(label, labelLen);
    auto lHash = lctx.finalize();

    size_t psLen = emLen - msgLen - 2*hLen - 2;
    std::vector<uint8_t> PS(psLen, 0x00);

    std::vector<uint8_t> DB;
    DB.reserve(emLen - hLen - 1);
    DB.insert(DB.end(), lHash.begin(), lHash.end());
    DB.insert(DB.end(), PS.begin(), PS.end());
    DB.push_back(0x01);
    DB.insert(DB.end(), message, message + msgLen);

    std::vector<uint8_t> seed(hLen);
    if (RAND_bytes(seed.data(), (int)hLen) != 1)
        throw std::runtime_error("RAND_bytes failed");

    auto dbMask = mgf1(seed.data(), seed.size(), DB.size());
    xor_bytes(DB.data(), dbMask.data(), DB.size());

    auto seedMask = mgf1(DB.data(), DB.size(), hLen);
    xor_bytes(seed.data(), seedMask.data(), hLen);

    std::vector<uint8_t> EM;
    EM.reserve(emLen);
    EM.push_back(0x00);
    EM.insert(EM.end(), seed.begin(), seed.end());
    EM.insert(EM.end(), DB.begin(), DB.end());
    return EM;
}

std::vector<uint8_t>
OAEP::unpad(const uint8_t* em, size_t emLen,
            const uint8_t* label, size_t labelLen) {

    size_t hLen = HASH_LEN;
    if (emLen < 2*hLen + 2)
        throw std::invalid_argument("OAEP::unpad: EM too short");

    uint8_t err = 0;

    err |= (em[0] ^ 0x00);

    const uint8_t* maskedSeed = em + 1;
    const uint8_t* maskedDB   = em + 1 + hLen;
    size_t dbLen = emLen - hLen - 1;

    auto seedMask = mgf1(maskedDB, dbLen, hLen);
    std::vector<uint8_t> seed(hLen);
    for (size_t i = 0; i < hLen; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    auto dbMask = mgf1(seed.data(), seed.size(), dbLen);
    std::vector<uint8_t> DB(dbLen);
    for (size_t i = 0; i < dbLen; ++i) DB[i] = maskedDB[i] ^ dbMask[i];

    SHA3_256 lctx;
    if (label && labelLen) lctx.update(label, labelLen);
    auto lHashPrime = lctx.finalize();

    err |= ct_compare(DB.data(), lHashPrime.data(), hLen);

    size_t sep_pos = 0;
    uint8_t found_sep = 0;
    for (size_t i = hLen; i < DB.size(); ++i) {
        uint8_t is_sep = (DB[i] == 0x01) ? 1 : 0;
        uint8_t update_mask = (uint8_t)(~found_sep) & is_sep;
        sep_pos += (size_t)(update_mask * i);
        found_sep |= is_sep;
    }
    err |= (found_sep ^ 1);

    for (size_t i = hLen; i < sep_pos; ++i) {
        err |= DB[i];
    }

    if (err != 0)
        throw std::runtime_error("OAEP::unpad: invalid padding");

    std::vector<uint8_t> M(DB.begin() + sep_pos + 1, DB.end());
    return M;
}
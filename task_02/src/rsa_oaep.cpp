#include "rsa_oaep.hpp"

#include <cstring>

#include "ct_utils.hpp"

namespace rsa {

namespace {

// i2osp: число -> ровно K байт (big-endian). Идём по limb'ам фиксированного
// количества: mpz_getlimbn для индекса за пределами размера даёт 0, поэтому
// длина "ведущих нулей" не влияет на последовательность операций.
void i2osp(uint8_t out[oaep::K], const mpz_class& x) {
    constexpr size_t LB = sizeof(mp_limb_t);
    for (size_t j = 0; j < oaep::K; ++j) {  // j = номер байта от младшего
        const mp_limb_t limb = mpz_getlimbn(x.get_mpz_t(), static_cast<mp_size_t>(j / LB));
        out[oaep::K - 1 - j] = static_cast<uint8_t>(limb >> (8 * (j % LB)));
    }
}

void os2ip(mpz_class& x, const uint8_t in[oaep::K]) {
    mpz_import(x.get_mpz_t(), oaep::K, 1, 1, 1, 0, in);
}

}  // namespace

void rsa_encrypt_em(const PublicKey& pub, const uint8_t em[oaep::K], uint8_t ct[oaep::K]) {
    mpz_class m, c;
    os2ip(m, em);
    rsa_encrypt_raw(c, m, pub);
    i2osp(ct, c);
}

int oaep_encrypt_with_seed(const PublicKey& pub, const uint8_t* msg, size_t msg_len,
                           const uint8_t* label, size_t label_len,
                           const uint8_t seed[oaep::HLEN], uint8_t ct[oaep::K]) {
    uint8_t em[oaep::K];
    int rc = oaep::encode_with_seed(em, msg, msg_len, label, label_len, seed);
    if (rc != 0) return rc;
    rsa_encrypt_em(pub, em, ct);
    ct::secure_zero(em, sizeof(em));
    return 0;
}

int oaep_encrypt(const PublicKey& pub, const uint8_t* msg, size_t msg_len,
                 const uint8_t* label, size_t label_len, uint8_t ct[oaep::K]) {
    uint8_t em[oaep::K];
    int rc = oaep::encode(em, msg, msg_len, label, label_len);
    if (rc != 0) return rc;
    rsa_encrypt_em(pub, em, ct);
    ct::secure_zero(em, sizeof(em));
    return 0;
}

int oaep_decrypt(const PrivateKey& priv, const uint8_t ct_in[oaep::K],
                 const uint8_t* label, size_t label_len,
                 uint8_t* out, size_t* out_len) {
    mpz_class c, m;
    os2ip(c, ct_in);
    *out_len = 0;
    std::memset(out, 0, oaep::MAX_MSG);
    if (c >= priv.n) return -1;  // диапазон шифротекста публичен (RFC 8017, п. 7.1.2)

    rsa_decrypt_crt(m, c, priv);

    uint8_t em[oaep::K];
    i2osp(em, m);
    int rc = oaep::decode(out, out_len, em, label, label_len);
    ct::secure_zero(em, sizeof(em));
    return rc;
}

}  // namespace rsa

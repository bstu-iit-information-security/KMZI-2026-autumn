#pragma once
#include "rsa_math.hpp"

namespace rsa {

inline bool rsa_encrypt(Big& c, const Big& m, const PublicKey& pub) {
    if (bn::cmp(m, pub.n) >= 0) return false;
    mod_exp(c, m, pub.e, pub.mn);
    return true;
}

inline void rsa_decrypt_plain(Big& m, const Big& c, const PrivateKey& k) {
    mod_exp(m, c, k.d, k.mn);
}

inline void rsa_decrypt_crt(Big& m, const Big& c, const PrivateKey& k) {
    Big junk, cp, cq;
    bn::divmod(junk, cp, c, k.p);
    bn::divmod(junk, cq, c, k.q);
    Big m1, m2;
    mod_exp(m1, cp, k.dp, k.mp);
    mod_exp(m2, cq, k.dq, k.mq);
    Big m2p;
    bn::divmod(junk, m2p, m2, k.p);
    Big diff;
    if (bn::cmp(m1, m2p) >= 0) {
        bn::sub(diff, m1, m2p);
    } else {
        bn::add(diff, m1, k.p);
        bn::sub(diff, diff, m2p);
    }
    Big h;
    mod_mul(h, k.qinv, diff, k.mp);
    Big hq;
    bn::mul(hq, h, k.q);
    bn::add(m, m2, hq);
}

inline bool rsa_decrypt_blinded(Big& m, const Big& c, const PrivateKey& k) {
    if (bn::cmp(c, k.n) >= 0) return false;
    std::uint8_t buf[512];
    std::size_t nbytes = (std::size_t)(bn::bitlen(k.n) + 7) / 8 + 8;
    Big r, rinv;
    for (;;) {
        Big rnd, junk;
        random_bytes(buf, nbytes);
        bn::from_bytes_be(rnd, buf, nbytes);
        bn::divmod(junk, r, rnd, k.n);
        if (bn::is_zero(r) || bn::eq_u64(r, 1)) continue;
        if (mod_inverse(rinv, r, k.n)) break;
    }
    Big re, cb;
    mod_exp(re, r, k.e, k.mn);
    mod_mul(cb, c, re, k.mn);
    Big mb;
    rsa_decrypt_crt(mb, cb, k);
    mod_mul(m, mb, rinv, k.mn);
    for (std::size_t i = 0; i < sizeof(buf); ++i) {
        volatile std::uint8_t* p = &buf[i];
        *p = 0;
    }
    return true;
}

}

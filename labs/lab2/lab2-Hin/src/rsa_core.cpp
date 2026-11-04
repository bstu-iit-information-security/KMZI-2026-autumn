#include "rsa_core.hpp"

bool RsaCore::encrypt(Bn& cipher, const Bn& message, const Bn& exponent, const Bn& modulus) {
    if (message.cmp(modulus) >= 0) {
        return false;
    }
    return RsaMath::mod_exp(cipher, message, exponent, modulus);
}

bool RsaCore::decrypt(Bn& message, const Bn& cipher, const RsaKey& key) {
    if (cipher.cmp(key.n) >= 0) {
        return false;
    }
    Bn m1;
    Bn m2;
    if (!RsaMath::mod_exp(m1, cipher, key.dp, key.p) || !RsaMath::mod_exp(m2, cipher, key.dq, key.q)) {
        return false;
    }
    Bn diff;
    Bn::sub(diff, m1, m2);
    Bn::mod(diff, diff, key.p);

    Bn h;
    Bn::mul(h, key.qinv, diff);
    Bn::mod(h, h, key.p);

    Bn hq;
    Bn::mul(hq, h, key.q);
    Bn::add(message, m2, hq);
    return message.cmp(key.n) < 0;
}

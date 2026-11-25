#include "rsa_core.h"
#include <stdexcept>

namespace rsa {

BigInt rsa_encrypt(const BigInt& m, const RsaKeys& k) {
    if (m < 0 || m >= k.n) throw std::invalid_argument("rsa_encrypt: m вне диапазона");
    return mod_pow(m, k.e, k.n);
}

BigInt rsa_decrypt_crt(const BigInt& c, const RsaKeys& k) {
    const BigInt m1 = mod_pow(c % k.p, k.dp, k.p);
    const BigInt m2 = mod_pow(c % k.q, k.dq, k.q);
    BigInt diff = (m1 - m2) % k.p;
    if (diff < 0) diff += k.p;
    const BigInt h = (k.qinv * diff) % k.p;
    return m2 + h * k.q;
}

}
#include "rsa_core.hpp"

namespace rsa {

BigInt rsa_encrypt_raw(const BigInt& m, const KeyPair& kp) {
    if (m.cmp(kp.n) >= 0) {
        throw BnError("message representative >= modulus");
    }
    return mod_exp(m, kp.e, kp.n);
}

BigInt rsa_decrypt_crt(const BigInt& c, const KeyPair& kp) {
    if (c.cmp(kp.n) >= 0) {
        throw BnError("ciphertext representative >= modulus");
    }
 
    BigInt m1 = mod_exp(c, kp.dp, kp.p);
    BigInt m2 = mod_exp(c, kp.dq, kp.q);
    BigInt h = kp.qinv.mod_mul(m1.mod_sub(m2, kp.p), kp.p);
    return m2.add(h.mul(kp.q));
}

GarnerDemo garner_demo_small() {

    GarnerDemo d;
    d.p = BigInt(61);
    d.q = BigInt(53);
    d.n = d.p.mul(d.q);  
    d.e = BigInt(17);
    BigInt lambda = lcm(d.p.sub(BigInt(1)), d.q.sub(BigInt(1)));
    d.d = mod_inverse(d.e, lambda);
    d.dp = d.d.mod(d.p.sub(BigInt(1)));
    d.dq = d.d.mod(d.q.sub(BigInt(1)));
    d.qinv = mod_inverse(d.q, d.p);
    d.m = BigInt(65);  // 'A'
    d.c = mod_exp_binary(d.m, d.e, d.n);

    KeyPair kp;
    kp.n = d.n;
    kp.e = d.e;
    kp.d = d.d;
    kp.p = d.p;
    kp.q = d.q;
    kp.dp = d.dp;
    kp.dq = d.dq;
    kp.qinv = d.qinv;
    d.m1 = mod_exp_binary(d.c, d.dp, d.p);
    d.m2 = mod_exp_binary(d.c, d.dq, d.q);
    d.h = d.qinv.mod_mul(d.m1.mod_sub(d.m2, d.p), d.p);
    d.recovered = d.m2.add(d.h.mul(d.q));
    return d;
}

} 
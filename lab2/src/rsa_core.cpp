#include "rsa_core.hpp"

namespace {

bool in_range(const Bn& message, const Bn& n) {
    return !BN_is_negative(message.raw()) && BN_cmp(message.raw(), n.raw()) < 0;
}

}

bool RsaCore::encrypt(Bn& cipher, const Bn& message, const Bn& e, const Bn& n) {
    if (!in_range(message, n)) {
        return false;
    }
    return RsaMath::mod_exp(cipher, message, e, n);
}

bool RsaCore::decrypt_naive(Bn& message, const Bn& cipher, const Bn& d, const Bn& n) {
    if (!in_range(cipher, n)) {
        return false;
    }
    return RsaMath::mod_exp(message, cipher, d, n);
}

bool RsaCore::decrypt_crt_trace(Bn& message, GarnerTrace& trace, const Bn& cipher,
                                const RsaPrivateKey& key) {
    if (!in_range(cipher, key.n)) {
        return false;
    }
    if (!RsaMath::mod_exp(trace.m1, cipher, key.dp, key.p)) {
        return false;
    }
    if (!RsaMath::mod_exp(trace.m2, cipher, key.dq, key.q)) {
        return false;
    }

    trace.diff_was_negative = BN_cmp(trace.m1.raw(), trace.m2.raw()) < 0;

    BN_CTX* ctx = BN_CTX_new();
    if (ctx == nullptr) {
        return false;
    }
    BN_CTX_start(ctx);
    BIGNUM* diff = BN_CTX_get(ctx);
    BIGNUM* h = BN_CTX_get(ctx);
    BIGNUM* hq = BN_CTX_get(ctx);
    BIGNUM* m = BN_CTX_get(ctx);
    bool ok = diff != nullptr && h != nullptr && hq != nullptr && m != nullptr;
    // (m1 - m2) mod p. Отрицательная разность приводится к [0, p) без ветвления
    // по знаку: BN_mod_sub даёт неотрицательный остаток.
    ok = ok && BN_mod_sub(diff, trace.m1.raw(), trace.m2.raw(), key.p.raw(), ctx) == 1;
    ok = ok && BN_mod_mul(h, key.qinv.raw(), diff, key.p.raw(), ctx) == 1;
    ok = ok && BN_mul(hq, h, key.q.raw(), ctx) == 1;
    ok = ok && BN_add(m, trace.m2.raw(), hq) == 1;
    ok = ok && BN_copy(trace.diff.raw(), diff) != nullptr;
    ok = ok && BN_copy(trace.h.raw(), h) != nullptr;
    ok = ok && BN_copy(trace.message.raw(), m) != nullptr;
    ok = ok && BN_copy(message.raw(), m) != nullptr;
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok;
}

bool RsaCore::decrypt_crt(Bn& message, const Bn& cipher, const RsaPrivateKey& key) {
    GarnerTrace trace;
    return decrypt_crt_trace(message, trace, cipher, key);
}

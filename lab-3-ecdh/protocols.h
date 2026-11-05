#pragma once
#include "ec_algebra.h"
#include "ct.h"
#include <gmpxx.h>
#include <cstdint>
#include <stdexcept>

struct EcdhKeyPair {
    mpz_class d;
    Point Q;
};

struct Signature {
    mpz_class r, s;
};

EcdhKeyPair ecdh_generate_keypair(const CurveParams& C);
mpz_class   ecdh_shared_secret(const mpz_class& d, const Point& Q_peer, const CurveParams& C);
Signature   sign(const mpz_class& e, const mpz_class& d, const CurveParams& C);
bool        verify(const mpz_class& e, const Signature& sig, const Point& Q, const CurveParams& C);
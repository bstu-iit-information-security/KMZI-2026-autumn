#pragma once
#include <utility>
#include "ec_algebra.h"

namespace protocols {

std::pair<BigInt, ec::Point> ecdh_generate_keys(const ec::Curve& curve);
ec::Point ecdh_compute_shared_secret(const BigInt& priv, const ec::Point& pub, const ec::Curve& curve);

std::pair<BigInt, BigInt> ecdsa_sign(const BigInt& hash, const BigInt& priv, const ec::Curve& curve);
bool ecdsa_verify(const BigInt& hash,
                  const std::pair<BigInt, BigInt>& signature,
                  const ec::Point& pub,
                  const ec::Curve& curve);

} // namespace protocols
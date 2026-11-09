#pragma once
#include "number_theory.h"

namespace rsa {

BigInt rsa_encrypt(const BigInt& m, const RsaKeys& k);
BigInt rsa_decrypt_crt(const BigInt& c, const RsaKeys& k);

}
#pragma once
#include "ec_algebra.h"
#include <gmpxx.h>
#include <cstdint>
#include <cstddef>
#include <stdexcept>

void random_bytes(uint8_t* out, size_t n);
void secure_zero(void* ptr, size_t len);
void secure_clear_mpz(mpz_class& z);
int secure_compare(const mpz_class& a, const mpz_class& b);
mpz_class generate_scalar_ct(const mpz_class& q, size_t iters = 100);
Point secure_multiply(const mpz_class& k, const Point& P, const CurveParams& C);
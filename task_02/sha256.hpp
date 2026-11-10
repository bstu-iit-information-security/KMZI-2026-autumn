#pragma once
#include <cstddef>
#include <cstdint>

constexpr size_t SHA256_DIGEST_SIZE = 32;

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

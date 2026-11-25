// Собственная реализация SHA-256 (FIPS 180-4). Внешние крипто-библиотеки
// по условию запрещены, поэтому хеш написан вручную.
#pragma once
#include <cstddef>
#include <cstdint>

namespace sha {

constexpr size_t SHA256_LEN = 32;

class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const uint8_t* data, size_t len);
    void finish(uint8_t out[SHA256_LEN]);

private:
    void compress(const uint8_t block[64]);
    uint32_t h_[8];
    uint8_t buf_[64];
    uint64_t total_;
    size_t buf_len_;
};

void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_LEN]);

}  // namespace sha

// Собственная реализация SHA-512 (FIPS 180-4). Стороннее крипто запрещено, кроме BigInt.
#pragma once
#include <cstddef>
#include <cstdint>

class Sha512 {
public:
    static constexpr size_t DIGEST = 64, BLOCK = 128;
    Sha512();
    ~Sha512();
    void update(const uint8_t* data, size_t len);
    void final(uint8_t out[DIGEST]);
    static void hash(const uint8_t* data, size_t len, uint8_t out[DIGEST]);
private:
    void compress(const uint8_t* block);
    uint64_t h_[8];
    uint8_t  buf_[BLOCK];
    uint64_t total_;   // длина в байтах
    size_t   buflen_;
};

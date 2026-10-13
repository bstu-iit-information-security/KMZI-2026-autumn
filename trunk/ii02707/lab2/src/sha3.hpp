#pragma once
/*
 * Модуль SHA3-256 (Keccak-f[1600]).
 * Реализован вручную, без использования крипто-библиотек.
 */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>

class SHA3_256 {
public:
    static constexpr size_t HASH_LEN  = 32;
    static constexpr size_t RATE      = 136;

    SHA3_256();
    void reset();
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& v) { update(v.data(), v.size()); }
    void final(uint8_t out[HASH_LEN]);

    std::array<uint8_t, HASH_LEN> finalize() {
        std::array<uint8_t, HASH_LEN> h{};
        final(h.data());
        return h;
    }

    static std::array<uint8_t, HASH_LEN> hash(const uint8_t* data, size_t len);
    static std::array<uint8_t, HASH_LEN> hash(const std::vector<uint8_t>& v) {
        return hash(v.data(), v.size());
    }

private:
    uint64_t state_[25];
    uint8_t  buf_[RATE];
    size_t   buf_len_;

    void permute();
    void absorb_block();
};
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>

class OAEP {
public:
    static constexpr size_t HASH_LEN = 32;

    static std::vector<uint8_t> mgf1(const uint8_t* seed, size_t seedLen,
                                     size_t maskLen);

    static std::vector<uint8_t> pad(const uint8_t* message, size_t msgLen,
                                    size_t emLen,
                                    const uint8_t* label = nullptr,
                                    size_t labelLen = 0);

    static std::vector<uint8_t> unpad(const uint8_t* em, size_t emLen,
                                      const uint8_t* label = nullptr,
                                      size_t labelLen = 0);
                                      
};
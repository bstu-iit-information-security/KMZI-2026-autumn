#pragma once

#include <cstddef>
#include <cstdint>

class Oaep {
public:
    static constexpr int kHashLen = 32;
    static constexpr int kModulusBytes = 384;
    static constexpr int kMaxMessage = kModulusBytes - 2 * kHashLen - 2;
    static constexpr int kDbLen = kModulusBytes - kHashLen - 1;

    static bool encode(const uint8_t* message, std::size_t message_len,
                       const uint8_t* label, std::size_t label_len,
                       uint8_t em[kModulusBytes]);

    static bool encode_with_seed(const uint8_t* message, std::size_t message_len,
                                 const uint8_t* label, std::size_t label_len,
                                 const uint8_t seed[kHashLen],
                                 uint8_t em[kModulusBytes]);

    static bool decode(const uint8_t em[kModulusBytes],
                       const uint8_t* label, std::size_t label_len,
                       uint8_t message[kMaxMessage],
                       std::size_t& message_len);
};

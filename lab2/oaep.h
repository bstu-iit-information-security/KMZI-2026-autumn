#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace rsa {

constexpr std::size_t K_LEN = 256;
constexpr std::size_t H_LEN = 64;
constexpr std::size_t DB_LEN = K_LEN - H_LEN - 1;
constexpr std::size_t MAX_MSG = K_LEN - 2 * H_LEN - 2;

struct Message { std::array<std::uint8_t, MAX_MSG> data{}; std::size_t len = 0; };
struct EncodedBlock { std::array<std::uint8_t, K_LEN> data{}; };
struct DecodeResult { bool ok = false; Message msg{}; };

void sha512(const std::uint8_t* in, std::size_t len, std::uint8_t out[64]);

EncodedBlock oaep_encode(const Message& m, const std::uint8_t seed[H_LEN]);
DecodeResult oaep_decode(const EncodedBlock& em);

}
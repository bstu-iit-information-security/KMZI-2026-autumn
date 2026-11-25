#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>

using BigInt = boost::multiprecision::cpp_int;
using Byte = std::uint8_t;

constexpr int RSA_BITS = 4096;
constexpr int RSA_BYTES = 512;
constexpr int HASH_BYTES = 32;
constexpr int MAX_MESSAGE_BYTES = RSA_BYTES - 2 * HASH_BYTES - 2; // 446

struct RSAKey {
    BigInt n, e, d;
    BigInt p, q;
    BigInt dp, dq, qInv;
};

using RSABytes = std::array<Byte, RSA_BYTES>;
using Hash256 = std::array<Byte, HASH_BYTES>;

// Module 1: number theory and key generation
RSAKey generateRSAKey();
BigInt bytesToBigInt(const Byte* data, std::size_t size);
RSABytes bigIntToBytes(BigInt value);

// Module 2: RSA and RSA-CRT
BigInt rsaEncrypt(const BigInt& message, const RSAKey& key);
bool rsaDecryptCRT(const BigInt& cipher, const RSAKey& key,
                   BigInt& message, bool simulateFault = false);

// Module 3: Streebog-256 and OAEP
Hash256 streebog256(const Byte* data, std::size_t size);
bool oaepEncode(const std::vector<Byte>& message, RSABytes& encoded);
bool oaepDecode(const RSABytes& encoded, std::vector<Byte>& message);

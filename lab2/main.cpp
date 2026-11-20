#include "number_theory.h"
#include "rsa_core.h"
#include "oaep.h"
#include <iostream>
#include <random>
#include <stdexcept>

using namespace rsa;

namespace {

std::mt19937_64& rng() {
    static std::mt19937_64 gen{std::random_device{}()};
    return gen;
}

Message random_message(std::size_t len) {
    Message m{};
    m.len = len;
    for (std::size_t i = 0; i < len; ++i) m.data[i] = static_cast<std::uint8_t>(rng());
    return m;
}

void random_seed(std::uint8_t seed[H_LEN]) {
    for (std::size_t i = 0; i < H_LEN; ++i) seed[i] = static_cast<std::uint8_t>(rng());
}

BigInt bytes_to_int(const std::array<std::uint8_t, K_LEN>& b) {
    BigInt x = 0;
    for (std::uint8_t c : b) x = (x << 8) | c;
    return x;
}

std::array<std::uint8_t, K_LEN> int_to_bytes(const BigInt& x) {
    std::array<std::uint8_t, K_LEN> b{};
    BigInt t = x;
    for (int i = static_cast<int>(K_LEN) - 1; i >= 0; --i) {
        b[i] = static_cast<std::uint8_t>((t & 0xFF).convert_to<unsigned>());
        t >>= 8;
    }
    return b;
}

}

int main() {
    try {
        std::cout << "Keygen 2048 bit...\n";
        const RsaKeys key = generate_keys(2048);
        std::cout << "Key generated\n";

        for (const std::size_t len : {std::size_t(0), MAX_MSG}) {
            const Message msg = random_message(len);
            std::uint8_t seed[H_LEN];
            random_seed(seed);
            const EncodedBlock em = oaep_encode(msg, seed);
            const BigInt c = rsa_encrypt(bytes_to_int(em.data), key);
            const EncodedBlock em2{int_to_bytes(rsa_decrypt_crt(c, key))};
            const DecodeResult res = oaep_decode(em2);
            if (!res.ok || res.msg.len != len) {
                std::cout << "Round-trip failed for len=" << len << "\n";
                return 1;
            }
            std::cout << "Round-trip OK, len=" << len << "\n";
        }

        std::cout << "Self-tests passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace lab3 {

class SHA512 {
public:
    SHA512();
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);
    std::array<uint8_t, 64> final();

    static std::array<uint8_t, 64> hash(const std::vector<uint8_t>& data);
private:
    void processBlock(const uint8_t* block);
    std::array<uint64_t, 8> state_;
    std::array<uint8_t, 128> buffer_;
    size_t bufferLen_;
    uint64_t totalLen_;
};

}
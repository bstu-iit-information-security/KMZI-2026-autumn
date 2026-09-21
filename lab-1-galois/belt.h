#include <cstdint>
#include <array>
#include "gfc.h"

class beltCipher {
private:
    gfc calc;
    uint32_t K[8];
    static uint32_t rotHi (uint32_t x, unsigned int shift);
    uint32_t H (uint32_t w) const;
    uint32_t G (uint32_t w, unsigned int shift) const;

    static uint32_t load32_le (const uint8_t* p);
    static void store32_le (uint8_t* p, uint32_t v);
public:
    explicit beltCipher (const gfc& g) : calc(g){}

    void set_key (const uint8_t key[32]);
    void encrypt_block (const uint8_t in[16], uint8_t out[16]) const;
    void decrypt_block (const uint8_t in[16], uint8_t out[16]) const;
};
#include <cstdint>
#include <cstddef>
#include <array>
#include <cstring>

class gfc {
private:
    uint16_t polynomial;
    static const uint8_t beltSbox[256];
public:
    uint8_t add (uint8_t a, uint8_t b) const;
    uint8_t multiply (uint16_t a, uint8_t b, uint16_t p_x) const;
    uint8_t inverse (uint8_t a, uint16_t p_x) const;
    uint8_t xtime (uint8_t a, uint16_t p_x) const;
    uint8_t sbox (uint8_t x) const;
};

    

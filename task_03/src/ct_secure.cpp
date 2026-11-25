#include "ct_secure.h"

Point ctSelectPoint(uint64_t bit, const Point& A, const Point& B) {
    Point r;
    r.X = feSelect(bit, A.X, B.X);
    r.Y = feSelect(bit, A.Y, B.Y);
    r.Z = feSelect(bit, A.Z, B.Z);
    return r;
}

uint64_t ctCompareBytes(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= (uint8_t)(a[i] ^ b[i]);
    uint64_t v = acc;
    return ((v | (0 - v)) >> 63) ^ 1;
}

uint64_t SecureCompare(const Point& A, const Point& B) {
    return pointEqual(A, B);
}

Point SecureMultiply(const uint8_t scalar[32], const Point& P) {
    Point R = pointIdentity();
    for (int i = 255; i >= 0; --i) {
        R = pointDouble(R);                        // единая формула, как и при сложении
        Point T = pointAdd(R, P);                  // единая формула
        uint64_t bit = (scalar[i / 8] >> (i % 8)) & 1;
        R = ctSelectPoint(bit, T, R);              // выбор маской, без if
    }
    return R;
}

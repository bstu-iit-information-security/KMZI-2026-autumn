#include "field.hpp"
#include <stdexcept>

namespace lab3 {

cpp_int Field::s_p = 0;

void Field::setModulus(const cpp_int& p) { s_p = p; }
const cpp_int& Field::modulus() { return s_p; }

cpp_int Field::ctReduce(const cpp_int& a) {
    unsigned carry = ctGreaterOrEqual(a, s_p);
    cpp_int mask = bitMask(carry);
    return a - (s_p & mask);
}

unsigned Field::ctGreaterOrEqual(const cpp_int& a, const cpp_int& b) {
    const unsigned bits = static_cast<unsigned>(s_p.backend().size() * 8);

    const unsigned W = 320;
    (void)bits;

    cpp_int twoW = cpp_int(1) << W;
    cpp_int t = a + twoW - b;
    cpp_int hi = (t >> W) & cpp_int(1);
    return static_cast<unsigned>(hi.convert_to<unsigned long long>());
}

cpp_int Field::bitMask(unsigned bit) {
    cpp_int m = cpp_int(0) - cpp_int(bit);
    return m;
}

cpp_int Field::ctSelect(const cpp_int& a, const cpp_int& b, unsigned bit) {
    cpp_int mask = bitMask(bit);
    return (a & ~mask) | (b & mask);
}

cpp_int Field::add(const cpp_int& a, const cpp_int& b) {
    return ctReduce(a + b);
}

cpp_int Field::sub(const cpp_int& a, const cpp_int& b) {
    return ctReduce(a + s_p - b);
}

cpp_int Field::mul(const cpp_int& a, const cpp_int& b) {
    return (a * b) % s_p;
}

cpp_int Field::pow(const cpp_int& a, const cpp_int& e) {
    cpp_int result = 1;
    cpp_int base = a % s_p;
    cpp_int exp = e;
    while (exp > 0) {
        if ((exp & 1) != 0) result = (result * base) % s_p;
        base = (base * base) % s_p;
        exp >>= 1;
    }
    return result;
}

cpp_int Field::inv(const cpp_int& a) {
    if (a % s_p == 0) throw std::runtime_error("inverse of zero");
    return pow(a, s_p - 2);
}

}
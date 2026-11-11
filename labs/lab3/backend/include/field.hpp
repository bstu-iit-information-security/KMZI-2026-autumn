#pragma once
#include "bigint.hpp"
#include <cstdint>

namespace lab3 {

class Field {
public:
    static void setModulus(const cpp_int& p);
    static const cpp_int& modulus();

    static cpp_int ctReduce(const cpp_int& a);

    static cpp_int add(const cpp_int& a, const cpp_int& b);
    static cpp_int sub(const cpp_int& a, const cpp_int& b);
    static cpp_int mul(const cpp_int& a, const cpp_int& b);

    static cpp_int pow(const cpp_int& a, const cpp_int& e);

    static cpp_int inv(const cpp_int& a);

    static unsigned ctGreaterOrEqual(const cpp_int& a, const cpp_int& b);

    static cpp_int bitMask(unsigned bit);

    static cpp_int ctSelect(const cpp_int& a, const cpp_int& b, unsigned bit);
private:
    static cpp_int s_p;
};

}
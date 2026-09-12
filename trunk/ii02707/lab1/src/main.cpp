#include <iostream>
#include <galoiscalculator.hpp>

int main() {

    GALOIS_FIELD p_x = "x^8+x^5+x^2+x+1";
    GALOIS_FIELD ghash = "x^128+x^7+x^2+x+1";

    std::cout << "Result:" << galois::galois_field_to_int("x^8+x^5+x^3+x+1");
    return 0;
}
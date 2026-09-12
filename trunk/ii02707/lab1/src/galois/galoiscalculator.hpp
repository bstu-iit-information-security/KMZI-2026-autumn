#pragma once
#include <string>
#include <algorithm>
#include <sstream>

typedef int GALOIS_INT;
typedef std::string GALOIS_FIELD;

namespace galois {

// x^8+x^5+x^2+x+1 (0x12B)
int galois_field_to_int(const std::string& poly) {
    int result = 0;
    
    std::stringstream ss(poly);
    std::string term;
    
    while (std::getline(ss, term, '+')) {
        size_t caretPos = term.find('^');
        
        if (caretPos != std::string::npos) {
            std::string expStr = term.substr(caretPos + 1);
            std::stringstream expSS(expStr);
            int exponent;
            expSS >> exponent;
            
            result += (1 << exponent);
        } else {
            if (term.find('x') != std::string::npos) {
                result += (1 << 1);
            } else {
                std::stringstream constSS(term);
                int constant;
                constSS >> constant;
                result += constant;
            }
        }
    }
    
    return result;
}

// p(x) = x^128+x^7+x^2+x+1

class GaloisCalculator {
public:
    explicit GaloisCalculator() = default;
    GALOIS_INT add(GALOIS_INT a, GALOIS_INT b);
    GALOIS_INT multiply(GALOIS_INT a, GALOIS_INT b, GALOIS_INT p_x);
    GALOIS_INT inverse(GALOIS_INT a, GALOIS_INT p_x);

private:
    static constexpr int FIELD_POWER { 8 };

};

}
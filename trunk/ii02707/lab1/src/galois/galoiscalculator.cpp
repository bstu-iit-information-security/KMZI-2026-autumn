#include <galoiscalculator.hpp>

GALOIS_INT galois::GaloisCalculator::add(GALOIS_INT a, GALOIS_INT b)
{
    return static_cast<GALOIS_INT>(a ^ b);
}

GALOIS_INT galois::GaloisCalculator::multiply(GALOIS_INT a, GALOIS_INT b, GALOIS_INT p_x)
{
    GALOIS_INT P_x = 0;
    for(auto i = 0; i < FIELD_POWER; i++) {
        if(b & (1 << i)) {
            P_x ^= (a << i);
        }
    }

    const auto reduce = [](GALOIS_INT P_x, GALOIS_INT p_x) -> GALOIS_INT {
        // When FIELD_POWER = 8 -> 2*FIELD_POWER-2 = 14 
        for(int i = 2*FIELD_POWER-2; i >= FIELD_POWER; i--) { 
            if(P_x & (1 << i)) {
                P_x ^= (p_x << (i - FIELD_POWER));
            }
        }
        return P_x;
    };
    GALOIS_INT C_x = reduce(P_x, p_x);
    return C_x;
}

GALOIS_INT galois::GaloisCalculator::inverse(GALOIS_INT a, GALOIS_INT p_x)
{
    GALOIS_INT result = 1;
    GALOIS_INT t = a;

    GALOIS_INT exp = (1 << FIELD_POWER) - 2;
    for(auto i = 0; i < FIELD_POWER; i++) {
        if(exp & (1 << i)) {
            result = multiply(result, t, p_x);
        }
        t = multiply(t, t, p_x);
    }
    return result;
}

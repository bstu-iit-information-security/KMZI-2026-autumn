#include "ec_algebra.h"
#include "constant_time.h"
#include <iostream>

using namespace ec;

Point ec::point_double(const Point& P, const Curve& c) {
    if (P.is_infinity || P.y.is_zero()) return Point::infinity();
    BigInt num = mod_add(mod_mul(BigInt(3), mod_mul(P.x, P.x, c.p), c.p), c.a, c.p);
    BigInt den = mod_mul(BigInt(2), P.y, c.p);
    BigInt inv = constant_time::mod_inverse_constant_time(den, c.p);
    BigInt s = mod_mul(num, inv, c.p);
    BigInt x3 = mod_sub(mod_mul(s, s, c.p), mod_mul(BigInt(2), P.x, c.p), c.p);
    BigInt y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, c.p), c.p), P.y, c.p);
    return Point(x3, y3);
}

Point ec::point_add(const Point& P, const Point& Q, const Curve& c) {
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;
    if (P.x == Q.x && P.y != Q.y) return Point::infinity();
    if (P.x == Q.x && P.y == Q.y) return point_double(P, c);

    BigInt num = mod_sub(Q.y, P.y, c.p);
    BigInt den = mod_sub(Q.x, P.x, c.p);
    BigInt inv = constant_time::mod_inverse_constant_time(den, c.p);
    BigInt s = mod_mul(num, inv, c.p);
    BigInt x3 = mod_sub(mod_sub(mod_mul(s, s, c.p), P.x, c.p), Q.x, c.p);
    BigInt y3 = mod_sub(mod_mul(s, mod_sub(P.x, x3, c.p), c.p), P.y, c.p);
    return Point(x3, y3);
}

Point ec::scalar_multiply(const BigInt& k, const Point& P, const Curve& c) {
    Point result = Point::infinity();
    Point temp = P;
    
    // Цикл по реальной длине скаляра для предотвращения зацикливания аффинной арифметики
    size_t total_bits = k.bit_length();
    
    for (size_t i = 0; i < total_bits; ++i) {
        Point added = point_add(result, temp, c);
        uint32_t bit_active = k.bit(i) ? 1 : 0;
        
        result.x = BigInt::constant_time_select(bit_active, added.x, result.x);
        result.y = BigInt::constant_time_select(bit_active, added.y, result.y);
        
        uint32_t inf_mask = 0 - bit_active;
        bool next_infinity = result.is_infinity ^ (inf_mask & (added.is_infinity ^ result.is_infinity));
        result.is_infinity = next_infinity;

        temp = point_double(temp, c);
    }
    return result;
}

bool ec::is_on_curve(const Point& P, const Curve& c) {
    if (P.is_infinity) return true;
    BigInt lhs = mod_mul(P.y, P.y, c.p);
    BigInt rhs = mod_add(
        mod_add(mod_mul(mod_mul(P.x, P.x, c.p), P.x, c.p),
                mod_mul(c.a, P.x, c.p), c.p),
        c.b, c.p);
    return lhs == rhs;
}

void ec::print_point(const char* name, const Point& P) {
    if (P.is_infinity) std::cout << name << ": Infinity" << std::endl;
    else {
        std::cout << name << ":" << std::endl;
        std::cout << "  x = " << P.x.to_hex() << std::endl;
        std::cout << "  y = " << P.y.to_hex() << std::endl;
    }
}

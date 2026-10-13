#pragma once
#include "bigint.h"

namespace ec {

struct Point {
    BigInt x, y;
    bool is_infinity;
    Point() : is_infinity(true) {}
    Point(const BigInt& x_, const BigInt& y_) : x(x_), y(y_), is_infinity(false) {}
    static Point infinity() { return Point(); }
    bool operator==(const Point& o) const {
        if (is_infinity && o.is_infinity) return true;
        if (is_infinity != o.is_infinity) return false;
        return x == o.x && y == o.y;
    }
};

struct Curve {
    BigInt p, a, b;
    Point G;
    BigInt q;
};

Point point_double(const Point& P, const Curve& c);
Point point_add(const Point& P, const Point& Q, const Curve& c);
Point scalar_multiply(const BigInt& k, const Point& P, const Curve& c);
bool is_on_curve(const Point& P, const Curve& c);
void print_point(const char* name, const Point& P);

} // namespace ec
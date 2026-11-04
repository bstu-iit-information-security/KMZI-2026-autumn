#ifndef CURVES_H
#define CURVES_H

#include <cstdint>
#include <stdexcept>

class Curves {
public:
    using u64 = std::uint64_t;

    struct Point {
        u64  x;
        u64  y;
        bool infinity;

        Point() : x(0), y(0), infinity(true) {}
        Point(u64 x_, u64 y_) : x(x_), y(y_), infinity(false) {}
    };

    Curves(u64 p, u64 a, u64 b, u64 Gx, u64 Gy, u64 q);

    u64          p() const noexcept { return p_; }
    u64          a() const noexcept { return a_; }
    u64          b() const noexcept { return b_; }
    u64          q() const noexcept { return q_; }
    const Point& G() const noexcept { return G_; }

    bool  isOnCurve(const Point& P) const noexcept;
    Point add(const Point& P, const Point& Q) const;
    Point dbl(const Point& P) const;
    Point mul(u64 k, const Point& P) const;

    // Constant-time API 
    Point mulConstantTime(u64 k, const Point& P) const;
    bool  constantTimeEqual(const Point& A, const Point& B) const noexcept;

    //  Проверка инвариантов кривой (Fault Injection) 
    bool validateInvariants() const noexcept;

private:
    u64   p_, a_, b_, q_;
    Point G_;

    static u64 mulmod(u64 a, u64 b, u64 m) noexcept;
    static u64 modInverse(u64 a, u64 m);
    static u64 modInverseConstantTime(u64 a, u64 p) noexcept; 
    bool       isNonSingular() const noexcept;

    // Внутренние constant-time примитивы
    static void cswap(Point& A, Point& B, u64 bit) noexcept;
    static void cselect(Point& dst, const Point& A, const Point& B, u64 bit) noexcept;
    static u64  cmov(u64 a, u64 b, u64 bit) noexcept; // b, если bit=1
};

#endif


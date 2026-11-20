#include "ec_ct.h"

namespace ecc { namespace ct {

namespace {

Point ct_select(bool cond, const Point& A, const Point& B) { // cond ? A : B
    const BigInt mask = BigInt(0) - BigInt(static_cast<int>(cond));
    Point R;
    R.x = (A.x & mask) | (B.x & ~mask);
    R.y = (A.y & mask) | (B.y & ~mask);
    R.inf = (cond && A.inf) || (!cond && B.inf);
    return R;
}

}

Point ct_table_lookup(const std::array<Point, TABLE_SIZE>& table, std::size_t index) {
    Point R; R.x = 0; R.y = 0; R.inf = false;
    for (std::size_t i = 0; i < TABLE_SIZE; ++i) {           // проход по всей таблице
        const BigInt mask = BigInt(0) - BigInt(static_cast<int>(i == index));
        R.x ^= (table[i].x & mask);                           // выбор по маске, без Table[index]
        R.y ^= (table[i].y & mask);
    }
    return R;
}

Point secure_multiply(const BigInt& k, const Point& P, const CurveParams& c) {
    std::array<Point, TABLE_SIZE> table{};                    // фиксированный блок памяти
    table[0] = P;
    const Point D = point_double(P, c);
    for (std::size_t i = 1; i < TABLE_SIZE; ++i) table[i] = point_add(table[i - 1], D, c);

    std::array<int, 260> digits{};                            // WNAF в фиксированном блоке
    std::size_t len = 0;
    BigInt cur = k;
    const int mod = 1 << WNAF_W;
    while (cur > 0) {
        if ((cur & 1) == 0) { digits[len++] = 0; cur >>= 1; }
        else {
            int val = static_cast<int>((cur & (mod - 1)).convert_to<int>());
            if (val >= mod / 2) val -= mod;
            digits[len++] = val;
            cur = (cur - val) >> 1;
        }
    }

    Point R;
    for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
        R = point_double(R, c);                               // удвоение всегда
        const int dgt = digits[i];
        const int absd = dgt < 0 ? -dgt : dgt;
        const Point T = ct_table_lookup(table, static_cast<std::size_t>(absd >> 1));
        const Point Tn = ct_select(dgt < 0, point_neg(T, c), T);
        const Point R2 = point_add(R, Tn, c);                 // сложение считаем всегда
        R = ct_select(dgt != 0, R2, R);                       // выбор по маске
    }
    return R;
}

bool secure_compare(const BigInt& A, const BigInt& B) {
    const auto ba = to_bytes32(A);
    const auto bb = to_bytes32(B);
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < 32; ++i) acc |= static_cast<std::uint8_t>(ba[i] ^ bb[i]);
    return acc == 0;
}

}}
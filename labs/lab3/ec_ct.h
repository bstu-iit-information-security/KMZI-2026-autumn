#pragma once
#include "ec_curve.h"
#include <array>

namespace ecc { namespace ct {

constexpr int WNAF_W = 4;
constexpr std::size_t TABLE_SIZE = 1u << (WNAF_W - 1); // 8 точек: 1P, 3P, ..., 15P

// constant-time доступ к предвычисленной таблице
Point ct_table_lookup(const std::array<Point, TABLE_SIZE>& table, std::size_t index);

// Оконный метод WNAF с constant-time доступом к таблице
Point secure_multiply(const BigInt& k, const Point& P, const CurveParams& c);

bool secure_compare(const BigInt& A, const BigInt& B);

}}
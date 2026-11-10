#ifndef EC_ALGEBRA_H
#define EC_ALGEBRA_H

// Модуль 1. Алгебра кривой Эдвардса Ed25519: -x^2 + y^2 = 1 + d x^2 y^2 над GF(p), p = 2^255 - 19.
// Элемент поля - 4 беззнаковых 64-битных слова (little-endian) в каноническом виде [0, p).
// Динамическая память не используется.

#include <cstdint>
#include <cstddef>

struct Fe {
    uint64_t v[4];
};

// Точка в проективных координатах: x = X/Z, y = Y/Z. Нейтральный элемент - (0, 1, 1).
struct Point {
    Fe X, Y, Z;
};

// ---- арифметика поля GF(p) (без ветвлений по значениям) ----
Fe feZero();
Fe feOne();
Fe feFromU64(uint64_t x);
Fe feAdd(const Fe& a, const Fe& b);
Fe feSub(const Fe& a, const Fe& b);
Fe feNeg(const Fe& a);
Fe feMul(const Fe& a, const Fe& b);
Fe feSquare(const Fe& a);
Fe feSelect(uint64_t bit, const Fe& a, const Fe& b);   // bit ? a : b, без ветвления
uint64_t feEqual(const Fe& a, const Fe& b);            // 1 если равны, XOR-аккумулятор без раннего выхода
Fe fePow(const Fe& a, const uint64_t exponent[4]);     // экспонента публичная
Fe feInvert(const Fe& a);                              // a^(p-2), малая теорема Ферма
uint64_t feIsNegative(const Fe& a);                    // младший бит канонического представления
void feToBytes(const Fe& a, uint8_t out[32]);          // little-endian
bool feFromBytes(const uint8_t in[32], Fe* out);       // false, если значение >= p
bool feFromHex(const char* hex64, Fe* out);            // big-endian hex, 64 символа

// ---- параметры кривой (заданы hex-строками) ----
struct CurveParams {
    Fe d;                    // коэффициент d
    Fe Gx, Gy;               // базовая точка
    uint8_t q[32];           // порядок подгруппы (little-endian)
};
const CurveParams& curve();

// ---- группа точек ----
Point pointIdentity();
Point pointFromAffine(const Fe& x, const Fe& y);
Point pointBase();
Point pointNeg(const Point& P);
// Единая (unified) формула: одна и та же функция для сложения разных точек и удвоения.
Point pointAdd(const Point& P, const Point& Q);
Point pointDouble(const Point& P);                    // = pointAdd(P, P), без ветвления P == Q
void pointToAffine(const Point& P, Fe* x, Fe* y);
uint64_t pointEqual(const Point& P, const Point& Q);  // перекрёстное умножение, без инверсии
bool pointOnCurve(const Point& P);
void pointEncode(const Point& P, uint8_t out[32]);    // RFC 8032: y и бит знака x
bool pointDecode(const uint8_t in[32], Point* P);

// Классическое скалярное умножение Double-and-Add (с ветвлением по биту, ТОЛЬКО для публичных скаляров)
Point pointMulDoubleAndAdd(const uint8_t scalar[32], const Point& P);

#endif

#ifndef CT_SECURE_H
#define CT_SECURE_H

// Модуль 3. Constant-time защита: безусловный выбор точек, сравнение и безопасное скалярное умножение
// на базе единой формулы сложения/удвоения (вариант 8).

#include <cstdint>
#include "ec_algebra.h"

// bit ? A : B для точек, маска вместо if
Point ctSelectPoint(uint64_t bit, const Point& A, const Point& B);

// Сравнение двух байтовых массивов с XOR-аккумулятором, без раннего выхода. Возвращает 1 при равенстве.
uint64_t ctCompareBytes(const uint8_t* a, const uint8_t* b, size_t len);

// Сравнение точек (SecureCompare): перекрёстное умножение, без инверсий и ветвлений
uint64_t SecureCompare(const Point& A, const Point& B);

// Безопасное скалярное умножение (Double-and-Add-Always на единой формуле):
// на каждой из 256 итераций выполняются ровно одно удвоение и одно сложение, результат выбирается маской.
Point SecureMultiply(const uint8_t scalar[32], const Point& P);

#endif

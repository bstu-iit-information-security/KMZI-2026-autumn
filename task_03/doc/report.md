Министерство образования Республики Беларусь

Учреждение образования
«Брестский Государственный технический университет»

Кафедра ИИТ

**Лабораторная работа №3**

По дисциплине «КМЗИ»

Тема: «Арифметика точечных групп эллиптических кривых, протокол ECDH и алгоритмы ЭЦП»

> **Выполнил:** Студент 3 курса, группы ИИ-27/24, Ханцевич Г.С.
>
> **Проверил:** Хацкевич А.С.

Брест 2026

---

**Цель работы:** программная реализация защищённого математического ядра для кривой Эдвардса над $\mathbb{GF}(p)$, протокола ECDH и электронной цифровой подписи EdDSA (Ed25519) с защитой от атак по времени.

**Индивидуальный вариант — №8:**

| Параметр | Значение |
|---|---|
| Алгоритм ЭЦП | EdDSA (Ed25519) |
| Тип кривой / координаты | Эдвардс / проективные |
| Задача Constant-time | Единая математическая формула сложения и удвоения (Unified Addition Formula) |

**Язык и ограничения.** C++17. Собственные реализации: арифметика поля $\mathbb{GF}(2^{255}-19)$ (4 слова по 64 бита), точки и группа, SHA-512, ECDH, EdDSA. Библиотека GMP используется **только** для арифметики больших чисел по модулю $q$ (сведение хэша по $q$, вычисление $S = r + k a \bmod q$, проверка $S < q$), как разрешено заданием. Парсинг PEM/DER/ASN.1 не используется; параметры кривой заданы hex-строками, вывод — сырой hex. Динамические контейнеры не применяются: точки и элементы поля — POD-структуры на стеке.

**Параметры кривой Ed25519** (hex, big-endian): 

- $p = 2^{255}-19$, $a = -1$;
- $d = $ `52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3` ($= -121665/121666 \bmod p$);
- $G_x = $ `216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a`;
- $G_y = $ `6666666666666666666666666666666666666666666666666666666666666658` ($= 4/5$);
- $q = 2^{252} + 27742317777372353535851937790883648493 = $ `1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed`, кофактор $h = 8$.

## 1. Математическая часть

### 1.1. Закон сложения на кривой Эдвардса

Кривая: $a x^2 + y^2 = 1 + d x^2 y^2$, $a = -1$. Для $P_1 = (x_1, y_1)$ и $P_2 = (x_2, y_2)$:

$$x_3 = \frac{x_1 y_2 + y_1 x_2}{1 + d\, x_1 x_2 y_1 y_2}, \qquad y_3 = \frac{y_1 y_2 - a\, x_1 x_2}{1 - d\, x_1 x_2 y_1 y_2}.$$

Нейтральный элемент — $(0, 1)$, обратный к $(x, y)$ — $(-x, y)$.

**Полнота (единая формула).** В $\mathbb{GF}(p)$, $p \equiv 1 \pmod 4$, элемент $a = -1$ — квадрат, а $d$ — квадратичный невычет (оба факта проверены в тесте: $d^{(p-1)/2} = -1$, $i^2 = -1$). Тогда по теореме Бернштейна и Ланге (Twisted Edwards Curves, 2008) знаменатели $1 \pm d x_1 x_2 y_1 y_2$ не обращаются в нуль ни для каких точек кривой. Поэтому одна формула верна для **любой** пары точек: разных, равных ($P_1 = P_2$, удвоение), нейтрального элемента и взаимно обратных точек. Особых случаев и проверок `if (P == Q)` не требуется. В форме Вейерштрасса такого нет: сложение и удвоение — разные формулы, плюс отдельные ветки для $\mathcal{O}$ и $P = -Q$.

**Удвоение.** При $P_1 = P_2$ и с учётом уравнения кривой $d x^2 y^2 = a x^2 + y^2 - 1$:

$$x_3 = \frac{2xy}{a x^2 + y^2}, \qquad y_3 = \frac{y^2 - a x^2}{2 - a x^2 - y^2}.$$

Тест сверяет `Add(G, G)` именно с этой независимой формулой.

### 1.2. Проективные координаты

Подставляем $x = X/Z$, $y = Y/Z$ и вводим $A = Z_1 Z_2$, $B = A^2$, $C = X_1 X_2$, $D = Y_1 Y_2$, $E = d\,C D$. Тогда

$$1 \pm d x_1 x_2 y_1 y_2 = \frac{B \pm E}{B}, \qquad x_1 y_2 + y_1 x_2 = \frac{H}{A},\ H = (X_1+Y_1)(X_2+Y_2) - C - D,$$

$$x_3 = \frac{A\,H}{B + E}, \qquad y_3 = \frac{A\,(D - aC)}{B - E}.$$

Приводим к общему знаменателю $Z_3 = (B-E)(B+E)$:

$$X_3 = A\,(B-E)\,H, \qquad Y_3 = A\,(B+E)\,(D - aC), \qquad Z_3 = (B-E)(B+E).$$

Это в точности формула из методички. При $a=-1$ множитель $D - aC$ становится $D + C$. На сложение приходится 9 умножений в $\mathbb{GF}(p)$ плюс умножение на $d$; инверсия нужна только один раз, при переводе в аффинный вид (кодирование точки). Удвоение — тот же вызов `pointAdd(P, P)`.

### 1.3. EdDSA: выработка и проверка подписи

Закрытое значение — `seed` (32 байта). $h = \text{SHA-512}(seed)$; $a = $ clamp$(h[0..31])$ (сбросить 3 младших бита, сбросить бит 255, установить бит 254); `prefix` $= h[32..63]$; открытый ключ $A = a \cdot G$.

* *Подпись сообщения $M$:* $r = \text{SHA-512}(prefix \parallel M) \bmod q$; $R = r\cdot G$; $k = \text{SHA-512}(R \parallel A \parallel M) \bmod q$; $S = (r + k\,a) \bmod q$. Подпись — $R \parallel S$ (64 байта). Подпись детерминирована: случайное $k$ не нужно.
* *Проверка:* требуем $S < q$, декодируем $R$ и $A$ (точка должна существовать), считаем $k$, проверяем $S\cdot G = R + k\cdot A$.

**Доказательство корректности.** Так как $A = aG$ и $R = rG$, 

$$R + k A = rG + k a G = (r + k a)\,G = S\,G,$$

поскольку $G$ имеет порядок $q$, а $S \equiv r + k a \pmod q$ ($qG = \mathcal{O}$). Значит, у честной подписи равенство выполняется всегда. Подделать $S$ без знания $a$ нельзя: нужно решить задачу дискретного логарифма для $A$ (в схеме ECDSA аналогом служит равенство $x_{c'} \bmod q = r$; здесь проверяется сразу равенство точек).

Условие $S < q$ убирает неоднозначность: иначе $S + q$ давало бы вторую валидную подпись.

### 1.4. ECDH

Каждая сторона берёт clamped-скаляр $d$ и публикует $Q = d\,G$. Общий секрет: $d_A \cdot Q_B = d_A d_B G = d_B \cdot Q_A$. Результат кодируется как точка (32 байта по RFC 8032). Clamping обнуляет три младших бита скаляра, то есть умножает его на кофактор 8: точки малого порядка не раскрывают биты $d$. Дополнительно отвергается результат, равный нейтральному элементу.

## 2. Архитектура

Три изолированных модуля и главный файл с тестами, сборка — `CMakeLists.txt` (`cmake ../src && cmake --build .`, исполняемый файл `main`).

| Модуль | Файлы | Содержимое |
|---|---|---|
| 1. Алгебра ЭК | `ec_algebra.h/.cpp` | Поле $\mathbb{GF}(p)$, структуры `Fe` и `Point`, `pointAdd` (единая формула), `pointDouble`, кодирование/декодирование точек (с извлечением квадратного корня), классический `pointMulDoubleAndAdd` |
| 2. Протоколы | `protocols.h/.cpp` | SHA-512, ключи, `eddsaSign`/`eddsaVerify`, `ecdhSharedSecret` (GMP — только mod $q$) |
| 3. Constant-time | `ct_secure.h/.cpp` | `ctSelectPoint`, `ctCompareBytes`, `SecureCompare`, `SecureMultiply` |

Потоки данных: модуль 2 вызывает `SecureMultiply` из модуля 3 для всех операций с секретом ($a$, $r$, $d$); модуль 3 использует `pointAdd`/`pointDouble` из модуля 1. Проверка подписи (публичные данные) использует классический Double-and-Add: Constant-time там не нужен.

## 3. Анализ безопасности (Constant-time)

### 3.1. Единая формула вместо ветвлений

Для кривой Вейерштрасса сложение выглядит так:

```
if (P is O) return Q;  if (Q is O) return P;
if (P == Q) return Double(P);  if (P == -Q) return O;  return Add(P, Q);
```

Каждая ветка занимает разное время и по-разному обращается к памяти, то есть выдаёт наблюдателю, какие из условий выполнились. В реализации варианта 8 вся функция сложения — одна линейная последовательность операций (фрагмент `ec_algebra.cpp`):

```cpp
Point pointAdd(const Point& P, const Point& Q) {
    Fe A = feMul(P.Z, Q.Z);   Fe B = feSquare(A);
    Fe C = feMul(P.X, Q.X);   Fe D = feMul(P.Y, Q.Y);
    Fe E = feMul(d, feMul(C, D));
    Fe F = feSub(B, E);       Fe G = feAdd(B, E);
    Fe H = feSub(feSub(feMul(feAdd(P.X, P.Y), feAdd(Q.X, Q.Y)), C), D);
    ...  /* X3 = A F H, Y3 = A G (D + C), Z3 = F G */
}
Point pointDouble(const Point& P) { return pointAdd(P, P); }   // тот же код, без if (P == Q)
```

Нет ни одного условного перехода, зависящего от координат: путь выполнения не зависит ни от того, равны ли точки, ни от того, лежит ли одна из них в нейтральном элементе. Тесты подтверждают, что единая формула верна на всех «особых» входах: `Add(G,G)` совпадает с независимой формулой удвоения, `Add(G,O)=G`, `Add(O,O)=O`, `Add(G,-G)=O`.

### 3.2. Скалярное умножение без ветвлений по секрету

```cpp
Point SecureMultiply(const uint8_t scalar[32], const Point& P) {
    Point R = pointIdentity();
    for (int i = 255; i >= 0; --i) {            // всегда 256 итераций
        R = pointDouble(R);                      // всегда одно удвоение
        Point T = pointAdd(R, P);                // всегда одно сложение
        uint64_t bit = (scalar[i / 8] >> (i % 8)) & 1;
        R = ctSelectPoint(bit, T, R);            // выбор маской
    }
    return R;
}
```

* Число итераций и операций фиксировано и не зависит от значения и веса Хэмминга $d$ или $k$.
* Бит секрета попадает только в маску `0 - bit`; `ctSelectPoint` делает `(a & mask) | (b & ~mask)` по всем 12 словам точки.
* Классический вариант (`pointMulDoubleAndAdd`) содержит `if (bit) R = pointAdd(R, P)`: число сложений равно весу Хэмминга скаляра. Он используется только для публичных скаляров (проверка подписи).

### 3.3. Арифметика поля и сравнения

* `feAdd`/`feSub`: условное вычитание/прибавление $p$ выполняется через маску от заёма (`feSelect`), без `if`.
* `feMul`: фиксированные циклы 4×4 слова на `unsigned __int128`, свёртка по $2^{256} \equiv 38$ и $2^{255} \equiv 19$, финальные два условных вычитания $p$ — маской.
* `feInvert`: $a^{p-2}$ (малая теорема Ферма), фиксированные 256 итераций «возвести в квадрат — умножить — выбрать маской».
* `feEqual`, `SecureCompare`, `ctCompareBytes`: XOR-аккумулятор без раннего выхода, результат 0/1 без ветвления.

### 3.4. Эмпирическая проверка (индикативная)

Замер на 200–700 вызовах (лучший из 7 раундов по 100 вызовов, Apple Silicon, `-O3`-режим Release):

| Реализация | $k = 1$ | $k = 2^{256}-1$ | $k$ смешанный |
|---|---|---|---|
| `SecureMultiply` | 118.1 мкс | 120.5 мкс (+2.0%) | 119.3 мкс (+1.0%) |
| Классический Double-and-Add | 61.6 мкс | 119.0 мкс (+93.1%) | 89.9 мкс (+45.9%) |

У классического алгоритма время растёт вместе с весом Хэмминга ключа (утечка), у `SecureMultiply` разброс в пределах 2% (шум измерения). Это иллюстрация, а не доказательство: для строгого вывода нужен анализ ассемблера и статистические тесты (dudect).

### 3.5. Ограничения

* GMP (`mpz_mul`, `mpz_mod`) вычисляет $S = r + k a \bmod q$ и $r = H \bmod q$ не в постоянное время; секрет $a$ участвует в этом умножении. Задание разрешает GMP только для больших чисел, поэтому данный участок оставлен как есть. Строго Constant-time заменой был бы собственный модуль $q$ на фиксированных словах.
* Отсутствие оптимизационных «сюрпризов» компилятора (замена масок ветвлениями) не проверялось по ассемблеру.
* GMP внутри себя выделяет память под `mpz_t`; в остальном код куча-свободный.
* Очистка секретов из памяти (`explicit_bzero`) не реализована.

## 4. Результаты тестирования

Полный вывод — `doc/run_output.txt`. Итог: **52 проверки, все PASS**, код возврата 0. Все критичные результаты совпали с независимыми источниками.

**Эталонные векторы.** Открытый ключ и подпись совпали побайтно для RFC 8032 TEST 1 и TEST 2, а также для третьего вектора, созданного независимо в OpenSSL 3.6.3 (`openssl pkeyutl -sign -rawin`, сообщение «KMZI lab3 variant 8»; EdDSA детерминирован, поэтому подписи должны совпасть).

```
RFC 8032, TEST 1 (пустое сообщение)
  публичный ключ : d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
  подпись (R||S) : e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
  ... PASS (ключ, подпись, проверка)
```

**ECDH (Алиса и Боб):**

```
Alice, открытый ключ Q_A: 79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664
Bob,   открытый ключ Q_B: a48aad3f096dd27fd9ea9073631921c433c724f4f2d78b40f5fda2b8f67284d3
Shared Secret у Alice (d_A * Q_B): 80e5d94fcbf211392409198fcfe12f300fd42c42143e1a89e5e229f43e5b3f74
Shared Secret у Bob   (d_B * Q_A): 80e5d94fcbf211392409198fcfe12f300fd42c42143e1a89e5e229f43e5b3f74
```

Секреты равны; у третьей стороны (Eve) секрет другой; публичный ключ — нейтральный элемент — отвергается.

**Подпись — проверка (для трёх сообщений, пример «KMZI»):**

| Проверка | Результат |
|---|---|
| Подписанное сообщение проходит проверку | PASS |
| **Искажение одного байта в $S$** | **отвергнуто** |
| Искажение одного байта в $R$ | отвергнуто |
| Искажение одного байта в сообщении | отвергнуто |
| Чужой открытый ключ | отвергнут |
| $S + q$ (то есть $S \ge q$) | отвергнуто |

**Групповые свойства:** $qG = \mathcal{O}$, $(q+1)G = G$, $0\cdot G = \mathcal{O}$; `SecureMultiply` совпадает с классическим Double-and-Add; кодирование/декодирование точки (с извлечением корня) корректно; инверсия бита знака даёт $-P$; $G$ лежит на кривой.

**SHA-512:** собственная реализация совпала с OpenSSL на строках `abc` и пустой.

Сборка: `cd src && mkdir build && cd build && cmake .. && cmake --build . && ./main` (нужен GMP: `brew install gmp`).

## 5. Код программы

*Модуль 1 — заголовок — `ec_algebra.h`*

```cpp
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
```

*Модуль 1 — реализация — `ec_algebra.cpp`*

```cpp
#include "ec_algebra.h"

typedef unsigned __int128 u128;

static const uint64_t P_LIMBS[4] = {0xffffffffffffffedULL, 0xffffffffffffffffULL,
                                    0xffffffffffffffffULL, 0x7fffffffffffffffULL};
// p - 2, (p - 5) / 8, (p - 1) / 4
static const uint64_t EXP_P_MINUS_2[4]  = {0xffffffffffffffebULL, 0xffffffffffffffffULL,
                                           0xffffffffffffffffULL, 0x7fffffffffffffffULL};
static const uint64_t EXP_P_MINUS_5_D8[4] = {0xfffffffffffffffdULL, 0xffffffffffffffffULL,
                                             0xffffffffffffffffULL, 0x0fffffffffffffffULL};
static const uint64_t EXP_P_MINUS_1_D4[4] = {0xfffffffffffffffbULL, 0xffffffffffffffffULL,
                                             0xffffffffffffffffULL, 0x1fffffffffffffffULL};

// ---------------------------------------------------------------- поле

Fe feZero() { Fe r = {{0, 0, 0, 0}}; return r; }
Fe feOne()  { Fe r = {{1, 0, 0, 0}}; return r; }
Fe feFromU64(uint64_t x) { Fe r = {{x, 0, 0, 0}}; return r; }

Fe feSelect(uint64_t bit, const Fe& a, const Fe& b) {
    uint64_t mask = 0 - (bit & 1);
    Fe r;
    for (int i = 0; i < 4; ++i) r.v[i] = (a.v[i] & mask) | (b.v[i] & ~mask);
    return r;
}

// r = a - P; если был заём (a < P), возвращается a. Без ветвлений.
static Fe condSubP(const Fe& a) {
    Fe t;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        u128 d = (u128)a.v[i] - P_LIMBS[i] - borrow;
        t.v[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    return feSelect(borrow, a, t);
}

Fe feAdd(const Fe& a, const Fe& b) {
    Fe s;
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)a.v[i] + b.v[i] + c;
        s.v[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    return condSubP(s);
}

Fe feSub(const Fe& a, const Fe& b) {
    Fe t;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        u128 d = (u128)a.v[i] - b.v[i] - borrow;
        t.v[i] = (uint64_t)d;
        borrow = (uint64_t)(d >> 64) & 1;
    }
    Fe u;
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 s = (u128)t.v[i] + P_LIMBS[i] + c;
        u.v[i] = (uint64_t)s;
        c = (uint64_t)(s >> 64);
    }
    return feSelect(borrow, u, t);
}

Fe feNeg(const Fe& a) { return feSub(feZero(), a); }

Fe feMul(const Fe& a, const Fe& b) {
    uint64_t r[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            u128 t = (u128)a.v[i] * b.v[j] + r[i + j] + carry;
            r[i + j] = (uint64_t)t;
            carry = (uint64_t)(t >> 64);
        }
        r[i + 4] = carry;
    }
    // 2^256 = 38 (mod p): w = L + 38 * H
    uint64_t w[5];
    uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)r[i + 4] * 38 + r[i] + c;
        w[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    w[4] = c;
    // 2^255 = 19 (mod p): отделяем биты выше 254
    uint64_t top = (w[3] >> 63) | (w[4] << 1);
    w[3] &= 0x7fffffffffffffffULL;
    Fe res;
    c = top * 19;
    for (int i = 0; i < 4; ++i) {
        u128 t = (u128)w[i] + c;
        res.v[i] = (uint64_t)t;
        c = (uint64_t)(t >> 64);
    }
    res = condSubP(res);
    return condSubP(res);
}

Fe feSquare(const Fe& a) { return feMul(a, a); }

uint64_t feEqual(const Fe& a, const Fe& b) {
    uint64_t acc = 0;
    for (int i = 0; i < 4; ++i) acc |= a.v[i] ^ b.v[i];
    // acc == 0  ->  1, иначе 0, без ветвления
    return ((acc | (0 - acc)) >> 63) ^ 1;
}

Fe fePow(const Fe& a, const uint64_t e[4]) {
    Fe result = feOne();
    for (int i = 255; i >= 0; --i) {
        result = feSquare(result);
        Fe t = feMul(result, a);
        result = feSelect((e[i / 64] >> (i % 64)) & 1, t, result);
    }
    return result;
}

Fe feInvert(const Fe& a) { return fePow(a, EXP_P_MINUS_2); }

uint64_t feIsNegative(const Fe& a) { return a.v[0] & 1; }

void feToBytes(const Fe& a, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = (uint8_t)(a.v[i / 8] >> (8 * (i % 8)));
}

bool feFromBytes(const uint8_t in[32], Fe* out) {
    Fe r;
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 7; j >= 0; --j) w = (w << 8) | in[8 * i + j];
        r.v[i] = w;
    }
    // значение должно быть < p (публичные данные, ветвление допустимо)
    Fe reduced = condSubP(r);
    bool canonical = true;
    for (int i = 0; i < 4; ++i) if (reduced.v[i] != r.v[i]) canonical = false;
    if (r.v[3] >> 63) canonical = false;
    *out = r;
    return canonical;
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool feFromHex(const char* hex, Fe* out) {
    uint8_t le[32];
    for (int i = 0; i < 32; ++i) {
        int hi = hexVal(hex[2 * i]), lo = hexVal(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        le[31 - i] = (uint8_t)(hi * 16 + lo);
    }
    return feFromBytes(le, out);
}

// ---------------------------------------------------------------- параметры

static CurveParams g_curve;
static bool g_curveReady = false;

static void hexToBytesLE(const char* hex, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i)
        out[31 - i] = (uint8_t)(hexVal(hex[2 * i]) * 16 + hexVal(hex[2 * i + 1]));
}

const CurveParams& curve() {
    if (!g_curveReady) {
        feFromHex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", &g_curve.d);
        feFromHex("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", &g_curve.Gx);
        feFromHex("6666666666666666666666666666666666666666666666666666666666666658", &g_curve.Gy);
        hexToBytesLE("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", g_curve.q);
        g_curveReady = true;
    }
    return g_curve;
}

// ---------------------------------------------------------------- точки

Point pointIdentity() { Point r; r.X = feZero(); r.Y = feOne(); r.Z = feOne(); return r; }

Point pointFromAffine(const Fe& x, const Fe& y) { Point r; r.X = x; r.Y = y; r.Z = feOne(); return r; }

Point pointBase() { return pointFromAffine(curve().Gx, curve().Gy); }

Point pointNeg(const Point& P) { Point r = P; r.X = feNeg(P.X); return r; }

// A = Z1 Z2, B = A^2, C = X1 X2, D = Y1 Y2, E = d C D, F = B - E, G = B + E
// X3 = A F ((X1+Y1)(X2+Y2) - C - D), Y3 = A G (D - a C) = A G (D + C) при a = -1, Z3 = F G
Point pointAdd(const Point& P, const Point& Q) {
    const Fe& d = curve().d;
    Fe A = feMul(P.Z, Q.Z);
    Fe B = feSquare(A);
    Fe C = feMul(P.X, Q.X);
    Fe D = feMul(P.Y, Q.Y);
    Fe E = feMul(d, feMul(C, D));
    Fe F = feSub(B, E);
    Fe G = feAdd(B, E);
    Fe H = feSub(feSub(feMul(feAdd(P.X, P.Y), feAdd(Q.X, Q.Y)), C), D);
    Point R;
    R.X = feMul(feMul(A, F), H);
    R.Y = feMul(feMul(A, G), feAdd(D, C));
    R.Z = feMul(F, G);
    return R;
}

Point pointDouble(const Point& P) { return pointAdd(P, P); }

void pointToAffine(const Point& P, Fe* x, Fe* y) {
    Fe zi = feInvert(P.Z);
    *x = feMul(P.X, zi);
    *y = feMul(P.Y, zi);
}

uint64_t pointEqual(const Point& P, const Point& Q) {
    uint64_t ex = feEqual(feMul(P.X, Q.Z), feMul(Q.X, P.Z));
    uint64_t ey = feEqual(feMul(P.Y, Q.Z), feMul(Q.Y, P.Z));
    return ex & ey;
}

// -X^2 Z^2 + Y^2 Z^2 = Z^4 + d X^2 Y^2
bool pointOnCurve(const Point& P) {
    Fe X2 = feSquare(P.X), Y2 = feSquare(P.Y), Z2 = feSquare(P.Z);
    Fe lhs = feMul(feSub(Y2, X2), Z2);
    Fe rhs = feAdd(feSquare(Z2), feMul(curve().d, feMul(X2, Y2)));
    return feEqual(lhs, rhs) == 1;
}

void pointEncode(const Point& P, uint8_t out[32]) {
    Fe x, y;
    pointToAffine(P, &x, &y);
    feToBytes(y, out);
    out[31] |= (uint8_t)(feIsNegative(x) << 7);
}

bool pointDecode(const uint8_t in[32], Point* P) {
    uint8_t tmp[32];
    for (int i = 0; i < 32; ++i) tmp[i] = in[i];
    uint64_t sign = tmp[31] >> 7;
    tmp[31] &= 0x7f;
    Fe y;
    if (!feFromBytes(tmp, &y)) return false;
    Fe y2 = feSquare(y);
    Fe u = feSub(y2, feOne());                         // y^2 - 1
    Fe v = feAdd(feMul(curve().d, y2), feOne());       // d y^2 + 1
    Fe v3 = feMul(feSquare(v), v);
    Fe v7 = feMul(feSquare(v3), v);
    Fe x = feMul(feMul(u, v3), fePow(feMul(u, v7), EXP_P_MINUS_5_D8));
    Fe vx2 = feMul(v, feSquare(x));
    if (feEqual(vx2, u) != 1) {
        if (feEqual(vx2, feNeg(u)) != 1) return false; // не квадрат - точки нет
        x = feMul(x, fePow(feFromU64(2), EXP_P_MINUS_1_D4)); // умножаем на sqrt(-1)
    }
    uint64_t xIsZero = feEqual(x, feZero());
    if (xIsZero && sign) return false;
    if (feIsNegative(x) != sign) x = feNeg(x);
    *P = pointFromAffine(x, y);
    return true;
}

Point pointMulDoubleAndAdd(const uint8_t scalar[32], const Point& P) {
    Point R = pointIdentity();
    for (int i = 255; i >= 0; --i) {
        R = pointDouble(R);
        if ((scalar[i / 8] >> (i % 8)) & 1) R = pointAdd(R, P);   // ветвление по биту: небезопасно для секретов
    }
    return R;
}
```

*Модуль 3 — заголовок — `ct_secure.h`*

```cpp
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
```

*Модуль 3 — реализация — `ct_secure.cpp`*

```cpp
#include "ct_secure.h"

Point ctSelectPoint(uint64_t bit, const Point& A, const Point& B) {
    Point r;
    r.X = feSelect(bit, A.X, B.X);
    r.Y = feSelect(bit, A.Y, B.Y);
    r.Z = feSelect(bit, A.Z, B.Z);
    return r;
}

uint64_t ctCompareBytes(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; ++i) acc |= (uint8_t)(a[i] ^ b[i]);
    uint64_t v = acc;
    return ((v | (0 - v)) >> 63) ^ 1;
}

uint64_t SecureCompare(const Point& A, const Point& B) {
    return pointEqual(A, B);
}

Point SecureMultiply(const uint8_t scalar[32], const Point& P) {
    Point R = pointIdentity();
    for (int i = 255; i >= 0; --i) {
        R = pointDouble(R);                        // единая формула, как и при сложении
        Point T = pointAdd(R, P);                  // единая формула
        uint64_t bit = (scalar[i / 8] >> (i % 8)) & 1;
        R = ctSelectPoint(bit, T, R);              // выбор маской, без if
    }
    return R;
}
```

*Модуль 2 — заголовок — `protocols.h`*

```cpp
#ifndef PROTOCOLS_H
#define PROTOCOLS_H

// Модуль 2. SHA-512, ECDH на кривой Эдвардса и подпись EdDSA (Ed25519, RFC 8032).

#include <cstdint>
#include <cstddef>
#include "ec_algebra.h"

// ---- SHA-512 (собственная реализация) ----
struct Sha512 {
    uint64_t h[8];
    uint8_t buf[128];
    uint64_t totalLen;
    size_t bufLen;
};
void sha512Init(Sha512* s);
void sha512Update(Sha512* s, const uint8_t* data, size_t len);
void sha512Final(Sha512* s, uint8_t out[64]);
void sha512(const uint8_t* data, size_t len, uint8_t out[64]);

// ---- ключи ----
struct KeyPair {
    uint8_t seed[32];       // секретное начальное значение
    uint8_t scalar[32];     // секретный скаляр a (после clamping), little-endian
    uint8_t prefix[32];     // вторая половина SHA-512(seed)
    uint8_t publicKey[32];  // A = a*G (сжатое представление)
};
void eddsaKeyFromSeed(const uint8_t seed[32], KeyPair* kp);

// ---- ЭЦП ----
void eddsaSign(const KeyPair& kp, const uint8_t* msg, size_t msgLen, uint8_t sig[64]);
bool eddsaVerify(const uint8_t publicKey[32], const uint8_t* msg, size_t msgLen, const uint8_t sig[64]);

// ---- ECDH ----
// Закрытый скаляр - clamped SHA-512(seed) (кофактор 8 убирается очисткой трёх младших бит).
bool ecdhSharedSecret(const uint8_t scalar[32], const uint8_t peerPublic[32], uint8_t shared[32]);

#endif
```

*Модуль 2 — реализация — `protocols.cpp`*

```cpp
#include "protocols.h"
#include "ct_secure.h"
#include <gmp.h>   // только арифметика больших чисел по модулю q

// ================================================================ SHA-512

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512Block(Sha512* s, const uint8_t* block) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v = (v << 8) | block[8 * i + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint64_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void sha512Init(Sha512* s) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    for (int i = 0; i < 8; ++i) s->h[i] = iv[i];
    s->totalLen = 0;
    s->bufLen = 0;
}

void sha512Update(Sha512* s, const uint8_t* data, size_t len) {
    s->totalLen += len;
    for (size_t i = 0; i < len; ++i) {
        s->buf[s->bufLen++] = data[i];
        if (s->bufLen == 128) { sha512Block(s, s->buf); s->bufLen = 0; }
    }
}

void sha512Final(Sha512* s, uint8_t out[64]) {
    uint64_t bitLen = s->totalLen * 8;
    uint8_t pad = 0x80;
    sha512Update(s, &pad, 1);
    uint8_t zero = 0;
    while (s->bufLen != 112) sha512Update(s, &zero, 1);
    for (int i = 0; i < 8; ++i) sha512Update(s, &zero, 1);           // старшие 64 бита длины
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; ++i) lenBytes[i] = (uint8_t)(bitLen >> (56 - 8 * i));
    sha512Update(s, lenBytes, 8);
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 8; ++j) out[8 * i + j] = (uint8_t)(s->h[i] >> (56 - 8 * j));
}

void sha512(const uint8_t* data, size_t len, uint8_t out[64]) {
    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, data, len);
    sha512Final(&s, out);
}

// ================================================================ скаляры (GMP: только mod q)

static void bytesToMpz(mpz_t z, const uint8_t* b, size_t n) { mpz_import(z, n, -1, 1, 0, 0, b); }

static void mpzToBytes32(const mpz_t z, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = 0;
    size_t count = 0;
    uint8_t tmp[64];
    mpz_export(tmp, &count, -1, 1, 0, 0, z);
    for (size_t i = 0; i < count && i < 32; ++i) out[i] = tmp[i];
}

static void loadQ(mpz_t q) { bytesToMpz(q, curve().q, 32); }

// SHA-512(...) mod q
static void hashToScalar(const uint8_t digest[64], uint8_t out[32]) {
    mpz_t z, q;
    mpz_inits(z, q, NULL);
    bytesToMpz(z, digest, 64);
    loadQ(q);
    mpz_mod(z, z, q);
    mpzToBytes32(z, out);
    mpz_clears(z, q, NULL);
}

static void clampScalar(const uint8_t h[32], uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = h[i];
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

// ================================================================ EdDSA

void eddsaKeyFromSeed(const uint8_t seed[32], KeyPair* kp) {
    uint8_t h[64];
    sha512(seed, 32, h);
    for (int i = 0; i < 32; ++i) { kp->seed[i] = seed[i]; kp->prefix[i] = h[32 + i]; }
    clampScalar(h, kp->scalar);
    Point A = SecureMultiply(kp->scalar, pointBase());   // секретный скаляр: только constant-time умножение
    pointEncode(A, kp->publicKey);
}

void eddsaSign(const KeyPair& kp, const uint8_t* msg, size_t msgLen, uint8_t sig[64]) {
    uint8_t digest[64], r[32], k[32];

    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, kp.prefix, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, r);                              // r = SHA-512(prefix || M) mod q

    Point R = SecureMultiply(r, pointBase());             // R = r * G
    pointEncode(R, sig);

    sha512Init(&s);
    sha512Update(&s, sig, 32);
    sha512Update(&s, kp.publicKey, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, k);                              // k = SHA-512(R || A || M) mod q

    mpz_t zr, zk, za, zS, q;
    mpz_inits(zr, zk, za, zS, q, NULL);
    bytesToMpz(zr, r, 32);
    bytesToMpz(zk, k, 32);
    bytesToMpz(za, kp.scalar, 32);
    loadQ(q);
    mpz_mul(zS, zk, za);
    mpz_add(zS, zS, zr);
    mpz_mod(zS, zS, q);                                   // S = (r + k * a) mod q
    mpzToBytes32(zS, sig + 32);
    mpz_clears(zr, zk, za, zS, q, NULL);
}

bool eddsaVerify(const uint8_t publicKey[32], const uint8_t* msg, size_t msgLen, const uint8_t sig[64]) {
    Point A, R;
    if (!pointDecode(publicKey, &A)) return false;
    if (!pointDecode(sig, &R)) return false;

    mpz_t zS, q;
    mpz_inits(zS, q, NULL);
    bytesToMpz(zS, sig + 32, 32);
    loadQ(q);
    bool sOk = mpz_cmp(zS, q) < 0;                        // требуем S < q
    mpz_clears(zS, q, NULL);
    if (!sOk) return false;

    uint8_t digest[64], k[32];
    Sha512 s;
    sha512Init(&s);
    sha512Update(&s, sig, 32);
    sha512Update(&s, publicKey, 32);
    sha512Update(&s, msg, msgLen);
    sha512Final(&s, digest);
    hashToScalar(digest, k);

    Point left = pointMulDoubleAndAdd(sig + 32, pointBase());          // S * G
    Point right = pointAdd(R, pointMulDoubleAndAdd(k, A));             // R + k * A
    return pointEqual(left, right) == 1;                               // публичные данные
}

// ================================================================ ECDH

bool ecdhSharedSecret(const uint8_t scalar[32], const uint8_t peerPublic[32], uint8_t shared[32]) {
    Point Q;
    if (!pointDecode(peerPublic, &Q)) return false;
    Point S = SecureMultiply(scalar, Q);
    if (pointEqual(S, pointIdentity()) == 1) return false;            // вырожденная точка малого порядка
    pointEncode(S, shared);
    return true;
}
```

*Главный файл с тестами — `main.cpp`*

```cpp
#include <cstdio>
#include <cstring>
#include <chrono>
#include "ec_algebra.h"
#include "ct_secure.h"
#include "protocols.h"

static int g_failed = 0;

static void check(const char* name, bool ok) {
    std::printf("%-78s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_failed;
}

static void hexToBytes(const char* hex, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned v = 0;
        std::sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void printHex(const char* label, const uint8_t* d, size_t n) {
    std::printf("%s: ", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

static void printFe(const char* label, const Fe& f) {
    uint8_t le[32];
    feToBytes(f, le);
    std::printf("%s: ", label);
    for (int i = 31; i >= 0; --i) std::printf("%02x", le[i]);   // big-endian hex
    std::printf("\n");
}

static void printPoint(const char* label, const Point& P) {
    Fe x, y;
    pointToAffine(P, &x, &y);
    std::printf("%s\n", label);
    printFe("  x", x);
    printFe("  y", y);
}

static void scalarFromU64(uint64_t v, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = i < 8 ? (uint8_t)(v >> (8 * i)) : 0;
}

struct Vector {
    const char* name;
    const char* seed;
    const char* pub;
    const char* msgHex;
    const char* sig;
};

int main() {
    std::printf("=== Модуль 1: поле и кривая ===\n");
    const Point G = pointBase();
    printPoint("Базовая точка G (hex, big-endian):", G);
    check("G лежит на кривой -x^2 + y^2 = 1 + d x^2 y^2", pointOnCurve(G));

    {   // инверсия в поле
        Fe a = feFromU64(123456789);
        check("a * a^(-1) = 1 в GF(p)", feEqual(feMul(a, feInvert(a)), feOne()) == 1);
        Fe m1 = feNeg(feOne());
        check("(-1)^2 = 1 в GF(p)", feEqual(feSquare(m1), feOne()) == 1);
    }

    std::printf("\n=== Единая формула сложения и удвоения (вариант 8) ===\n");
    {
        // Полнота формулы: a = -1 - квадрат, d - квадратичный невычет в GF(p)
        static const uint64_t HALF[4] = {0xfffffffffffffff6ULL, 0xffffffffffffffffULL,
                                         0xffffffffffffffffULL, 0x3fffffffffffffffULL};  // (p - 1) / 2
        static const uint64_t QUARTER[4] = {0xfffffffffffffffbULL, 0xffffffffffffffffULL,
                                            0xffffffffffffffffULL, 0x1fffffffffffffffULL}; // (p - 1) / 4
        Fe minusOne = feNeg(feOne());
        check("d - квадратичный невычет: d^((p-1)/2) = -1", feEqual(fePow(curve().d, HALF), minusOne) == 1);
        Fe i = fePow(feFromU64(2), QUARTER);
        check("a = -1 - квадрат: существует i, i^2 = -1", feEqual(feSquare(i), minusOne) == 1);
        Point G2a = pointDouble(G);                       // удвоение той же функцией pointAdd(G, G)
        Point G2b = pointAdd(G, G);
        check("Double(G) == Add(G, G): одна формула без ветвления P == Q", pointEqual(G2a, G2b) == 1);
        // независимая проверка удвоения аффинной формулой: x3 = 2xy / (y^2 - x^2), y3 = (y^2 + x^2) / (2 - y^2 + x^2)
        Fe x = curve().Gx, y = curve().Gy;
        Fe x2 = feSquare(x), y2 = feSquare(y);
        Fe x3 = feMul(feAdd(feMul(x, y), feMul(x, y)), feInvert(feSub(y2, x2)));
        Fe y3 = feMul(feAdd(y2, x2), feInvert(feAdd(feSub(feFromU64(2), y2), x2)));
        check("Add(G, G) совпадает с аффинной формулой удвоения кривой Эдвардса",
              pointEqual(G2a, pointFromAffine(x3, y3)) == 1);
        check("2G лежит на кривой", pointOnCurve(G2a));
        check("Add(G, O) == G (нейтральный элемент без особого случая)", pointEqual(pointAdd(G, pointIdentity()), G) == 1);
        check("Add(O, O) == O", pointEqual(pointAdd(pointIdentity(), pointIdentity()), pointIdentity()) == 1);
        check("Add(G, -G) == O (взаимно обратные точки без особого случая)",
              pointEqual(pointAdd(G, pointNeg(G)), pointIdentity()) == 1);
        Point G3a = pointAdd(G2a, G), G3b = pointAdd(G, G2a);
        check("Add коммутативно: 2G + G == G + 2G", pointEqual(G3a, G3b) == 1);
        check("Add ассоциативно: (G + 2G) + G == G + (2G + G)",
              pointEqual(pointAdd(G3a, G), pointAdd(G, G3a)) == 1);
    }

    std::printf("\n=== Скалярное умножение ===\n");
    {
        uint8_t k5[32], k7[32];
        scalarFromU64(5, k5);
        scalarFromU64(7, k7);
        Point g5 = SecureMultiply(k5, G);
        Point manual = pointAdd(pointDouble(pointDouble(G)), G);
        check("SecureMultiply(5, G) == 4G + G", pointEqual(g5, manual) == 1);
        check("SecureMultiply == классический Double-and-Add для k = 5, 7",
              pointEqual(g5, pointMulDoubleAndAdd(k5, G)) == 1 &&
              pointEqual(SecureMultiply(k7, G), pointMulDoubleAndAdd(k7, G)) == 1);

        const uint8_t* q = curve().q;
        check("q * G == O (порядок подгруппы)", pointEqual(SecureMultiply(q, G), pointIdentity()) == 1);
        uint8_t q1[32];
        std::memcpy(q1, q, 32);
        q1[0] += 1;                                       // младший байт q = 0xed, переноса нет
        check("(q + 1) * G == G", pointEqual(SecureMultiply(q1, G), G) == 1);
        uint8_t zero[32] = {0};
        check("0 * G == O", pointEqual(SecureMultiply(zero, G), pointIdentity()) == 1);

        uint8_t enc[32];
        pointEncode(g5, enc);
        Point back;
        bool dec = pointDecode(enc, &back);
        check("Кодирование и декодирование точки 5G", dec && pointEqual(back, g5) == 1);
        enc[31] ^= 0x80;
        Point neg;
        bool dec2 = pointDecode(enc, &neg);
        check("Инвертированный бит знака x даёт точку -5G", dec2 && pointEqual(neg, pointNeg(g5)) == 1);
    }

    std::printf("\n=== SHA-512 (собственная реализация) ===\n");
    {
        uint8_t out[64], exp[64];
        sha512((const uint8_t*)"abc", 3, out);
        hexToBytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", exp, 64);
        check("SHA-512(\"abc\")", std::memcmp(out, exp, 64) == 0);
        sha512((const uint8_t*)"", 0, out);
        hexToBytes("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", exp, 64);
        check("SHA-512(\"\")", std::memcmp(out, exp, 64) == 0);
        uint8_t long_msg[200];
        for (int i = 0; i < 200; ++i) long_msg[i] = (uint8_t)i;
        sha512(long_msg, 200, out);
        printHex("SHA-512(00..c7), 200 байт, 2 блока", out, 64);
    }

    std::printf("\n=== EdDSA Ed25519: тестовые векторы ===\n");
    const Vector vectors[] = {
        {"RFC 8032, TEST 1 (пустое сообщение)",
         "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"RFC 8032, TEST 2 (1 байт: 72)",
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"Эталон OpenSSL 3.6.3 (pkeyutl -sign -rawin)",
         "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
         "712651f450ba05b63898b99ef5f7ba45632e8e2527f7f715cd671ec4024cc51e",
         "4b4d5a49206c6162332076617269616e742038",
         "93378adbdc01af68e3ee113b125e1641e2a81c46941eb1977bb533b9ae9cb62c80939dd730ee99b09a74943eb903f5e3d8dfed97d48ba531433a5935d7ba3509"}};
    for (const Vector& v : vectors) {
        uint8_t seed[32], pub[32], sig[64], msg[64], got[64];
        size_t mlen = std::strlen(v.msgHex) / 2;
        hexToBytes(v.seed, seed, 32);
        hexToBytes(v.pub, pub, 32);
        hexToBytes(v.sig, sig, 64);
        hexToBytes(v.msgHex, msg, mlen);
        KeyPair kp;
        eddsaKeyFromSeed(seed, &kp);
        std::printf("%s\n", v.name);
        printHex("  публичный ключ ", kp.publicKey, 32);
        eddsaSign(kp, msg, mlen, got);
        printHex("  подпись (R||S) ", got, 64);
        check("  публичный ключ совпадает с эталоном", std::memcmp(kp.publicKey, pub, 32) == 0);
        check("  подпись совпадает с эталоном (EdDSA детерминирован)", std::memcmp(got, sig, 64) == 0);
        check("  проверка подписи успешна", eddsaVerify(kp.publicKey, msg, mlen, got));
    }

    std::printf("\n=== ECDH на кривой Эдвардса ===\n");
    {
        uint8_t seedA[32], seedB[32], sharedA[32], sharedB[32];
        for (int i = 0; i < 32; ++i) { seedA[i] = (uint8_t)(i + 1); seedB[i] = (uint8_t)(0xA0 ^ (i * 7)); }
        KeyPair alice, bob;
        eddsaKeyFromSeed(seedA, &alice);
        eddsaKeyFromSeed(seedB, &bob);
        printHex("Alice, открытый ключ Q_A", alice.publicKey, 32);
        printHex("Bob,   открытый ключ Q_B", bob.publicKey, 32);
        bool okA = ecdhSharedSecret(alice.scalar, bob.publicKey, sharedA);
        bool okB = ecdhSharedSecret(bob.scalar, alice.publicKey, sharedB);
        printHex("Shared Secret у Alice (d_A * Q_B)", sharedA, 32);
        printHex("Shared Secret у Bob   (d_B * Q_A)", sharedB, 32);
        check("Alice и Bob получили одинаковый Shared Secret", okA && okB && ctCompareBytes(sharedA, sharedB, 32) == 1);
        uint8_t other[32];
        KeyPair eve;
        uint8_t seedE[32];
        for (int i = 0; i < 32; ++i) seedE[i] = (uint8_t)(0x55 + i);
        eddsaKeyFromSeed(seedE, &eve);
        ecdhSharedSecret(eve.scalar, bob.publicKey, other);
        check("Третья сторона (Eve) получает другой секрет", ctCompareBytes(sharedA, other, 32) == 0);
        uint8_t identity[32] = {1};                       // y = 1, x = 0: нейтральный элемент
        uint8_t dummy[32];
        check("Публичный ключ - нейтральный элемент отвергается", !ecdhSharedSecret(alice.scalar, identity, dummy));
    }

    std::printf("\n=== Подпись - проверка и отбраковка искажений ===\n");
    {
        uint8_t seed[32];
        for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(0xC3 + 5 * i);
        KeyPair kp;
        eddsaKeyFromSeed(seed, &kp);
        const char* texts[] = {"KMZI", "Variant 8: Ed25519, unified addition", "The quick brown fox jumps over the lazy dog"};
        for (const char* t : texts) {
            const uint8_t* m = (const uint8_t*)t;
            size_t n = std::strlen(t);
            uint8_t sig[64];
            eddsaSign(kp, m, n, sig);
            printHex("  подпись", sig, 64);
            check("  сообщение подписано и проверено", eddsaVerify(kp.publicKey, m, n, sig));
            uint8_t badS[64];
            std::memcpy(badS, sig, 64);
            badS[40] ^= 0x01;                             // один бит в параметре S
            check("  искажение одного байта в S отвергнуто", !eddsaVerify(kp.publicKey, m, n, badS));
            uint8_t badR[64];
            std::memcpy(badR, sig, 64);
            badR[5] ^= 0x01;
            check("  искажение одного байта в R отвергнуто", !eddsaVerify(kp.publicKey, m, n, badR));
            uint8_t badM[64];
            std::memcpy(badM, t, n);
            badM[0] ^= 0x01;
            check("  искажение сообщения отвергнуто", !eddsaVerify(kp.publicKey, badM, n, sig));
            uint8_t badQ[32];
            std::memcpy(badQ, kp.publicKey, 32);
            badQ[0] ^= 0x01;
            check("  чужой открытый ключ отвергнут", !eddsaVerify(badQ, m, n, sig));
            uint8_t big[64];                              // S + q: должен отбрасываться проверкой S < q
            std::memcpy(big, sig, 64);
            check("  S >= q отвергается (неоднозначность подписи)", [&] {
                const uint8_t* q = curve().q;
                unsigned carry = 0;
                for (int i = 0; i < 32; ++i) { unsigned s = big[32 + i] + q[i] + carry; big[32 + i] = (uint8_t)s; carry = s >> 8; }
                return !eddsaVerify(kp.publicKey, m, n, big);
            }());
        }
    }

    std::printf("\n=== Индикативный замер времени (лучший из 7 раундов по 100 вызовов; не доказательство) ===\n");
    {
        uint8_t kLow[32] = {0}, kHigh[32], kMix[32];
        kLow[0] = 1;                                      // вес Хэмминга 1
        for (int i = 0; i < 32; ++i) { kHigh[i] = 0xFF; kMix[i] = (uint8_t)(0xA5 + i * 13); }
        const uint8_t* ks[3] = {kLow, kHigh, kMix};
        const char* names[3] = {"k = 1 (вес Хэмминга 1)", "k = 2^256-1 (вес 256)  ", "k = смешанный          "};
        auto bench = [&](bool secure, const uint8_t* k) {
            double best = 1e18;
            for (int round = 0; round < 7; ++round) {
                auto t0 = std::chrono::steady_clock::now();
                for (int it = 0; it < 100; ++it) {
                    Point R = secure ? SecureMultiply(k, G) : pointMulDoubleAndAdd(k, G);
                    asm volatile("" : : "r"(&R) : "memory");
                }
                auto t1 = std::chrono::steady_clock::now();
                double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / 100.0;
                if (us < best) best = us;
            }
            return best;
        };
        bench(true, kMix); bench(false, kMix);            // прогрев
        double sec[3], naive[3];
        for (int t = 0; t < 3; ++t) { sec[t] = bench(true, ks[t]); naive[t] = bench(false, ks[t]); }
        for (int t = 0; t < 3; ++t)
            std::printf("  SecureMultiply          %s: %7.1f мкс (%+.1f%% к k=1)\n", names[t], sec[t], 100.0 * (sec[t] - sec[0]) / sec[0]);
        for (int t = 0; t < 3; ++t)
            std::printf("  Классический Double-Add %s: %7.1f мкс (%+.1f%% к k=1)\n", names[t], naive[t], 100.0 * (naive[t] - naive[0]) / naive[0]);
    }

    std::printf("\nИтог: %s\n", g_failed == 0 ? "все тесты пройдены" : "ЕСТЬ ОШИБКИ");
    return g_failed == 0 ? 0 : 1;
}
```

*Сборка — `CMakeLists.txt`*

```cpp
cmake_minimum_required(VERSION 3.10)
project(lab3_ed25519_variant8 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# GMP используется только для арифметики больших чисел по модулю q (скаляры подписи)
find_path(GMP_INCLUDE_DIR gmp.h HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(GMP_LIBRARY gmp HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
include_directories(${GMP_INCLUDE_DIR})

add_executable(main
    ./ec_algebra.cpp
    ./ct_secure.cpp
    ./protocols.cpp
    ./main.cpp
)
target_link_libraries(main ${GMP_LIBRARY})
```


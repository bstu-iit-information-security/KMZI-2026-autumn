#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <numeric>
#include <cassert>
#include <iomanip>
#include <algorithm>

using namespace std;

long long gcd(long long a, long long b) {
    while (b) {
        a %= b;
        swap(a, b);
    }
    return a;
}

long long modPow(long long base, long long exp, long long mod) {
    long long res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (__int128(res) * base) % mod;
        base = (__int128(base) * base) % mod;
        exp /= 2;
    }
    return res;
}

int eulerPhi(int n) {
    int res = n;
    for (int p = 2; p * p <= n; ++p) {
        if (n % p == 0) {
            while (n % p == 0) n /= p;
            res -= res / p;
        }
    }
    if (n > 1) res -= res / n;
    return res;
}

struct DeutschOracle {
    int type;
    int eval(int x) const {
        if (type == 1) return 0;
        if (type == 2) return x;
        if (type == 3) return 1 - x;
        return 1;
    }
    bool isConstant() const {
        return (type == 1 || type == 4);
    }
};

bool runDeutschAlgorithm(const DeutschOracle& oracle) {
    int f0 = oracle.eval(0);
    int f1 = oracle.eval(1);

    double amp0 = (pow(-1.0, f0) + pow(-1.0, f1)) / 2.0;
    double prob0 = amp0 * amp0;

    return (prob0 > 0.99);
}

void testDeutsch() {
    cout << "[Задание 1] Тестирование алгоритма Дойча:\n";
    cout << " Оракул | f(0) | f(1) | Тип функции   | Результат алгоритма | Статус\n";
    cout << "--------+------+------+---------------+---------------------+--------\n";
    for (int type = 1; type <= 4; ++type) {
        DeutschOracle oracle{type};
        bool isConst = runDeutschAlgorithm(oracle);
        assert(isConst == oracle.isConstant());
        cout << " f_" << type << "    |  " << oracle.eval(0) << "   |  "
             << oracle.eval(1) << "   | "
             << (oracle.isConstant() ? "Постоянная   " : "Сбалансиров. ") << "| "
             << (isConst ? "Постоянная       " : "Сбалансированная ") << "| OK\n";
    }
    cout << "[+] Алгоритм Дойча успешно распознал все 4 функции с 1 вызова оракула!\n\n";
}

void testDeutschJozsa() {
    cout << "[Задание 2] Алгоритм Дойча-Йожи (n = 3 кубита):\n";
    int n = 3;
    int N = 1 << n;

    double sumConst = 0;
    for (int x = 0; x < N; ++x) sumConst += pow(-1.0, 1);
    double prob0_const = (sumConst / N) * (sumConst / N);
    assert(abs(prob0_const - 1.0) < 1e-6);

    double sumBalanced = 0;
    for (int x = 0; x < N; ++x) sumBalanced += pow(-1.0, x & 1);
    double prob0_bal = (sumBalanced / N) * (sumBalanced / N);
    assert(abs(prob0_bal - 0.0) < 1e-6);

    cout << "  - Постоянная функция: P(|0...0>) = " << prob0_const << " (100% распознавание)\n";
    cout << "  - Сбалансированная:  P(|0...0>) = " << prob0_bal << " (0% попадания в |0...0>)\n";
    cout << "[+] Алгоритм Дойча-Йожи подтверждён!\n\n";
}

long long findOrderFromPhase(long long y, long long two_m, long long N, long long a) {
    long long p0 = 0, p1 = 1;
    long long q0 = 1, q1 = 0;
    long long num = y, den = two_m;

    while (den != 0) {
        long long q = num / den;
        long long rem = num % den;

        long long p2 = q * p1 + p0;
        long long q2 = q * q1 + q0;

        if (q2 >= N) break;

        if (q2 > 1 && modPow(a, q2, N) == 1) {
            return q2;
        }

        p0 = p1; p1 = p2;
        q0 = q1; q1 = q2;
        num = den;
        den = rem;
    }
    return -1;
}

void testShorVariant7() {
    const long long N = 35;
    const long long a = 2;

    cout << "[Задание 3-6] Алгоритм Шора (Вариант 7: Таблица А):\n";
    cout << "  Составное число N = " << N << ", Основание a = " << a << "\n";

    long long g = gcd(a, N);
    cout << "  1. Проверка взаимной простоты: gcd(" << a << ", " << N << ") = " << g << "\n";
    assert(g == 1);

    long long true_r = 1;
    while (modPow(a, true_r, N) != 1) {
        true_r++;
    }
    cout << "  2. Порядок числа a = 2 по модулю 35: r = " << true_r << "\n";
    assert(true_r == 12);

    int n = (int)ceil(log2(N));
    int m = 2 * n;
    long long two_m = 1LL << m;

    cout << "  3. Параметры квантовой схемы:\n";
    cout << "     - Целевой регистр: n = ceil(log2(" << N << ")) = " << n << " кубитов\n";
    cout << "     - Управляющий регистр: m = 2n = " << m << " кубитов (размерность 2^m = " << two_m << ")\n";

    cout << "\n  4. Моделирование фазовой оценки и квантовых измерений:\n";
    cout << "   s | Фаза s/r | Дискретное y | Непрерывная дробь (r) | Статус кандидата\n";
    cout << "  ---+----------+--------------+-----------------------+------------------\n";

    int successfulMeasurements = 0;
    for (int s = 0; s < true_r; ++s) {
        double phase = (double)s / true_r;
        long long y = llround(phase * two_m);
        long long cand_r = findOrderFromPhase(y, two_m, N, a);

        bool success = (cand_r == true_r);
        if (success) successfulMeasurements++;

        cout << "  " << setw(2) << s << " |  "
             << fixed << setprecision(4) << phase << "  |     "
             << setw(4) << y << "     |           "
             << (cand_r > 0 ? to_string(cand_r) : "-") << "          | "
             << (success ? "Засчитано (r=12)" : "Делитель r (или 0)") << "\n";
    }

    double successRate = (double)successfulMeasurements / true_r;
    double theorRate = (double)eulerPhi((int)true_r) / true_r;

    cout << "\n  Доля успешных измерений порядка r: " << successRate * 100.0 << "%\n";
    cout << "  Теоретическая величина phi(r)/r:   " << theorRate * 100.0 << "%\n";
    assert(abs(successRate - theorRate) < 1e-4);
    cout << "  [+] Доля засчитанных измерений в точности равна phi(r)/r!\n\n";

    cout << "  5. Факторизация числа N = " << N << " по найденному порядку r = 12:\n";
    assert(true_r % 2 == 0);
    long long half_r = true_r / 2;
    long long x = modPow(a, half_r, N);
    cout << "     x = a^(r/2) mod N = 2^6 mod 35 = " << x << "\n";
    assert(x != N - 1 && x != 1);

    long long p = gcd(x - 1, N);
    long long q = gcd(x + 1, N);

    cout << "     d1 = gcd(x - 1, N) = gcd(" << x - 1 << ", " << N << ") = " << p << "\n";
    cout << "     d2 = gcd(x + 1, N) = gcd(" << x + 1 << ", " << N << ") = " << q << "\n";

    assert(p * q == N);
    assert(p > 1 && p < N);
    assert(q > 1 && q < N);

    cout << "\n  [+] УСПЕХ: Найдены нетривиальные множители числа " << N << ": " << p << " и " << q << "!\n";
    cout << "      Проверка: " << p << " * " << q << " = " << (p * q) << "\n\n";
}

int main() {
    cout << "====================================================================\n";
    cout << " Лабораторная работа №6 (КМЗИ) - Вариант 7\n";
    cout << " Алгоритмы Дойча, Дойча-Йожи. Алгоритм Шора\n";
    cout << "====================================================================\n\n";

    testDeutsch();
    testDeutschJozsa();
    testShorVariant7();

    cout << "====================================================================\n";
    cout << "[+] Все алгоритмы и тесты Лабораторной работы №6 успешно выполнены!\n";
    cout << "====================================================================\n";
    return 0;
}

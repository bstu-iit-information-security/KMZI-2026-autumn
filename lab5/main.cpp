#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <iomanip>
#include <cassert>
#include <random>
#include <algorithm>

using namespace std;

struct FullAdderCircuit {
    static void run(int A, int B, int X, int& S, int& C) {
        int q0 = A, q1 = B, q2 = X;
        int q3 = 0, q4 = 0;

        q3 ^= q0;
        q3 ^= q1;
        q3 ^= q2;

        if (q0 && q1) q4 ^= 1;
        q1 ^= q0;
        if (q1 && q2) q4 ^= 1;
        q1 ^= q0;

        S = q3;
        C = q4;
    }
};

void testFullAdder() {
    cout << "[Задание 1] Проверка полного 5-кубитного сумматора:\n";
    cout << " A | B | X | Ожид (S, C) | Получ (S, C) | Статус\n";
    cout << "---+---+---+-------------+--------------+--------\n";
    for (int a = 0; a <= 1; ++a) {
        for (int b = 0; b <= 1; ++b) {
            for (int x = 0; x <= 1; ++x) {
                int expS = (a + b + x) % 2;
                int expC = (a + b + x) / 2;
                int actS = 0, actC = 0;
                FullAdderCircuit::run(a, b, x, actS, actC);
                assert(actS == expS && actC == expC);
                cout << " " << a << " | " << b << " | " << x
                     << " |      (" << expS << ", " << expC << ")  |       ("
                     << actS << ", " << actC << ")   | OK\n";
            }
        }
    }
    cout << "[+] Полный сумматор успешно протестирован на всех 8 комбинациях!\n\n";
}

void test4BitAdder() {
    cout << "[Задание 1.4] Тестирование 4-битного каскадного сумматора (256 пар чисел):\n";
    for (int a = 0; a < 16; ++a) {
        for (int b = 0; b < 16; ++b) {
            int carry = 0;
            int sum = 0;
            for (int bit = 0; bit < 4; ++bit) {
                int bitA = (a >> bit) & 1;
                int bitB = (b >> bit) & 1;
                int sBit = 0, nextCarry = 0;
                FullAdderCircuit::run(bitA, bitB, carry, sBit, nextCarry);
                sum |= (sBit << bit);
                carry = nextCarry;
            }
            sum |= (carry << 4);
            assert(sum == a + b);
        }
    }
    cout << "[+] Все 256 пар 4-битных сложений проверены программно!\n\n";
}

bool classicalF7(int A, int B, int C, int D) {
    return (A && B) || (C && D) || (A && C);
}

void q_and(int in1, int in2, int& out) {
    if (in1 && in2) out ^= 1;
}

void q_or(int in1, int in2, int& out) {
    int not1 = in1 ^ 1;
    int not2 = in2 ^ 1;
    int nandVal = 0;
    if (not1 && not2) nandVal ^= 1;
    out ^= (nandVal ^ 1);
}

void quantumF7(int A, int B, int C, int D, int& out, vector<int>& ancilla) {
    ancilla.assign(5, 0);

    q_and(A, B, ancilla[0]);
    q_and(C, D, ancilla[1]);
    q_and(A, C, ancilla[2]);
    q_or(ancilla[0], ancilla[1], ancilla[3]);
    q_or(ancilla[3], ancilla[2], ancilla[4]);

    out = ancilla[4];

    q_or(ancilla[3], ancilla[2], ancilla[4]);
    q_or(ancilla[0], ancilla[1], ancilla[3]);
    q_and(A, C, ancilla[2]);
    q_and(C, D, ancilla[1]);
    q_and(A, B, ancilla[0]);
}

void testVariant7Function() {
    cout << "[Задание 2] Тестирование функции F(A, B, C, D) = (A & B) | (C & D) | (A & C):\n";
    cout << " A B C D | F_классич | F_квантов | Вспом. кубиты в |0> | Статус\n";
    cout << "---------+-----------+-----------+---------------------+--------\n";
    for (int A = 0; A <= 1; ++A) {
        for (int B = 0; B <= 1; ++B) {
            for (int C = 0; C <= 1; ++C) {
                for (int D = 0; D <= 1; ++D) {
                    bool expF = classicalF7(A, B, C, D);
                    int actF = 0;
                    vector<int> anc;
                    quantumF7(A, B, C, D, actF, anc);

                    bool allZero = true;
                    for (int x : anc) if (x != 0) allZero = false;

                    assert(actF == (int)expF);
                    assert(allZero);

                    cout << " " << A << " " << B << " " << C << " " << D
                         << " |     " << expF << "     |     " << actF
                         << "     |         " << (allZero ? "Да (|00000>)" : "Нет")
                         << "         | OK\n";
                }
            }
        }
    }
    cout << "[+] Все 16 наборов проверены! Uncomputation вернул все вспомогательные кубиты в |0>.\n\n";
}

void runGroverVariant7() {
    const int n = 5;
    const int N = 1 << n;
    const int marked = 0b10010;

    cout << "[Задание 7] Моделирование алгоритма Гровера (Вариант 7):\n";
    cout << "  Число кубитов n = " << n << ", Размер базы N = " << N << "\n";
    cout << "  Отмеченное состояние |w> = |10010> (18)\n";

    double k_theor = floor((M_PI / 4.0) * sqrt(N));
    cout << "  Теоретическое оптимальное число итераций k_теор = floor(pi/4 * sqrt(32)) = " << (int)k_theor << "\n\n";

    vector<double> state(N, 1.0 / sqrt(N));

    cout << "  k | Точная вероятность P_точн(k) | Симуляция (1024 shots) | Примечание\n";
    cout << "----+------------------------------+------------------------+------------\n";

    int maxK = 0;
    double maxProb = 0.0;

    mt19937 rng(42);

    for (int k = 0; k <= 15; ++k) {
        double prob = state[marked] * state[marked];
        if (prob > maxProb) {
            maxProb = prob;
            maxK = k;
        }

        int countTarget = 0;
        discrete_distribution<int> dist(state.begin(), state.end());
        for (int s = 0; s < 1024; ++s) {
            int measured = dist(rng);
            if (measured == marked) countTarget++;
        }
        double expProb = (double)countTarget / 1024.0;

        cout << " " << setw(2) << k << " |           "
             << fixed << setprecision(5) << prob << "            |         "
             << setprecision(5) << expProb << "        | "
             << (k == (int)k_theor ? "<-- ТЕОРЕТИЧЕСКИЙ ОПТИМУМ" : "") << "\n";

        state[marked] = -state[marked];

        double mean = 0.0;
        for (double a : state) mean += a;
        mean /= N;
        for (int i = 0; i < N; ++i) {
            state[i] = 2.0 * mean - state[i];
        }
    }

    cout << "\n[+] Итог задания 7:\n";
    cout << "    - k_теор:          " << (int)k_theor << "\n";
    cout << "    - k_точн (максимум): " << maxK << "\n";
    cout << "    - Максимальная P:  " << fixed << setprecision(5) << maxProb * 100.0 << "%\n";
    assert(maxK == (int)k_theor);
    cout << "    - Подтверждено: k_точн строго совпадает с k_теор!\n\n";
}

int main() {
    cout << "====================================================================\n";
    cout << " Лабораторная работа №5 (КМЗИ) - Вариант 7\n";
    cout << " Квантовые сумматоры. Алгоритм Гровера\n";
    cout << "====================================================================\n\n";

    testFullAdder();
    test4BitAdder();
    testVariant7Function();
    runGroverVariant7();

    cout << "====================================================================\n";
    cout << "[+] Все модули и тесты Лабораторной работы №5 успешно пройдены!\n";
    cout << "====================================================================\n";
    return 0;
}

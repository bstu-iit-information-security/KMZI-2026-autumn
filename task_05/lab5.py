"""
Лабораторная работа №5. Квантовые сумматоры. Алгоритм Гровера.
Вариант 4.

Запуск:
    python lab5.py --task all
    python lab5.py --task 1
    python lab5.py --task 2
    ...
    python lab5.py --task 7

Результаты сохраняются в папку results/.
"""
from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from qiskit import QuantumCircuit, transpile
from qiskit.quantum_info import Statevector, Operator
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


def write_csv(filename, headers, rows):
    with (RESULTS / filename).open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(headers)
        writer.writerows(rows)


def save_plot(filename, title, xlabel, ylabel, curves):
    plt.figure(figsize=(9, 5))
    for label, xs, ys, style in curves:
        plt.plot(xs, ys, style, marker="o", label=label)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULTS / filename, dpi=160)
    plt.close()


# ---------------------------------------------------------------------------
# ЗАДАНИЕ 1. Квантовые сумматоры
# ---------------------------------------------------------------------------

def full_adder_five_qubits(a, b, carry_in):
    """Полный сумматор на пяти кубитах: A, B, X, S, C."""
    qc = QuantumCircuit(5)
    for bit, q in ((a, 0), (b, 1), (carry_in, 2)):
        if bit:
            qc.x(q)

    # S = A XOR B XOR X
    qc.cx(0, 3)
    qc.cx(1, 3)
    qc.cx(2, 3)

    # C = AB XOR AX XOR BX (для битов это majority)
    qc.ccx(0, 1, 4)
    qc.ccx(0, 2, 4)
    qc.ccx(1, 2, 4)
    return qc


def read_basis_bit(statevector, qubit):
    probabilities = statevector.probabilities()
    index = int(np.argmax(probabilities))
    return (index >> qubit) & 1


def full_adder_two_half_adders(a, b, carry_in):
    """
    Полный сумматор из двух полусумматоров и OR.
    Вспомогательные кубиты: p=A XOR B, g=A AND B, h=p AND X.
    """
    qc = QuantumCircuit(8)  # A,B,X,S,C,p,g,h
    for bit, q in ((a, 0), (b, 1), (carry_in, 2)):
        if bit:
            qc.x(q)

    # Первый полусумматор
    qc.cx(0, 5)
    qc.cx(1, 5)
    qc.ccx(0, 1, 6)

    # Второй полусумматор: p + X
    qc.cx(5, 3)
    qc.cx(2, 3)
    qc.ccx(5, 2, 7)

    # g и h не могут одновременно быть равны 1,
    # поэтому OR(g,h) = XOR(g,h).
    qc.cx(6, 4)
    qc.cx(7, 4)
    return qc


def task1():
    print("\nЗАДАНИЕ 1. Квантовые сумматоры")
    rows = []
    for a in (0, 1):
        for b in (0, 1):
            for x in (0, 1):
                expected_s = a ^ b ^ x
                expected_c = int((a + b + x) >= 2)

                q1 = full_adder_five_qubits(a, b, x)
                sv1 = Statevector.from_instruction(q1)
                got_s1, got_c1 = read_basis_bit(sv1, 3), read_basis_bit(sv1, 4)
                assert (got_s1, got_c1) == (expected_s, expected_c)

                q2 = full_adder_two_half_adders(a, b, x)
                sv2 = Statevector.from_instruction(q2)
                got_s2, got_c2 = read_basis_bit(sv2, 3), read_basis_bit(sv2, 4)
                assert (got_s2, got_c2) == (expected_s, expected_c)

                rows.append([a, b, x, expected_s, expected_c, got_s1, got_c1,
                             got_s2, got_c2, "OK"])

    write_csv("task1_full_adder_truth_table.csv",
              ["A", "B", "X", "S_expected", "C_expected",
               "S_5_qubits", "C_5_qubits", "S_two_half_adders",
               "C_two_half_adders", "check"], rows)

    # Схема для заданных входов A=1, B=0, X=1 с измерением.
    qc = full_adder_five_qubits(1, 0, 1)
    measured = QuantumCircuit(5, 2)
    measured.compose(qc, inplace=True)
    measured.measure(3, 0)  # S
    measured.measure(4, 1)  # C
    simulator = AerSimulator()
    compiled = transpile(measured, simulator)
    counts = simulator.run(compiled, shots=1024, seed_simulator=42).result().get_counts()
    print("Для A=1, B=0, X=1 ожидается S=0, C=1.")
    print("Распределение измерений (1024 shots):", counts)

    # Сравнение ресурсов двух схем.
    resources = []
    for name, circuit in [
        ("direct_5_qubits", full_adder_five_qubits(1, 0, 1)),
        ("two_half_adders", full_adder_two_half_adders(1, 0, 1)),
    ]:
        ops = circuit.count_ops()
        resources.append([name, circuit.num_qubits, ops.get("cx", 0),
                          ops.get("ccx", 0), circuit.depth()])
    write_csv("task1_resources.csv",
              ["implementation", "qubits", "CX", "CCX", "depth"], resources)

    # Обратный перенос для 2-, 3- и 4-разрядного сложения.
    ripple_rows = []
    for width in (2, 3, 4):
        total_tests = 0
        for av in range(2 ** width):
            for bv in range(2 ** width):
                qc_r = ripple_adder_circuit(width, av, bv)
                sv = Statevector.from_instruction(qc_r)
                result = 0
                # sum bits are q[2w : 3w+1]
                for bit in range(width + 1):
                    result |= ((int(np.argmax(sv.probabilities())) >> (2 * width + bit)) & 1) << bit
                assert result == av + bv
                total_tests += 1
        sample = ripple_adder_circuit(width, 0, 0)
        ops = sample.count_ops()
        ripple_rows.append([width, sample.num_qubits, ops.get("cx", 0),
                            ops.get("ccx", 0), sample.depth(), total_tests])
    write_csv("task1_ripple_resources.csv",
              ["width", "qubits", "CX", "CCX", "depth", "tested_pairs"],
              ripple_rows)
    print("Проверены все 8 входов полного сумматора и все пары для 2-, 3-, 4-разрядного сложения.")
    print("Таблицы сохранены в results/.")


def ripple_adder_circuit(width, a_value, b_value):
    """
    Простой обратимый ripple-carry сумматор.
    Qubits: A[width], B[width], SUM[width+1], carry[width].
    Выход A и B сохраняются; результат записывается в SUM.
    """
    n = 4 * width + 1
    qc = QuantumCircuit(n)
    a0 = 0
    b0 = width
    s0 = 2 * width
    c0 = 3 * width + 1  # c[0]..c[width-1], carry[0] = 0 подразумевается

    for i in range(width):
        if (a_value >> i) & 1:
            qc.x(a0 + i)
        if (b_value >> i) & 1:
            qc.x(b0 + i)

    for i in range(width):
        cin = None if i == 0 else c0 + i - 1
        # sum[i] = A[i] XOR B[i] XOR carry[i]
        qc.cx(a0 + i, s0 + i)
        qc.cx(b0 + i, s0 + i)
        if cin is not None:
            qc.cx(cin, s0 + i)

        # carry[i+1] = AB XOR A*cin XOR B*cin.
        target = c0 + i
        qc.ccx(a0 + i, b0 + i, target)
        if cin is not None:
            qc.ccx(a0 + i, cin, target)
            qc.ccx(b0 + i, cin, target)

    qc.cx(c0 + width - 1, s0 + width)
    return qc


# ---------------------------------------------------------------------------
# ЗАДАНИЕ 2. Логическая функция варианта 4
# F(A,B,C,D) = NOT(A OR B) AND (C XOR D)
# ---------------------------------------------------------------------------

def boolean_variant4_circuit(bits, optimized=True):
    """Входы q0..q3, выход q4, вспомогательные кубиты после q4."""
    if optimized:
        qc = QuantumCircuit(7)
    else:
        qc = QuantumCircuit(8)
    # Сначала подготавливаем входное состояние, затем вычисляем функцию.
    for i, bit in enumerate(bits):
        if int(bit):
            qc.x(i)

    if optimized:
        # q5 = NOR(A,B), q6 = XOR(C,D)
        nor, xor_tmp = 5, 6
        qc.cx(0, nor)
        qc.cx(1, nor)
        qc.ccx(0, 1, nor)  # OR
        qc.x(nor)          # NOR
        qc.cx(2, xor_tmp)
        qc.cx(3, xor_tmp)
        qc.ccx(nor, xor_tmp, 4)
        # Uncompute auxiliaries in reverse order.
        qc.cx(3, xor_tmp)
        qc.cx(2, xor_tmp)
        qc.x(nor)
        qc.ccx(0, 1, nor)
        qc.cx(1, nor)
        qc.cx(0, nor)
    else:
        # Базовая версия хранит OR, NOR и XOR в отдельных кубитах.
        or_tmp, nor, xor_tmp = 5, 6, 7
        qc.cx(0, or_tmp)
        qc.cx(1, or_tmp)
        qc.ccx(0, 1, or_tmp)
        qc.cx(or_tmp, nor)
        qc.x(nor)
        qc.cx(2, xor_tmp)
        qc.cx(3, xor_tmp)
        qc.ccx(nor, xor_tmp, 4)
        qc.cx(3, xor_tmp)
        qc.cx(2, xor_tmp)
        qc.x(nor)
        qc.cx(or_tmp, nor)
        qc.ccx(0, 1, or_tmp)
        qc.cx(1, or_tmp)
        qc.cx(0, or_tmp)

    return qc


def classical_f4(a, b, c, d):
    return int((not (a or b)) and (c ^ d))


def task2():
    print("\nЗАДАНИЕ 2. Логическая функция варианта 4")
    rows = []
    for number in range(16):
        bits = [(number >> (3 - i)) & 1 for i in range(4)]
        expected = classical_f4(*bits)
        results = []
        for optimized in (False, True):
            qc = boolean_variant4_circuit(bits, optimized)
            sv = Statevector.from_instruction(qc)
            index = int(np.argmax(sv.probabilities()))
            out = (index >> 4) & 1
            # все вспомогательные кубиты должны вернуться в |0>
            aux_start = 5
            aux_end = 8 if not optimized else 7
            aux_zero = all(((index >> q) & 1) == 0 for q in range(aux_start, aux_end))
            assert out == expected
            assert aux_zero
            results.append(out)
        rows.append([*bits, expected, results[0], results[1], "OK"])
    write_csv("task2_variant4_truth_table.csv",
              ["A", "B", "C", "D", "F_classical", "F_basic",
               "F_optimized", "check"], rows)

    resources = []
    for name, optimized in (("basic", False), ("optimized", True)):
        qc = boolean_variant4_circuit([0, 0, 0, 0], optimized)
        ops = qc.count_ops()
        resources.append([name, qc.num_qubits, ops.get("cx", 0),
                          ops.get("ccx", 0), qc.depth()])
    write_csv("task2_resources.csv",
              ["implementation", "qubits", "CX", "CCX", "depth"], resources)
    print("Функция проверена на всех 16 входах. Вспомогательные кубиты очищаются.")


# ---------------------------------------------------------------------------
# ЗАДАНИЕ 3. Шумовая модель
# ---------------------------------------------------------------------------

def noisy_boolean_run(bits, p1, p2, shots=512, seed=123):
    qc = boolean_variant4_circuit(bits, optimized=True)
    measured = QuantumCircuit(qc.num_qubits, 1)
    measured.compose(qc, inplace=True)
    measured.measure(4, 0)

    noise = NoiseModel()
    if p1 > 0:
        noise.add_all_qubit_quantum_error(depolarizing_error(p1, 1), ["u"])
    if p2 > 0:
        noise.add_all_qubit_quantum_error(depolarizing_error(p2, 2), ["cx"])

    simulator = AerSimulator(noise_model=noise)
    compiled = transpile(measured, simulator, basis_gates=["u", "cx"])
    counts = simulator.run(compiled, shots=shots, seed_simulator=seed).result().get_counts()
    return counts.get("1", 0) / shots


def task3():
    print("\nЗАДАНИЕ 3. Моделирование шума")
    p1 = 0.001
    p2_values = [0, 0.001, 0.005, 0.01, 0.02]
    rows = []
    for p2 in p2_values:
        correct = 0
        total = 0
        for number in range(16):
            bits = [(number >> (3 - i)) & 1 for i in range(4)]
            expected = classical_f4(*bits)
            # Для каждого входа вероятность правильного выхода оценивается shots.
            p_one = noisy_boolean_run(bits, p1, p2, shots=512, seed=1000 + number)
            p_correct = p_one if expected else 1 - p_one
            correct += p_correct
            total += 1
        fraction = correct / total
        rows.append([p1, p2, fraction])
        print(f"p2={p2:.3f}: средняя доля правильных ответов={fraction:.4f}")
    write_csv("task3_noise_results.csv",
              ["p1", "p2", "mean_correct_fraction"], rows)
    save_plot("task3_noise.png", "Влияние двухкубитного шума",
              "p2", "Доля правильных ответов",
              [("оптимизированная схема", p2_values,
                [r[2] for r in rows], "-")])


# ---------------------------------------------------------------------------
# ЗАДАНИЯ 4-7. Алгоритм Гровера
# ---------------------------------------------------------------------------

def build_oracle(n, marked):
    """Фазовый оракул: меняет знак только у |marked>."""
    if len(marked) != n or any(ch not in "01" for ch in marked):
        raise ValueError("marked должна быть битовой строкой длины n")
    qc = QuantumCircuit(n, name=f"Oracle_{marked}")
    # В Qiskit q0 — младший бит, поэтому сопоставляем правый символ q0.
    for qubit, bit in enumerate(reversed(marked)):
        if bit == "0":
            qc.x(qubit)
    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
    for qubit, bit in enumerate(reversed(marked)):
        if bit == "0":
            qc.x(qubit)
    return qc


def build_diffuser(n):
    """Инверсия относительно среднего; отличается общим знаком от 2|s><s|-I."""
    qc = QuantumCircuit(n, name="Diffuser")
    for q in range(n):
        qc.h(q)
    for q in range(n):
        qc.x(q)
    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
    for q in range(n):
        qc.x(q)
    for q in range(n):
        qc.h(q)
    return qc


def grover_circuit(n, marked, iterations, measure=False):
    qc = QuantumCircuit(n, n) if measure else QuantumCircuit(n)
    for q in range(n):
        qc.h(q)
    oracle = build_oracle(n, marked)
    diffuser = build_diffuser(n)
    for _ in range(iterations):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    if measure:
        qc.measure(range(n), range(n))
    return qc


def marked_probability_statevector(n, marked, iterations):
    qc = grover_circuit(n, marked, iterations, measure=False)
    sv = Statevector.from_instruction(qc)
    index = int(marked, 2)
    return float(sv.probabilities()[index])


def marked_probability_shots(n, marked, iterations, shots=1024, seed=42):
    qc = grover_circuit(n, marked, iterations, measure=True)
    simulator = AerSimulator()
    compiled = transpile(qc, simulator)
    counts = simulator.run(compiled, shots=shots, seed_simulator=seed).result().get_counts()
    return counts.get(marked, 0) / shots, counts


def theoretical_probability(n, iterations, marked_count=1):
    N = 2 ** n
    theta = math.asin(math.sqrt(marked_count / N))
    return math.sin((2 * iterations + 1) * theta) ** 2


def verify_oracle_and_diffuser():
    for n in range(2, 6):
        for value in range(2 ** n):
            marked = format(value, f"0{n}b")
            op = Operator(build_oracle(n, marked)).data
            diag = np.diag(op)
            expected = np.ones(2 ** n, dtype=complex)
            expected[value] = -1
            assert np.allclose(diag, expected)
            assert np.allclose(op, np.diag(expected))

        diffuser = Operator(build_diffuser(n)).data
        s = np.ones(2 ** n, dtype=complex) / math.sqrt(2 ** n)
        target = 2 * np.outer(s, s.conj()) - np.eye(2 ** n)
        assert np.allclose(diffuser, -target, atol=1e-8)

    for k in (1, 2):
        exact = marked_probability_statevector(3, "111", k)
        formula = theoretical_probability(3, k)
        assert abs(exact - formula) < 1e-8


def task4():
    print("\nЗАДАНИЕ 4. Проверка оракула, диффузора и алгоритма Гровера")
    verify_oracle_and_diffuser()
    print("Оракул проверен для n=2,3,4,5; диффузор совпадает с целевой матрицей с точностью до общего знака.")
    print("Проверка вероятностей Гровера для n=3 и k=1,2 пройдена.")


def run_grover_experiment(n, marked, shots=1024, seed=42, max_k=15):
    exact = []
    experimental = []
    counts_by_k = []
    for k in range(max_k + 1):
        exact.append(marked_probability_statevector(n, marked, k))
        p, counts = marked_probability_shots(n, marked, k, shots=shots,
                                             seed=seed + k)
        experimental.append(p)
        counts_by_k.append(counts)
    return exact, experimental, counts_by_k


def task5():
    print("\nЗАДАНИЕ 5. Эксперимент для отмеченного состояния |1010011>")
    n, marked = 7, "1010011"
    max_k = 15
    exact, exp, _ = run_grover_experiment(n, marked, shots=1024, seed=500)
    theory = [theoretical_probability(n, k) for k in range(max_k + 1)]
    rows = [[k, exact[k], exp[k], theory[k]] for k in range(max_k + 1)]
    write_csv("task5_probabilities.csv",
              ["k", "P_exact_statevector", "P_experimental_1024", "P_theory"],
              rows)
    save_plot("task5_grover_probabilities.png",
              "Алгоритм Гровера: |1010011>, N=128",
              "Число итераций k", "Вероятность обнаружения",
              [("точная", list(range(16)), exact, "-"),
               ("экспериментальная, 1024 shots", list(range(16)), exp, "--"),
               ("теория", list(range(16)), theory, ":")])

    k_theory = max(range(16), key=lambda k: theory[k])
    k_exact = max(range(16), key=lambda k: exact[k])
    k_exp = max(range(16), key=lambda k: exp[k])

    stability_rows = []
    for shots in (16, 64, 256, 1024):
        matches = 0
        for seed in range(20):
            exp_run = []
            for k in range(16):
                p, _ = marked_probability_shots(n, marked, k, shots=shots,
                                                seed=10000 + seed * 100 + k)
                exp_run.append(p)
            if int(np.argmax(exp_run)) == k_theory:
                matches += 1
        fraction = matches / 20
        stability_rows.append([shots, matches, 20, fraction])
    write_csv("task5_shot_stability.csv",
              ["shots", "matches_theoretical_optimum", "runs", "fraction"],
              stability_rows)
    save_plot("task5_shot_stability.png",
              "Устойчивость экспериментального оптимума",
              "Число shots", "Доля совпадений",
              [("20 независимых запусков",
                [r[0] for r in stability_rows],
                [r[3] for r in stability_rows], "-")])
    print(f"k_theory={k_theory}, k_exact={k_exact}, k_experimental={k_exp}")
    print("Стабильность по shots:", stability_rows)


def task6():
    print("\nЗАДАНИЕ 6. Несколько отмеченных состояний, N=64")
    n = 6
    rng = random.Random(2026)
    rows = []
    curves = []
    for m in (1, 2, 3, 4, 8):
        marked_set = sorted(rng.sample(range(2 ** n), m))
        marked_strings = [format(v, f"0{n}b") for v in marked_set]
        probs = []
        for k in range(16):
            qc = QuantumCircuit(n)
            for q in range(n):
                qc.h(q)
            oracle = QuantumCircuit(n)
            for marked in marked_strings:
                oracle.compose(build_oracle(n, marked), inplace=True)
            diffuser = build_diffuser(n)
            for _ in range(k):
                qc.compose(oracle, inplace=True)
                qc.compose(diffuser, inplace=True)
            sv = Statevector.from_instruction(qc)
            p = sum(float(sv.probabilities()[v]) for v in marked_set)
            probs.append(p)
        local_maxima = [k for k in range(1, 15)
                        if probs[k] >= probs[k-1] and probs[k] >= probs[k+1]]
        first_local = local_maxima[0] if local_maxima else int(np.argmax(probs))
        k_global = int(np.argmax(probs))
        k_theory = math.floor((math.pi / 4) * math.sqrt((2 ** n) / m))
        rows.append([m, k_theory, first_local, probs[first_local],
                     k_global, probs[k_global],
                     ",".join(marked_strings)])
        curves.append((f"M={m}", list(range(16)), probs, "-"))
    write_csv("task6_multiple_solutions.csv",
              ["M", "k_theory_floor", "k_first_local_max", "P_first_local",
               "k_global_max_0_15", "P_global_max", "marked_states"], rows)
    save_plot("task6_multiple_solutions.png",
              "Алгоритм Гровера при нескольких решениях, N=64",
              "Число итераций k", "Суммарная вероятность отмеченных состояний",
              curves)
    print("Сводная таблица сохранена в results/task6_multiple_solutions.csv")


def task7():
    print("\nЗАДАНИЕ 7. Вариант 4: N=32, отмеченное состояние |00110>")
    n, marked = 5, "00110"
    exact, exp, _ = run_grover_experiment(n, marked, shots=1024, seed=700)
    theory = [theoretical_probability(n, k) for k in range(16)]
    rows = [[k, exact[k], exp[k], theory[k]] for k in range(16)]
    write_csv("task7_variant4_probabilities.csv",
              ["k", "P_exact_statevector", "P_experimental_1024", "P_theory"],
              rows)
    save_plot("task7_variant4_grover.png",
              "Алгоритм Гровера: вариант 4, |00110>, N=32",
              "Число итераций k", "Вероятность обнаружения",
              [("точная", list(range(16)), exact, "-"),
               ("экспериментальная, 1024 shots", list(range(16)), exp, "--"),
               ("теория", list(range(16)), theory, ":")])

    k_theory_floor = math.floor((math.pi / 4) * math.sqrt(2 ** n))
    k_exact = int(np.argmax(exact))
    k_exp = int(np.argmax(exp))
    summary = [[4, 2 ** n, f"|{marked}>", k_theory_floor,
                k_exact, k_exp, max(exact)]]
    write_csv("task7_variant4_summary.csv",
              ["variant", "N", "marked_state", "k_theory_floor",
               "k_exact_first_max", "k_experimental", "max_P_exact"],
              summary)
    print("Сводная строка:", summary[0])
    print("Для M=1 точная кривая зависит от N, но не от конкретной метки.")
    print("Экспериментальный максимум может сдвигаться из-за статистической выборки.")


def main():
    parser = argparse.ArgumentParser(description="Лабораторная работа №5, вариант 4")
    parser.add_argument("--task", default="all",
                        choices=["all", "1", "2", "3", "4", "5", "6", "7"])
    args = parser.parse_args()
    tasks = {
        "1": task1, "2": task2, "3": task3, "4": task4,
        "5": task5, "6": task6, "7": task7,
    }
    if args.task == "all":
        for key in ("1", "2", "3", "4", "5", "6", "7"):
            tasks[key]()
    else:
        tasks[args.task]()
    print(f"\nГотово. Файлы результатов находятся здесь: {RESULTS}")


if __name__ == "__main__":
    main()

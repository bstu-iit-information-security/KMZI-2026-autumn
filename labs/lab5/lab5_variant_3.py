# -*- coding: utf-8 -*-
"""
Лабораторная работа №5. Квантовые сумматоры. Алгоритм Гровера
Студент: Вабищевич Илья (группа ИИ-28)
Вариант: 3
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import math
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error
from qiskit.quantum_info import Statevector, Operator

sim = AerSimulator()


# ==============================================================================
# ЗАДАНИЕ 1. Полный сумматор и многоразрядный квантовый сумматор
# ==============================================================================
def build_full_adder_5q(a_val: int = 0, b_val: int = 0, x_val: int = 0, measure: bool = True) -> QuantumCircuit:
    """
    Полный сумматор на 5 кубитах (q[0]=A, q[1]=B, q[2]=X, q[3]=S, q[4]=C)
    только из вентилей X, CX и CCX без промежуточных измерений и без ancilla.
    """
    qc = QuantumCircuit(5, 2) if measure else QuantumCircuit(5)
    if a_val:
        qc.x(0)
    if b_val:
        qc.x(1)
    if x_val:
        qc.x(2)

    qc.ccx(0, 1, 4)
    qc.cx(0, 3)
    qc.cx(1, 3)
    qc.ccx(2, 3, 4)
    qc.cx(2, 3)

    if measure:
        qc.measure(3, 0)  # c[0] = S
        qc.measure(4, 1)  # c[1] = C
    return qc


def build_full_adder_2ha_or(a_val: int = 0, b_val: int = 0, x_val: int = 0, measure: bool = True) -> QuantumCircuit:
    """
    Полный сумматор из двух полусумматоров и вентиля ИЛИ (8 кубитов).
    """
    qc = QuantumCircuit(8, 2) if measure else QuantumCircuit(8)
    if a_val:
        qc.x(0)
    if b_val:
        qc.x(1)
    if x_val:
        qc.x(2)

    # Полусумматор 1 (A, B -> S1=q[3], C1=q[4])
    qc.cx(0, 3)
    qc.cx(1, 3)
    qc.ccx(0, 1, 4)

    # Полусумматор 2 (S1=q[3], X=q[2] -> S=q[5], C2=q[6])
    qc.cx(3, 5)
    qc.cx(2, 5)
    qc.ccx(3, 2, 6)

    # Вентиль ИЛИ (C1=q[4], C2=q[6] -> C=q[7])
    qc.cx(4, 7)
    qc.cx(6, 7)
    qc.ccx(4, 6, 7)

    if measure:
        qc.measure(5, 0)  # S
        qc.measure(7, 1)  # C
    return qc


def build_nbit_adder(n_bits: int, a_int: int = 0, b_int: int = 0, measure: bool = True) -> QuantumCircuit:
    """
    n-разрядный сумматор с последовательным переносом (ripple-carry).
    """
    reg_a = QuantumRegister(n_bits, "a")
    reg_b = QuantumRegister(n_bits, "b")
    reg_c = QuantumRegister(n_bits + 1, "c")
    reg_s = QuantumRegister(n_bits, "s")

    if measure:
        creg = ClassicalRegister(n_bits + 1, "sum")
        qc = QuantumCircuit(reg_a, reg_b, reg_c, reg_s, creg)
    else:
        qc = QuantumCircuit(reg_a, reg_b, reg_c, reg_s)

    for i in range(n_bits):
        if (a_int >> i) & 1:
            qc.x(reg_a[i])
        if (b_int >> i) & 1:
            qc.x(reg_b[i])

    for i in range(n_bits):
        qc.ccx(reg_a[i], reg_b[i], reg_c[i + 1])
        qc.cx(reg_a[i], reg_s[i])
        qc.cx(reg_b[i], reg_s[i])
        qc.ccx(reg_c[i], reg_s[i], reg_c[i + 1])
        qc.cx(reg_c[i], reg_s[i])

    if measure:
        for i in range(n_bits):
            qc.measure(reg_s[i], creg[i])
        qc.measure(reg_c[n_bits], creg[n_bits])
    return qc


# ==============================================================================
# ЗАДАНИЕ 2. Квантовая схема булевой функции (Вариант 3)
# Вариант 3: F(A, B, C, D) = (A ∧ ¬B) ∨ (¬C ∧ D)
# ==============================================================================
def gate_not(qc: QuantumCircuit, a, out):
    qc.cx(a, out)
    qc.x(out)


def gate_and(qc: QuantumCircuit, a, b, out):
    qc.ccx(a, b, out)


def gate_or(qc: QuantumCircuit, a, b, out):
    qc.cx(a, out)
    qc.cx(b, out)
    qc.ccx(a, b, out)


def gate_xor(qc: QuantumCircuit, a, b, out):
    qc.cx(a, out)
    qc.cx(b, out)


def gate_nand(qc: QuantumCircuit, a, b, out):
    qc.ccx(a, b, out)
    qc.x(out)


def gate_nor(qc: QuantumCircuit, a, b, out):
    qc.cx(a, out)
    qc.cx(b, out)
    qc.ccx(a, b, out)
    qc.x(out)


def gate_maj(qc: QuantumCircuit, a, b, c, out):
    qc.ccx(a, b, out)
    qc.ccx(a, c, out)
    qc.ccx(b, c, out)


def gate_and_not(qc: QuantumCircuit, a, b_neg, out):
    qc.x(b_neg)
    gate_and(qc, a, b_neg, out)
    qc.x(b_neg)


def classical_F_var3(A: int, B: int, C: int, D: int) -> int:
    return int((bool(A) and (not bool(B))) or ((not bool(C)) and bool(D)))


def build_F_var3_basic(inputs=None, measure: bool = True) -> QuantumCircuit:
    qr_in = QuantumRegister(4, "in")
    qr_anc = QuantumRegister(5, "anc")
    qr_out = QuantumRegister(1, "out")
    if measure:
        cr_out = ClassicalRegister(1, "f")
        cr_anc = ClassicalRegister(5, "canc")
        qc = QuantumCircuit(qr_in, qr_anc, qr_out, cr_out, cr_anc)
    else:
        qc = QuantumCircuit(qr_in, qr_anc, qr_out)

    if inputs is not None:
        for i, bit in enumerate(inputs):
            if bit:
                qc.x(qr_in[i])

    comp = QuantumCircuit(qr_in, qr_anc, qr_out)
    gate_not(comp, qr_in[1], qr_anc[0])               # anc[0] = ¬B
    gate_not(comp, qr_in[2], qr_anc[1])               # anc[1] = ¬C
    gate_and(comp, qr_in[0], qr_anc[0], qr_anc[2])    # anc[2] = A ∧ ¬B
    gate_and(comp, qr_anc[1], qr_in[3], qr_anc[3])    # anc[3] = ¬C ∧ D
    gate_or(comp, qr_anc[2], qr_anc[3], qr_anc[4])    # anc[4] = (A ∧ ¬B) ∨ (¬C ∧ D)

    qc.compose(comp, inplace=True)
    qc.cx(qr_anc[4], qr_out[0])
    qc.compose(comp.inverse(), inplace=True)

    if measure:
        qc.measure(qr_out[0], cr_out[0])
        qc.measure(qr_anc, cr_anc)
    return qc


def build_F_var3_optimized(inputs=None, measure: bool = True) -> QuantumCircuit:
    qr_in = QuantumRegister(4, "in")
    qr_anc = QuantumRegister(2, "anc")
    qr_out = QuantumRegister(1, "out")
    if measure:
        cr_out = ClassicalRegister(1, "f")
        cr_anc = ClassicalRegister(2, "canc")
        qc = QuantumCircuit(qr_in, qr_anc, qr_out, cr_out, cr_anc)
    else:
        qc = QuantumCircuit(qr_in, qr_anc, qr_out)

    if inputs is not None:
        for i, bit in enumerate(inputs):
            if bit:
                qc.x(qr_in[i])

    comp = QuantumCircuit(qr_in, qr_anc, qr_out)
    gate_and_not(comp, qr_in[0], qr_in[1], qr_anc[0])  # anc[0] = A ∧ ¬B
    gate_and_not(comp, qr_in[3], qr_in[2], qr_anc[1])  # anc[1] = D ∧ ¬C

    qc.compose(comp, inplace=True)
    gate_or(qc, qr_anc[0], qr_anc[1], qr_out[0])       # out = anc[0] ∨ anc[1]
    qc.compose(comp.inverse(), inplace=True)

    if measure:
        qc.measure(qr_out[0], cr_out[0])
        qc.measure(qr_anc, cr_anc)
    return qc


# ==============================================================================
# ЗАДАНИЕ 4. Фазовый оракул, диффузор и алгоритм Гровера
# ==============================================================================
def build_oracle(n: int, marked: str) -> QuantumCircuit:
    assert len(marked) == n, "Длина строки marked должна равняться n"
    qc = QuantumCircuit(n, name=f"U_w({marked})")

    for i, bit in enumerate(reversed(marked)):
        if bit == "0":
            qc.x(i)

    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)

    for i, bit in enumerate(reversed(marked)):
        if bit == "0":
            qc.x(i)

    return qc


def build_diffuser(n: int) -> QuantumCircuit:
    qc = QuantumCircuit(n, name="Diffuser")
    qc.h(range(n))
    qc.x(range(n))
    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
    qc.x(range(n))
    qc.h(range(n))
    return qc


def build_grover_circuit(n: int, marked_states, iterations: int, measure: bool = True) -> QuantumCircuit:
    if isinstance(marked_states, str):
        marked_list = [marked_states]
    else:
        marked_list = list(marked_states)

    qc = QuantumCircuit(n, n) if measure else QuantumCircuit(n)
    qc.h(range(n))

    oracles = [build_oracle(n, w) for w in marked_list]
    diffuser = build_diffuser(n)

    for _ in range(iterations):
        for orc in oracles:
            qc.compose(orc, inplace=True)
        qc.compose(diffuser, inplace=True)

    if measure:
        qc.measure(range(n), range(n))
    return qc


def main():
    print("=== ЛАБОРАТОРНАЯ РАБОТА №5 (Вариант 3, Вабищевич Илья) ===\n")

    # 1. Проверка сумматоров
    sv_101 = Statevector.from_instruction(build_full_adder_5q(1, 0, 1, measure=False))
    cnt_101 = sim.run(build_full_adder_5q(1, 0, 1, measure=True), shots=1024, seed_simulator=42).result().get_counts()
    print("[Задание 1] A=1, B=0, X=1 -> Statevector probs:", sv_101.probabilities_dict(), "Counts:", cnt_101)

    for a in (0, 1):
        for b in (0, 1):
            for x in (0, 1):
                exp_s, exp_c = a ^ b ^ x, (a & b) | (a & x) | (b & x)
                for builder in (build_full_adder_5q, build_full_adder_2ha_or):
                    c = sim.run(builder(a, b, x, True), shots=128, seed_simulator=42).result().get_counts()
                    bstr = next(iter(c.keys()))
                    assert int(bstr[1]) == exp_s and int(bstr[0]) == exp_c

    for a_val in range(16):
        for b_val in range(16):
            c = sim.run(build_nbit_adder(4, a_val, b_val, True), shots=8, seed_simulator=42).result().get_counts()
            assert int(next(iter(c.keys())), 2) == a_val + b_val
    print("[Задание 1] Все 8 входов полных сумматоров и 256 пар 4-битного сумматора проверены (assert OK)!")

    # 2. Проверка булевой функции Варианта 3
    for idx in range(16):
        A, B, C, D = (idx >> 3) & 1, (idx >> 2) & 1, (idx >> 1) & 1, idx & 1
        f_cls = classical_F_var3(A, B, C, D)
        for builder, n_anc in ((build_F_var3_basic, 5), (build_F_var3_optimized, 2)):
            c = sim.run(builder((A, B, C, D), True), shots=128, seed_simulator=42).result().get_counts()
            anc_s, f_s = next(iter(c.keys())).split(" ")
            assert anc_s == "0" * n_anc and int(f_s) == f_cls
    print("[Задание 2] Функция варианта 3 F(A,B,C,D) = (A ∧ ¬B) ∨ (¬C ∧ D) проверена на всех 16 входах (assert OK)!")

    # 4. Проверка оракула и диффузора Гровера
    for n_test in (2, 3, 4, 5):
        w = format((1 << (n_test - 1)) | 1, f"0{n_test}b")
        diag = np.diag(Operator(build_oracle(n_test, w)).data)
        for x in range(1 << n_test):
            assert np.isclose(diag[x], -1.0 if format(x, f"0{n_test}b") == w else 1.0)
        N_dim = 1 << n_test
        s_vec = np.ones((N_dim, 1)) / np.sqrt(N_dim)
        assert np.allclose(Operator(build_diffuser(n_test)).data, -(2.0 * (s_vec @ s_vec.T) - np.eye(N_dim)))
    print("[Задание 4] Фазовый оракул и диффузор проверены для n = 2, 3, 4, 5 (assert OK)!")

    # 7. Вариант 3: |11001>, N = 2^5 = 32
    w_var3 = "11001"
    sv_g3 = Statevector.from_instruction(build_grover_circuit(5, w_var3, 4, measure=False))
    p_max_v3 = float(sv_g3.probabilities_dict()[w_var3])
    print(f"[Задание 7] Вариант 3 (|w> = |{w_var3}>, N = 32): k_opt = 4, P_точн(4) = {p_max_v3:.6f}")


if __name__ == "__main__":
    main()

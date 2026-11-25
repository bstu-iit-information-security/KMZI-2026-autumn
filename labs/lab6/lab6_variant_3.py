# -*- coding: utf-8 -*-
"""
Лабораторная работа №6. Алгоритмы Дойча, Дойча–Йожи. Алгоритм Шора
Студент: Вабищевич Илья (группа ИИ-28)
Вариант: 3 (Таблица А: N=21, a=2; Таблица Б: Вариант 18 -> N=78817, a1=4, a2=5)
"""
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import math
from fractions import Fraction
import numpy as np
import pandas as pd
import sympy

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit_aer import AerSimulator
from qiskit.quantum_info import Statevector, partial_trace
from qiskit.circuit.library import QFTGate, UnitaryGate

sim = AerSimulator()


# ==============================================================================
# ЗАДАНИЕ 1. Алгоритм Дойча
# ==============================================================================
def twobit_function(case: int) -> QuantumCircuit:
    if case not in [1, 2, 3, 4]:
        raise ValueError("`case` должен быть 1, 2, 3 или 4.")
    f = QuantumCircuit(2, name=f"Uf_{case}")
    if case in [2, 3]:
        f.cx(0, 1)
    if case in [3, 4]:
        f.x(1)
    return f


def classical_twobit_eval(case: int, x: int) -> int:
    if case == 1:
        return 0
    if case == 2:
        return x
    if case == 3:
        return 1 - x
    if case == 4:
        return 1
    raise ValueError(case)


def classical_deutsch_type(case: int) -> str:
    return "постоянная" if classical_twobit_eval(case, 0) == classical_twobit_eval(case, 1) else "сбалансированная"


def deutsch_decide(oracle: QuantumCircuit) -> str:
    oracle_gate = oracle.to_gate(label="U_f")
    qc = QuantumCircuit(2, 1)
    qc.x(1)
    qc.h([0, 1])
    qc.append(oracle_gate, [0, 1])
    qc.h(0)
    qc.measure(0, 0)

    oracle_calls = sum(1 for inst in qc.data if (inst.operation.label or inst.operation.name) == "U_f")
    assert oracle_calls == 1, "Оракул должен вызываться ровно 1 раз"

    t_qc = transpile(qc, sim)
    cnt = sim.run(t_qc, shots=1, seed_simulator=42).result().get_counts()
    bit = next(iter(cnt.keys()))
    return "сбалансированная" if bit == "1" else "постоянная"


# ==============================================================================
# ЗАДАНИЕ 2. Алгоритм Дойча–Йожи
# ==============================================================================
def dj_function(num_qubits: int, rng_inst=None) -> QuantumCircuit:
    if rng_inst is None:
        rng_inst = np.random.default_rng()
    qc_dj = QuantumCircuit(num_qubits + 1, name="U_dj")
    if rng_inst.integers(0, 2):
        if rng_inst.integers(0, 2):
            qc_dj.x(num_qubits)
        return qc_dj
    on_states = rng_inst.choice(range(2**num_qubits), 2**num_qubits // 2, replace=False)

    def add_cx(qc, bit_string):
        for qubit, bit in enumerate(reversed(bit_string)):
            if bit == "1":
                qc.x(qubit)
        return qc

    for state in on_states:
        bstr = format(int(state), f"0{num_qubits}b")
        add_cx(qc_dj, bstr)
        qc_dj.mcx(list(range(num_qubits)), num_qubits)
        add_cx(qc_dj, bstr)
    return qc_dj


def determine_true_type_by_probing(oracle: QuantumCircuit, n: int) -> str:
    ones = 0
    for x in range(1 << n):
        qc_probe = QuantumCircuit(n + 1)
        for i in range(n):
            if (x >> i) & 1:
                qc_probe.x(i)
        qc_probe.compose(oracle, inplace=True)
        sv = Statevector.from_instruction(qc_probe)
        idx_max = int(np.argmax(np.abs(sv.data) ** 2))
        ones += (idx_max >> n) & 1

    if ones == 0 or ones == (1 << n):
        return "постоянная"
    if ones == (1 << (n - 1)):
        return "сбалансированная"
    return f"другая ({ones}/{1<<n})"


def dj_from_truth_table(f_vals) -> QuantumCircuit:
    L = len(f_vals)
    n = int(round(math.log2(L)))
    assert (1 << n) == L
    qc = QuantumCircuit(n + 1, name="Uf_table")

    if all(v == 1 for v in f_vals):
        qc.x(n)
        return qc

    for x, val in enumerate(f_vals):
        if val == 1:
            for i in range(n):
                if ((x >> i) & 1) == 0:
                    qc.x(i)
            qc.mcx(list(range(n)), n)
            for i in range(n):
                if ((x >> i) & 1) == 0:
                    qc.x(i)
    return qc


def run_dj_algorithm(oracle: QuantumCircuit, n: int, shots: int = 1024, seed: int = 42):
    qc = QuantumCircuit(n + 1, n)
    qc.x(n)
    qc.h(range(n + 1))
    qc.compose(oracle, inplace=True)
    qc.h(range(n))
    qc.measure(range(n), range(n))

    t_qc = transpile(qc, sim)
    cnt = sim.run(t_qc, shots=shots, seed_simulator=seed).result().get_counts()
    top_bstr = max(cnt, key=cnt.get)
    algo_type = "постоянная" if cnt.get("0" * n, 0) == shots else "сбалансированная"
    return top_bstr, algo_type, cnt, t_qc


# ==============================================================================
# ЗАДАНИЯ 3–6. Алгоритм Шора
# ==============================================================================
def mod_mult_gate(b: int, N: int) -> UnitaryGate:
    assert math.gcd(b, N) == 1
    n = math.ceil(math.log2(N))
    dim = 1 << n
    U = np.zeros((dim, dim), dtype=complex)
    for x in range(N):
        U[(b * x) % N, x] = 1.0
    for x in range(N, dim):
        U[x, x] = 1.0
    return UnitaryGate(U, label=f"M_{b}")


def verify_mod_mult_gate(b: int, N: int):
    mat = mod_mult_gate(b, N).to_matrix()
    for x in range(N):
        target = (b * x) % N
        col = mat[:, x]
        assert np.isclose(col[target], 1.0) and np.isclose(np.linalg.norm(col), 1.0)


def build_shor_qpe_circuit(N: int, a: int, m_ctrl: int = None) -> QuantumCircuit:
    n_t = math.ceil(math.log2(N))
    if m_ctrl is None:
        m_ctrl = 2 * n_t

    ctrl = QuantumRegister(m_ctrl, "C")
    tgt = QuantumRegister(n_t, "T")
    out = ClassicalRegister(m_ctrl, "out")
    qc = QuantumCircuit(ctrl, tgt, out)

    qc.x(tgt[0])
    qc.h(ctrl)

    for k in range(m_ctrl):
        b = pow(a, 1 << k, N)
        verify_mod_mult_gate(b, N)
        if b != 1:
            qc.append(mod_mult_gate(b, N).control(1), [ctrl[k]] + list(tgt))

    qc.append(QFTGate(m_ctrl).inverse(), ctrl)
    qc.measure(ctrl, out)
    return qc


def analyze_shor_counts(counts: dict, N: int, a: int, m_ctrl: int, shots_total: int):
    valid_shots = 0
    r_candidates = {}
    for bstr, cnt in counts.items():
        y = int(bstr, 2)
        frac = Fraction(y, 1 << m_ctrl).limit_denominator(N)
        r_cand = frac.denominator
        if r_cand > 1 and pow(a, r_cand, N) == 1:
            valid_shots += cnt
            r_candidates[r_cand] = r_candidates.get(r_cand, 0) + cnt
    return valid_shots / shots_total, r_candidates


def classical_order(a: int, N: int) -> int:
    r = 1
    cur = a % N
    while cur != 1:
        cur = (cur * a) % N
        r += 1
    return r


def emulate_shor_qpe(N: int, a: int, r: int, m_ctrl: int, shots: int = 2000, window: int = 300, seed: int = 42):
    rng_em = np.random.default_rng(seed)
    M = 1 << m_ctrl
    ks = rng_em.integers(0, r, size=shots)
    valid_count = 0
    r_cands = {}
    offsets = np.arange(-window, window + 1)

    for k in ks:
        if k == 0:
            y = 0
        else:
            theta = k / r
            center = int(round(M * theta))
            y_win = (center + offsets) % M
            delta = M * theta - (center + offsets)
            num = np.sin(np.pi * delta)
            den = M * np.sin(np.pi * delta / M)
            with np.errstate(divide="ignore", invalid="ignore"):
                probs = np.where(np.isclose(den, 0.0), 1.0, (num / den) ** 2)
            probs = probs / np.sum(probs)
            y = int(rng_em.choice(y_win, p=probs))

        frac = Fraction(y, M).limit_denominator(N)
        r_cand = frac.denominator
        if r_cand > 1 and pow(a, r_cand, N) == 1:
            valid_count += 1
            r_cands[r_cand] = r_cands.get(r_cand, 0) + 1

    return valid_count / shots, r_cands


def shor_factor(N: int, bases: list[int]):
    n_bits = math.ceil(math.log2(N))
    m_ctrl = 2 * n_bits

    for attempt, a in enumerate(bases, start=1):
        g = math.gcd(a, N)
        if 1 < g < N:
            p, q = sorted((g, N // g))
            return (p, q), a, attempt

        if N < 64:
            qc = transpile(build_shor_qpe_circuit(N, a, m_ctrl), sim)
            cnt = sim.run(qc, shots=512, seed_simulator=42 + attempt).result().get_counts()
            _, r_cands = analyze_shor_counts(cnt, N, a, m_ctrl, 512)
        else:
            r_hidden = classical_order(a, N)
            _, r_cands = emulate_shor_qpe(N, a, r_hidden, m_ctrl, shots=512, window=300, seed=42 + attempt)

        for r_cand, _ in sorted(r_cands.items(), key=lambda item: item[1], reverse=True):
            if r_cand % 2 != 0:
                continue
            x = pow(a, r_cand // 2, N)
            if x == 1 or x == N - 1:
                continue
            for d in (math.gcd(x - 1, N), math.gcd(x + 1, N)):
                if 1 < d < N:
                    p, q = sorted((d, N // d))
                    return (p, q), a, attempt

    raise RuntimeError(f"Не удалось разложить N={N} по основаниям {bases}")


def main():
    print("=== ЛАБОРАТОРНАЯ РАБОТА №6 (Вариант 3, Вабищевич Илья) ===\n")

    for c in (1, 2, 3, 4):
        assert deutsch_decide(twobit_function(c)) == classical_deutsch_type(c)
    print("[Задание 1] Алгоритм Дойча (Вариант 3 -> f_3 и все 4 функции): assert OK!")

    rng = np.random.default_rng(42)
    for i in range(5):
        orc = dj_function(4, rng)
        _, algo_ans, _, _ = run_dj_algorithm(orc, 4, shots=256, seed=100 + i)
        assert algo_ans == determine_true_type_by_probing(orc, 4)
    print("[Задание 2] Алгоритм Дойча-Йожи (Вариант 3 -> n=4): assert OK!")

    (p_a, q_a), base_a, att_a = shor_factor(21, [2])
    assert p_a * q_a == 21 and {p_a, q_a} == set(sympy.factorint(21).keys())
    print(f"[Задания 3-4, 6] Таблица А (N=21, a=2): множители = ({p_a}, {q_a}), основание = {base_a}, попыток = {att_a} (assert OK!)")

    (p_b, q_b), base_b, att_b = shor_factor(78817, [4, 5])
    assert p_b * q_b == 78817 and {p_b, q_b} == set(sympy.factorint(78817).keys())
    print(f"[Задания 5-6] Таблица Б (Вариант 18, N=78817, bases=[4, 5]): множители = ({p_b}, {q_b}), основание = {base_b}, попыток = {att_b} (assert OK!)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Лабораторная работа №5 (вариант 2): квантовые сумматоры и алгоритм Гровера.

Полный исходный код ноутбука task_05_var2.ipynb в виде запускаемого скрипта.
Запуск:
    python3 task_05_var2.py
Сохранить графики в каталог:
    LAB5_FIG_DIR=figures python3 task_05_var2.py

Требования: qiskit, qiskit-aer, numpy, matplotlib.
"""
import matplotlib
matplotlib.use("Agg")


# %%
# Если пакеты qiskit / qiskit-aer отсутствуют в окружении, раскомментируйте строку ниже:
# !pip install -q qiskit qiskit-aer matplotlib numpy

import os
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import matplotlib.pyplot as plt
from math import pi, floor, sqrt, sin, asin

import qiskit
import qiskit_aer
from qiskit import QuantumCircuit, transpile
from qiskit.quantum_info import Statevector, Operator
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error

_FIG_DIR = os.environ.get("LAB5_FIG_DIR")


def _show(name):
    """Показать график в ноутбуке или сохранить PNG, если задан LAB5_FIG_DIR."""
    if _FIG_DIR:
        os.makedirs(_FIG_DIR, exist_ok=True)
        path = os.path.join(_FIG_DIR, name)
        plt.savefig(path, dpi=120, bbox_inches="tight")
        print(f"[figure] {path}")
    else:
        plt.show()
    plt.close()


sim = AerSimulator()
print(f"qiskit {qiskit.__version__}, qiskit-aer {qiskit_aer.__version__}, numpy {np.__version__}")
print("Симулятор AerSimulator инициализирован.")

# %%
print("=== ЗАДАНИЕ 1.1: полный сумматор, A=1, B=0, X=1 ===")
print("Кубиты: q0=A, q1=B, q2=X, q3=S, q4=C\n")

qc = QuantumCircuit(5, 2)
qc.x(0)          # A = 1
qc.x(2)          # X = 1
qc.cx(0, 3); qc.cx(1, 3); qc.cx(2, 3)              # S = A ⊕ B ⊕ X
qc.ccx(0, 1, 4); qc.ccx(1, 2, 4); qc.ccx(0, 2, 4)  # C = AB ⊕ BX ⊕ AX

sv = Statevector(qc)
probs = sv.probabilities_dict()
state = max(probs, key=probs.get)
amplitudes = {str(k): complex(np.round(v, 6)) for k, v in sv.to_dict().items()}
print("Вектор состояния (без измерений), порядок битов q4 q3 q2 q1 q0:")
print(f"  |{state}>  = |C S X B A>,  ненулевые амплитуды: {amplitudes}")
print(f"  S = q3 = {state[1]},  C = q4 = {state[0]}")
print("  Проверка: 1 + 0 + 1 = 10₂  ->  S = 0, C = 1 (строка 101 таблицы истинности).\n")

print("Схема полного сумматора (без измерений):")
print(qc.draw('text'))

qcm = QuantumCircuit(5, 2)
qcm.x(0); qcm.x(2)
qcm.cx(0, 3); qcm.cx(1, 3); qcm.cx(2, 3)
qcm.ccx(0, 1, 4); qcm.ccx(1, 2, 4); qcm.ccx(0, 2, 4)
qcm.measure(3, 0)   # S -> c0
qcm.measure(4, 1)   # C -> c1
counts = sim.run(qcm, shots=1024, seed_simulator=11).result().get_counts()
print("\nРаспределение измерений (строка c1 c0 = C S), shots=1024:")
print(" ", counts)
key = list(counts)[0]
print(f"  Единственный исход: C = {key[0]}, S = {key[1]}  ->  сумма 1+0+1 = 10₂.")

# %%
print("=== ЗАДАНИЕ 1.2: полный сумматор на 5 кубитах, все 8 наборов входов ===")

def full_adder_5q(a, b, x, measure=True):
    """q0=A, q1=B, q2=X, q3=S, q4=C. Только X, CX, CCX; без анцилл и промежуточных измерений."""
    qc = QuantumCircuit(5, 2) if measure else QuantumCircuit(5)
    if a: qc.x(0)
    if b: qc.x(1)
    if x: qc.x(2)
    qc.cx(0, 3); qc.cx(1, 3); qc.cx(2, 3)
    qc.ccx(0, 1, 4); qc.ccx(1, 2, 4); qc.ccx(0, 2, 4)
    if measure:
        qc.measure(3, 0)   # S -> c0
        qc.measure(4, 1)   # C -> c1
    return qc

TRUTH = [(0, 0, 0, 0, 0), (0, 0, 1, 1, 0), (0, 1, 0, 1, 0), (0, 1, 1, 0, 1),
         (1, 0, 0, 1, 0), (1, 0, 1, 0, 1), (1, 1, 0, 0, 1), (1, 1, 1, 1, 1)]

hdr = f"{'A':>2} {'B':>2} {'X':>2} | {'S ожид':>6} {'C ожид':>6} | {'S факт':>6} {'C факт':>6} | статус"
print(hdr)
print("-" * len(hdr))
for a, b, x, s_exp, c_exp in TRUTH:
    counts = sim.run(full_adder_5q(a, b, x), shots=1024, seed_simulator=12).result().get_counts()
    assert len(counts) == 1, f"недетерминированный результат: {counts}"
    key = list(counts)[0]
    c_got, s_got = int(key[0]), int(key[1])
    assert (s_got, c_got) == (s_exp, c_exp), (a, b, x, s_got, c_got)
    print(f"{a:>2} {b:>2} {x:>2} | {s_exp:>6} {c_exp:>6} | {s_got:>6} {c_got:>6} | OK")

gate5 = full_adder_5q(0, 0, 0, measure=False)
ops5 = gate5.count_ops()
print(f"\nМетрики схемы (без измерений): кубитов={gate5.num_qubits}, "
      f"CX={ops5.get('cx', 0)}, CCX={ops5.get('ccx', 0)}, X={ops5.get('x', 0)}, глубина={gate5.depth()}")
print("Все 8 строк таблицы истинности подтверждены assert-проверкой по 1024 shots.")

# %%
print("=== ЗАДАНИЕ 1.3: полный сумматор из двух полусумматоров и вентиля ИЛИ ===")
print("Кубиты: q0=A, q1=B, q2=X; HA1: q3=S1, q4=C1; HA2: q5=S, q6=C2; q7 = C1 ИЛИ C2\n")

def full_adder_ha(a, b, x, measure=True):
    """Полный сумматор из двух полусумматоров; ИЛИ(C1, C2) реализовано через X/CCX/X."""
    qc = QuantumCircuit(8, 2) if measure else QuantumCircuit(8)
    if a: qc.x(0)
    if b: qc.x(1)
    if x: qc.x(2)
    qc.cx(0, 3); qc.cx(1, 3); qc.ccx(0, 1, 4)   # HA1(A, B): S1 = A⊕B, C1 = A∧B
    qc.cx(3, 5); qc.cx(2, 5); qc.ccx(3, 2, 6)   # HA2(S1, X): S = S1⊕X, C2 = S1∧X
    qc.x(4); qc.x(6)                      # C1∨C2 = ¬(¬C1 ∧ ¬C2)
    qc.ccx(4, 6, 7); qc.x(7)
    qc.x(4); qc.x(6)                      # восстановление C1 и C2
    if measure:
        qc.measure(5, 0)   # S -> c0
        qc.measure(7, 1)   # C -> c1
    return qc

hdr = f"{'A':>2} {'B':>2} {'X':>2} | {'S ожид':>6} {'C ожид':>6} | {'S факт':>6} {'C факт':>6} | статус"
print(hdr)
print("-" * len(hdr))
for a, b, x, s_exp, c_exp in TRUTH:
    counts = sim.run(full_adder_ha(a, b, x), shots=1024, seed_simulator=13).result().get_counts()
    assert len(counts) == 1, f"недетерминированный результат: {counts}"
    key = list(counts)[0]
    c_got, s_got = int(key[0]), int(key[1])
    assert (s_got, c_got) == (s_exp, c_exp), (a, b, x, s_got, c_got)
    print(f"{a:>2} {b:>2} {x:>2} | {s_exp:>6} {c_exp:>6} | {s_got:>6} {c_got:>6} | OK")

gate8 = full_adder_ha(0, 0, 0, measure=False)
ops8 = gate8.count_ops()
print(f"\nМетрики схемы (без измерений): кубитов={gate8.num_qubits}, "
      f"CX={ops8.get('cx', 0)}, CCX={ops8.get('ccx', 0)}, X={ops8.get('x', 0)}, глубина={gate8.depth()}")

print("\nСравнение реализаций полного сумматора:")
hdr2 = f"{'реализация':<32} {'кубитов':>7} {'CX':>4} {'CCX':>4} {'X':>4} {'глубина':>7}"
print(hdr2)
print("-" * len(hdr2))
for name, g, o in [("прямая 5-кубитная", gate5, ops5), ("из двух полусумматоров", gate8, ops8)]:
    print(f"{name:<32} {g.num_qubits:>7} {o.get('cx', 0):>4} {o.get('ccx', 0):>4} {o.get('x', 0):>4} {g.depth():>7}")

# %%
print("=== ЗАДАНИЕ 1.4: сумматор с последовательным переносом (ripple-carry) ===")

def ripple_adder(n):
    """4n+1 кубитов: A(q0..), B(qn..), S(q2n..), переносы c0..cn(q3n..q4n)."""
    qc = QuantumCircuit(4 * n + 1)
    for i in range(n):
        ai, bi, si, ci = i, n + i, 2 * n + i, 3 * n + i
        qc.cx(ai, si); qc.cx(bi, si); qc.cx(ci, si)
        qc.ccx(ai, bi, ci + 1); qc.ccx(bi, ci, ci + 1); qc.ccx(ai, ci, ci + 1)
    return qc

def ripple_test(n, shots=64):
    """Исчерпывающая проверка всех 2^n * 2^n пар (a, b) сравнением с a+b."""
    gates = ripple_adder(n)
    meas_q = list(range(2 * n, 3 * n)) + [4 * n]   # s0..s_{n-1}, c_n
    meas_c = list(range(n + 1))
    tested = 0
    for a in range(2 ** n):
        for b in range(2 ** n):
            qc = QuantumCircuit(4 * n + 1, n + 1)
            for i in range(n):
                if (a >> i) & 1: qc.x(i)
                if (b >> i) & 1: qc.x(n + i)
            qc.compose(gates, inplace=True)
            qc.measure(meas_q, meas_c)
            counts = sim.run(qc, shots=shots, seed_simulator=n * 1000 + a * 64 + b).result().get_counts()
            assert len(counts) == 1, f"n={n}, {a}+{b}: недетерминированный результат {counts}"
            got = int(list(counts)[0], 2)
            assert got == a + b, f"n={n}: {a} + {b} = {a + b}, получено {got}"
            tested += 1
    return tested

hdr = f"{'n':>2} {'кубитов':>8} {'CX':>4} {'CCX':>4} {'глубина':>8} {'пар проверено':>14} {'статус':>8}"
print(hdr)
print("-" * len(hdr))
rows = []
for n in (2, 3, 4):
    g = ripple_adder(n)
    tested = ripple_test(n)
    o = g.count_ops()
    rows.append((n, g.num_qubits, o.get('cx', 0), o.get('ccx', 0), g.depth(), tested))
    print(f"{n:>2} {g.num_qubits:>8} {o.get('cx', 0):>4} {o.get('ccx', 0):>4} {g.depth():>8} {tested:>14} "
          f"{'OK' if tested == 4 ** n else 'FAIL':>8}")

print("\nВсе пары (a, b) для n = 2 (16), n = 3 (64) и n = 4 (256) сложены верно "
      "(проверка assert по измеренному (n+1)-битному результату).")

plt.figure(figsize=(7, 4.2))
plt.plot([r[0] for r in rows], [r[4] for r in rows], 'o-', label='глубина')
plt.plot([r[0] for r in rows], [r[3] for r in rows], 's--', label='CCX = 3n')
plt.plot([r[0] for r in rows], [r[2] for r in rows], '^:', label='CX = 3n')
plt.xlabel('Число разрядов $n$')
plt.ylabel('Значение')
plt.title('Рост глубины и числа вентилей ripple-carry сумматора')
plt.xticks([2, 3, 4])
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig1_adder_scaling.png')

# %%
print("=== ЗАДАНИЕ 2: модульные квантовые подсхемы (вариант 2) ===")
print("F(A,B,C,D) = (A XOR B) AND (C OR D)\n")

def gate_not(qc, a, out):
    """out = NOT a (out должен быть |0>)."""
    qc.x(out); qc.cx(a, out)

def gate_and(qc, a, b, out):
    """out ^= a AND b."""
    qc.ccx(a, b, out)

def gate_or(qc, a, b, out):
    """out ^= a OR b  (a⊕b⊕ab, 2 CX + 1 CCX)."""
    qc.cx(a, out); qc.cx(b, out); qc.ccx(a, b, out)

def gate_xor(qc, a, b, out):
    """out ^= a XOR b."""
    qc.cx(a, out); qc.cx(b, out)

def gate_nand(qc, a, b, out):
    """out = NOT(a AND b) (out должен быть |0>)."""
    qc.ccx(a, b, out); qc.x(out)

def gate_nor(qc, a, b, out):
    """out = NOT(a OR b) (out должен быть |0>)."""
    gate_or(qc, a, b, out); qc.x(out)

def gate_maj(qc, a, b, c, out):
    """out ^= MAJ(a,b,c) = ab ⊕ bc ⊕ ac."""
    qc.ccx(a, b, out); qc.ccx(b, c, out); qc.ccx(a, c, out)

def F_classical(A, B, C, D):
    """Классическая реализация функции варианта 2 на чистом Python."""
    return (A ^ B) & (C | D)

def self_test(name, gate_fn, n_in, ref):
    """Проверка подсхемы на всех 2^n_in наборах входов (Statevector, без выборки)."""
    ok = 0
    for bits in range(2 ** n_in):
        qc = QuantumCircuit(n_in + 1)
        for i in range(n_in):
            if (bits >> i) & 1:
                qc.x(i)
        gate_fn(qc, *range(n_in), n_in)
        probs = Statevector(qc).probabilities_dict()
        key = max(probs, key=probs.get)
        vals = [(bits >> i) & 1 for i in range(n_in)]
        if int(key[0]) == ref(vals) and key[1:] == format(bits, f'0{n_in}b'):
            ok += 1
    print(f"  {name:<6} входов={2 ** n_in:>2}  корректно={ok:>2}  статус={'OK' if ok == 2 ** n_in else 'FAIL'}")

print("Самопроверка подсхем на всех наборах входов:")
self_test("NOT",  gate_not, 1, lambda v: 1 - v[0])
self_test("AND",  gate_and, 2, lambda v: v[0] & v[1])
self_test("OR",   gate_or,  2, lambda v: v[0] | v[1])
self_test("XOR",  gate_xor, 2, lambda v: v[0] ^ v[1])
self_test("NAND", gate_nand, 2, lambda v: 1 - (v[0] & v[1]))
self_test("NOR",  gate_nor, 2, lambda v: 1 - (v[0] | v[1]))
self_test("MAJ",  gate_maj, 3, lambda v: int(sum(v) >= 2))

# %%
print("=== ЗАДАНИЕ 2.1: базовая схема (9 кубитов) ===")

def F_basic_compute():
    """Блок вычисления: q5=A⊕B, q6=C⊕D, q7=C∧D, q8=q6⊕q7=C∨D."""
    qc = QuantumCircuit(9)
    gate_xor(qc, 0, 1, 5)      # q5 = A ⊕ B
    gate_xor(qc, 2, 3, 6)      # q6 = C ⊕ D
    gate_and(qc, 2, 3, 7)      # q7 = C ∧ D
    gate_xor(qc, 6, 7, 8)      # q8 = q6 ⊕ q7 = C ∨ D
    return qc

def F_basic_body():
    """Вся схема: вычисление, запись q4 = q5 ∧ q8, inverse() блока вычисления."""
    comp = F_basic_compute()
    qc = QuantumCircuit(9)
    qc.compose(comp, inplace=True)
    gate_and(qc, 5, 8, 4)   # q4 = (A ⊕ B) ∧ (C ∨ D)
    qc.compose(comp.inverse(), inplace=True)
    return qc

def test_boolean(name, body, ancillas, shots=1024, seed=2):
    """Проверка на всех 16 входах: F и состояние анцилл."""
    nq = body.num_qubits
    hdr = f"{'A':>2} {'B':>2} {'C':>2} {'D':>2} | {'F кл':>4} | {'F кв':>4} | {'анциллы':>8} | статус"
    print(hdr)
    print("-" * len(hdr))
    ok = 0
    for bits in range(16):
        A, B, C, D = (bits >> 3) & 1, (bits >> 2) & 1, (bits >> 1) & 1, bits & 1
        qc = QuantumCircuit(nq, 1 + len(ancillas))
        for i, v in enumerate((A, B, C, D)):
            if v: qc.x(i)
        qc.compose(body, inplace=True)
        qc.measure(4, 0)
        qc.measure(ancillas, list(range(1, 1 + len(ancillas))))
        counts = sim.run(qc, shots=shots, seed_simulator=seed * 100 + bits).result().get_counts()
        assert len(counts) == 1, f"недетерминированный результат: {counts}"
        key = list(counts)[0]
        f_q, anc = int(key[-1]), key[:-1]
        f_cl = F_classical(A, B, C, D)
        good = (f_q == f_cl) and ('1' not in anc)
        assert good, (bits, key)
        ok += good
        print(f"{A:>2} {B:>2} {C:>2} {D:>2} | {f_cl:>4} | {f_q:>4} | {anc:>8} | {'OK' if good else 'FAIL'}")
    print(f"Итого: {ok}/16 наборов — ответ совпал с классическим, все анциллы в |0>.\n")

basic_body = F_basic_body()
test_boolean("базовая", basic_body, [5, 6, 7, 8])
o = basic_body.count_ops()
print(f"Метрики базовой схемы: кубитов={basic_body.num_qubits}, CX={o.get('cx', 0)}, "
      f"CCX={o.get('ccx', 0)}, глубина={basic_body.depth()}, анцилл=4")

# %%
print("=== ЗАДАНИЕ 2.2: оптимизированная схема (7 кубитов) ===")

def F_opt_compute():
    """Блок вычисления: q5=A⊕B, q6=C∨D — две анциллы вместо четырёх."""
    qc = QuantumCircuit(7)
    gate_xor(qc, 0, 1, 5)   # q5 = A ⊕ B
    gate_or(qc, 2, 3, 6)    # q6 = C ∨ D
    return qc

def F_opt_body():
    comp = F_opt_compute()
    qc = QuantumCircuit(7)
    qc.compose(comp, inplace=True)
    gate_and(qc, 5, 6, 4)   # q4 = (A ⊕ B) ∧ (C ∨ D)
    qc.compose(comp.inverse(), inplace=True)
    return qc

opt_body = F_opt_body()
test_boolean("оптим.", opt_body, [5, 6])
o = opt_body.count_ops()
print(f"Метрики оптимизированной схемы: кубитов={opt_body.num_qubits}, CX={o.get('cx', 0)}, "
      f"CCX={o.get('ccx', 0)}, глубина={opt_body.depth()}, анцилл=2")

print("\nСравнение версий схемы функции F(A,B,C,D) = (A⊕B) ∧ (C∨D):")
hdr = f"{'версия':<18} {'кубитов':>7} {'CX':>4} {'CCX':>4} {'глубина':>7} {'анцилл':>6}"
print(hdr)
print("-" * len(hdr))
for name, body, n_anc in [("базовая", basic_body, 4), ("оптимизированная", opt_body, 2)]:
    oo = body.count_ops()
    print(f"{name:<18} {body.num_qubits:>7} {oo.get('cx', 0):>4} {oo.get('ccx', 0):>4} "
          f"{body.depth():>7} {n_anc:>6}")

# %%
print("=== ЗАДАНИЕ 3: деполяризующий шум ===")

P2_VALUES = [0.0, 0.001, 0.005, 0.01, 0.02]

def build_noise_model(p2):
    nm = NoiseModel()
    nm.add_all_qubit_quantum_error(depolarizing_error(0.001, 1), ['rz', 'sx', 'x'])
    if p2 > 0:
        nm.add_all_qubit_quantum_error(depolarizing_error(p2, 2), ['cx'])
    return nm

BODIES = {"базовая": basic_body, "оптимизированная": opt_body}
TRANSPILED = {}
for name, body in BODIES.items():
    tqc = transpile(body, basis_gates=['rz', 'sx', 'x', 'cx'], optimization_level=1)
    TRANSPILED[name] = tqc
    print(f"{name:<18}: после транспиляции CX={tqc.count_ops().get('cx', 0)}, глубина={tqc.depth()}")

def fraction_correct(tqc, p2, shots=1024, seed=3):
    nm = build_noise_model(p2)
    total = 0.0
    for bits in range(16):
        A, B, C, D = (bits >> 3) & 1, (bits >> 2) & 1, (bits >> 1) & 1, bits & 1
        qc = QuantumCircuit(tqc.num_qubits, 1)
        for i, v in enumerate((A, B, C, D)):
            if v: qc.x(i)
        qc.compose(tqc, inplace=True)
        qc.measure(4, 0)
        counts = sim.run(qc, shots=shots, noise_model=nm,
                         seed_simulator=seed * 100 + bits).result().get_counts()
        total += counts.get(str(F_classical(A, B, C, D)), 0) / shots
    return total / 16

results = {name: [] for name in BODIES}
for p2 in P2_VALUES:
    for name in BODIES:
        results[name].append(fraction_correct(TRANSPILED[name], p2))

hdr = f"{'p2':>6} | {'базовая':>10} | {'оптимизированная':>16}"
print("\nДоля правильных ответов (усреднение по 16 входам, 1024 shots):")
print(hdr)
print("-" * len(hdr))
for i, p2 in enumerate(P2_VALUES):
    print(f"{p2:>6} | {results['базовая'][i]:>10.4f} | {results['оптимизированная'][i]:>16.4f}")

plt.figure(figsize=(7.5, 4.2))
for name, style in [("базовая", 'o-'), ("оптимизированная", 's--')]:
    plt.plot(P2_VALUES, results[name], style, label=name)
plt.xlabel('Вероятность двухкубитной ошибки $p_2$')
plt.ylabel('Доля правильных ответов')
plt.title('Устойчивость схем функции $F=(A\\oplus B)\\wedge(C\\vee D)$ к шуму')
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig2_noise_function.png')

print("\nОценка экспоненциального закона P ≈ exp(-κ · N_CX · p2):")
ratio_cx = TRANSPILED['базовая'].count_ops().get('cx', 0) / TRANSPILED['оптимизированная'].count_ops().get('cx', 0)
print(f"  отношение числа CX: N_баз / N_опт = {ratio_cx:.4f}")
print(f"  {'p2':>6} | {'ln P баз':>9} | {'ln P опт':>9} | {'отношение':>10}")
print("  " + "-" * 44)
ln_ratios = []
for i, p2 in enumerate(P2_VALUES):
    if p2 == 0.0:
        continue
    lb, lo = np.log(results['базовая'][i]), np.log(results['оптимизированная'][i])
    ln_ratios.append(lb / lo)
    print(f"  {p2:>6} | {lb:>9.4f} | {lo:>9.4f} | {lb / lo:>10.4f}")
print(f"  среднее отношение логарифмов = {np.mean(ln_ratios):.4f} (ожидается ≈ {ratio_cx:.4f})")

# %%
print("=== ЗАДАНИЕ 4.1–4.2: оракул и диффузор ===")

def build_oracle(n, marked):
    """Фазовый оракул: |x> -> -|x> при x == marked (строка marked = q_{n-1}...q_0)."""
    qc = QuantumCircuit(n)
    for i, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(i)
    qc.h(n - 1)
    qc.mcx(list(range(n - 1)), n - 1)
    qc.h(n - 1)
    for i, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(i)
    return qc

def build_diffuser(n):
    """Инверсия относительно среднего: D = -(2|s><s| - I)."""
    qc = QuantumCircuit(n)
    qc.h(range(n))
    qc.x(range(n))
    qc.h(n - 1)
    qc.mcx(list(range(n - 1)), n - 1)
    qc.h(n - 1)
    qc.x(range(n))
    qc.h(range(n))
    return qc

print(f"{'n':>2} | {'оракулов':>8} | {'состояний':>9} | {'max|diag-эталон|':>17} | {'max|U†U-I|':>11}")
print("-" * 62)
for n in (2, 3, 4, 5):
    N = 2 ** n
    max_dev, max_uni = 0.0, 0.0
    for bits in range(N):
        marked = format(bits, f'0{n}b')
        U = Operator(build_oracle(n, marked)).data
        max_uni = max(max_uni, np.max(np.abs(U.conj().T @ U - np.eye(N))))
        diag = np.real(np.diag(U))
        expected = np.ones(N)
        expected[bits] = -1.0
        max_dev = max(max_dev, np.max(np.abs(diag - expected)),
                      np.max(np.abs(U - np.diag(diag))))
        assert np.allclose(diag, expected, atol=1e-12)
        assert np.allclose(U.conj().T @ U, np.eye(N), atol=1e-12)
    print(f"{n:>2} | {N:>8} | {N * N:>9} | {max_dev:>17.2e} | {max_uni:>11.2e}")

print("\nДиффузор: сравнение с 2|s><s| - I")
print(f"{'n':>2} | {'max|D - T|':>12} | {'max|D + T|':>12}")
print("-" * 34)
for n in (2, 3, 4, 5):
    N = 2 ** n
    D = Operator(build_diffuser(n)).data
    s = np.ones(N) / np.sqrt(N)
    T = 2 * np.outer(s, s) - np.eye(N)
    print(f"{n:>2} | {np.max(np.abs(D - T)):>12.3e} | {np.max(np.abs(D + T)):>12.3e}")

# %%
print("=== ЗАДАНИЕ 4.3: сборка алгоритма Гровера и проверка при n=3 ===")

def grover_circuit(n, oracle, diffuser, k, measure=True):
    qc = QuantumCircuit(n, n) if measure else QuantumCircuit(n)
    qc.h(range(n))
    for _ in range(k):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    if measure:
        qc.measure(range(n), range(n))
    return qc

def run_P(n, oracle, diffuser, marked, k, shots, seed):
    """Экспериментальная вероятность отмеченного состояния по shots измерениям."""
    counts = sim.run(grover_circuit(n, oracle, diffuser, k), shots=shots,
                     seed_simulator=seed).result().get_counts()
    return counts.get(marked, 0) / shots

def prob_marked(n, oracle, diffuser, strings, k):
    """Точная суммарная вероятность набора отмеченных состояний (Statevector)."""
    probs = Statevector(grover_circuit(n, oracle, diffuser, k, measure=False)).probabilities_dict()
    return float(sum(probs.get(s, 0.0) for s in strings))

n3, marked3 = 3, "101"
N3 = 2 ** n3
theta3 = asin(1 / sqrt(N3))
oracle3, diffuser3 = build_oracle(n3, marked3), build_diffuser(n3)
print(f"n={n3}, N={N3}, |w>={marked3}, theta={theta3:.6f} рад\n")
print(f"{'k':>2} | {'P точное':>10} | {'sin²((2k+1)θ)':>14} | {'|разность|':>11}")
print("-" * 46)
for k in (1, 2):
    p = prob_marked(n3, oracle3, diffuser3, [marked3], k)
    th = sin((2 * k + 1) * theta3) ** 2
    assert abs(p - th) < 1e-12, (k, p, th)
    print(f"{k:>2} | {p:>10.6f} | {th:>14.6f} | {abs(p - th):>11.1e}")
print("Формула sin²((2k+1)θ) подтверждена с точностью < 1e-12.")

# %%
print("=== ЗАДАНИЕ 5.1: P(k) для N=128, |w>=|1010011> ===")

n5, marked5 = 7, "1010011"
N5 = 2 ** n5
theta5 = asin(1 / sqrt(N5))
oracle5, diffuser5 = build_oracle(n5, marked5), build_diffuser(n5)
print(f"N={N5}, |w>={marked5} ({int(marked5, 2)}), theta={theta5:.6f} рад\n")

K5 = list(range(16))
P_exact5 = [prob_marked(n5, oracle5, diffuser5, [marked5], k) for k in K5]
P_exp5 = [run_P(n5, oracle5, diffuser5, marked5, k, 1024, 21 * 100 + k) for k in K5]
P_theory5 = [sin((2 * k + 1) * theta5) ** 2 for k in K5]

hdr = f"{'k':>2} | {'P точное':>10} | {'P экспер.':>10} | {'sin²((2k+1)θ)':>14}"
print(hdr)
print("-" * len(hdr))
for k in K5:
    print(f"{k:>2} | {P_exact5[k]:>10.6f} | {P_exp5[k]:>10.6f} | {P_theory5[k]:>14.6f}")

plt.figure(figsize=(9, 4.4))
plt.plot(K5, P_exact5, 'b-o', label='$P_{точн}(k)$ (Statevector)')
plt.plot(K5, P_exp5, 'r--x', label='$P_{эксп}(k)$ (1024 shots)')
plt.plot(K5, P_theory5, 'g:', linewidth=2, label=r'$\sin^2((2k+1)\theta)$')
plt.xlabel('Число итераций Гровера $k$')
plt.ylabel('Вероятность $P(k)$')
plt.title('Гровер: $N=128$, $|w\\rangle=|1010011\\rangle$')
plt.xticks(K5)
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig3_grover_N128.png')

# %%
print("=== ЗАДАНИЕ 5.2: теоретический и экспериментальный оптимум ===")

k_exact5 = int(np.argmax(P_exact5))
k_round5 = round(pi / 4 * sqrt(N5))
k_floor5 = floor(pi / 4 * sqrt(N5))
k_exp5 = int(np.argmax(P_exp5))
print(f"argmax точной P(k)          : {k_exact5}  (P = {P_exact5[k_exact5]:.6f})")
print(f"round(π/4·√N)               : {k_round5}  (P = {P_exact5[k_round5]:.6f})")
print(f"floor(π/4·√N)               : {k_floor5}  (P = {P_exact5[k_floor5]:.6f})")
print(f"argmax экспериментальной P(k): {k_exp5}  (P = {P_exp5[k_exp5]:.6f})")

p8, p9 = P_exact5[8], P_exact5[9]
dP = p8 - p9
var_sum = p8 * (1 - p8) + p9 * (1 - p9)
sigma_diff = sqrt(var_sum / 1024)
print(f"\nP(8) = {p8:.6f}, P(9) = {p9:.6f}, ΔP = {dP:.6f}")
print(f"σ разности при 1024 shots: sqrt((p8(1-p8)+p9(1-p9))/1024) = {sigma_diff:.6f}; ΔP/σ = {dP / sigma_diff:.2f}")
for z, label in [(1.96, '95%'), (3.0, '99.7%')]:
    need = (z * sqrt(var_sum) / dP) ** 2
    print(f"  shots для надёжности {label}: (z·sqrt(p8(1-p8)+p9(1-p9))/ΔP)² = {need:.0f}")

print("\n=== ЗАДАНИЕ 5.3: устойчивость оценки оптимума (20 запусков) ===")
SHOTS_GRID = [16, 64, 256, 1024]
fractions = []
tie_fractions = []
for shots in SHOTS_GRID:
    good = 0
    ties = 0
    for seed in range(20):
        pk = [run_P(n5, oracle5, diffuser5, marked5, k, shots, seed * 100 + k) for k in K5]
        best = max(pk)
        winners = [k for k in K5 if pk[k] == best]
        if len(winners) > 1:
            ties += 1
        if winners == [k_exact5]:
            good += 1
    fractions.append(good / 20)
    tie_fractions.append(ties / 20)

hdr = f"{'shots':>6} | {'уникальный max при k=8':>22} | {'доля ничьих':>11}"
print(hdr)
print("-" * len(hdr))
for shots, f, t in zip(SHOTS_GRID, fractions, tie_fractions):
    print(f"{shots:>6} | {f:>22.2f} | {t:>11.2f}")

plt.figure(figsize=(7, 4.2))
plt.plot(SHOTS_GRID, fractions, 'o-', label='доля запусков с единственным максимумом при $k=8$')
plt.axhline(0.9, color='red', linestyle='--', label='уровень 90%')
plt.xscale('log')
plt.xlabel('Число измерений shots')
plt.ylabel('Доля запусков с $k_{эксп} = k_{точн}$')
plt.title('Надёжность определения оптимума от числа shots')
plt.xticks(SHOTS_GRID, [str(s) for s in SHOTS_GRID])
plt.ylim(-0.05, 1.05)
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig4_grover_shots.png')

ok_shots = [s for s, f in zip(SHOTS_GRID, fractions) if f >= 0.9]
print(f"Минимальное число shots с долей ≥ 90%: {min(ok_shots) if ok_shots else 'не достигнуто'}")

# %%
print("=== ЗАДАНИЕ 6.1–6.2: P(k) при M решениях, N=2^6=64 ===")
n6, N6 = 6, 64
np.random.seed(42)
diffuser6 = build_diffuser(n6)

M_LIST = [1, 2, 3, 4, 8]
res6 = {}
plt.figure(figsize=(9.5, 4.8))

print(f"{'M':>2} | {'отмеченные индексы':<34} | {'k теор':>6} | {'k 1-й макс':>10} | {'P':>8} | {'global':>6} | {'P(global)':>9}")
print("-" * 104)
for M in M_LIST:
    idx = sorted(int(x) for x in np.random.choice(list(range(N6)), M, replace=False))
    strings = [format(x, f'0{n6}b') for x in idx]
    oracle = QuantumCircuit(n6)
    for s in strings:
        oracle.compose(build_oracle(n6, s), inplace=True)
    P = [prob_marked(n6, oracle, diffuser6, strings, k) for k in range(16)]
    k_first = next(k for k in range(1, 15) if P[k] > P[k - 1] and P[k] >= P[k + 1])
    k_theor = floor(pi / 4 * sqrt(N6 / M))
    k_global = int(np.argmax(P))
    res6[M] = dict(idx=idx, strings=strings, P=P, k_first=k_first,
                   k_theor=k_theor, k_global=k_global)
    print(f"{M:>2} | {str(idx):<34} | {k_theor:>6} | {k_first:>10} | {P[k_first]:>8.6f} | "
          f"{k_global:>6} | {P[k_global]:>9.6f}")
    plt.plot(range(16), P, marker='o', label=f'M={M}')

plt.xlabel('Число итераций $k$')
plt.ylabel('Суммарная вероятность $P(k)$')
plt.title('Гровер при $M$ решениях ($N=64$)')
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig5_grover_M.png')

# %%
print("=== ЗАДАНИЕ 6.3: глобальный максимум против первого локального ===")
hdr = f"{'M':>2} | {'k 1-го макс':>11} | {'P(1-го)':>8} | {'argmax':>6} | {'P(argmax)':>9} | {'период π/(2θ_M)':>16}"
print(hdr)
print("-" * len(hdr))
for M in M_LIST:
    r = res6[M]
    thetaM = asin(sqrt(M / N6))
    period = pi / (2 * thetaM)
    print(f"{M:>2} | {r['k_first']:>11} | {r['P'][r['k_first']]:>8.6f} | {r['k_global']:>6} | "
          f"{r['P'][r['k_global']]:>9.6f} | {period:>16.3f}")

print("\nПоложения пиков sin²((2k+1)θ_M) (нецелые значения k, ближайшие целые выделены):")
for M in (4, 8):
    thetaM = asin(sqrt(M / N6))
    peaks = [((pi / 2 + m * pi) / thetaM - 1) / 2 for m in range(4)]
    print(f"  M={M}: θ_M={thetaM:.6f}, период={pi / (2 * thetaM):.3f}, пики k = " +
          ", ".join(f"{p:.2f}" for p in peaks))

print("\n=== ЗАДАНИЕ 6.4: M = N/2 = 32 и M = 3N/4 = 48 ===")
for M in (32, 48):
    idx = sorted(int(x) for x in np.random.choice(list(range(N6)), M, replace=False))
    strings = [format(x, f'0{n6}b') for x in idx]
    oracle = QuantumCircuit(n6)
    for s in strings:
        oracle.compose(build_oracle(n6, s), inplace=True)
    P = [prob_marked(n6, oracle, diffuser6, strings, k) for k in range(7)]
    print(f"\nM={M} ({M}/{N6}N): θ_M = arcsin(√(M/N)) = {asin(sqrt(M / N6)):.6f} рад")
    print(f"  {'k':>2} | {'P(k)':>8}")
    for k, p in enumerate(P):
        print(f"  {k:>2} | {p:>8.6f}")

# %%
print("=== ЗАДАНИЕ 7.1: вариант 2, N=2^5=32, |w>=|10101> ===")
n7, marked7 = 5, "10101"
N7 = 2 ** n7
theta7 = asin(1 / sqrt(N7))
oracle7, diffuser7 = build_oracle(n7, marked7), build_diffuser(n7)
print(f"N={N7}, |w>={marked7} ({int(marked7, 2)}), theta={theta7:.6f} рад")
print(f"k теор = floor(π/4·√N) = {floor(pi / 4 * sqrt(N7))}\n")

K7 = list(range(16))
P_exact7 = [prob_marked(n7, oracle7, diffuser7, [marked7], k) for k in K7]
P_exp7 = [run_P(n7, oracle7, diffuser7, marked7, k, 1024, 2 * 100 + k) for k in K7]
P_theory7 = [sin((2 * k + 1) * theta7) ** 2 for k in K7]

hdr = f"{'k':>2} | {'P точное':>10} | {'P экспер.':>10} | {'sin²((2k+1)θ)':>14}"
print(hdr)
print("-" * len(hdr))
for k in K7:
    print(f"{k:>2} | {P_exact7[k]:>10.6f} | {P_exp7[k]:>10.6f} | {P_theory7[k]:>14.6f}")

plt.figure(figsize=(9, 4.4))
plt.plot(K7, P_exact7, 'b-o', label='$P_{точн}(k)$ (Statevector)')
plt.plot(K7, P_exp7, 'r--x', label='$P_{эксп}(k)$ (1024 shots)')
plt.plot(K7, P_theory7, 'g:', linewidth=2, label=r'$\sin^2((2k+1)\theta)$')
plt.axvline(4, color='gray', linestyle='--', label='$k=4$')
plt.xlabel('Число итераций Гровера $k$')
plt.ylabel('Вероятность $P(k)$')
plt.title('Вариант 2: $N=32$, $|w\\rangle=|10101\\rangle$')
plt.xticks(K7)
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig6_grover_var2.png')

# %%
print("=== ЗАДАНИЕ 7.2: сводная таблица по варианту 2 ===")
k_th7 = floor(pi / 4 * sqrt(N7))
k_ex7 = next(k for k in range(1, 15) if P_exact7[k] > P_exact7[k - 1] and P_exact7[k] >= P_exact7[k + 1])
k_exp7 = int(np.argmax(P_exp7))
hdr = f"{'вариант':>7} | {'N':>4} | {'|w>':>8} | {'k теор':>6} | {'k точн':>6} | {'k эксп':>6} | {'max P точн':>10}"
print(hdr)
print("-" * len(hdr))
print(f"{2:>7} | {N7:>4} | {marked7:>8} | {k_th7:>6} | {k_ex7:>6} | {k_exp7:>6} | {max(P_exact7):>10.6f}")

print("\n=== ЗАДАНИЕ 7.3: группа N=2^5 (варианты 1–10) ===")
GROUP = ["01010", "10101", "11001", "00110", "11100", "00011", "10010", "01101", "10110", "01001"]
hdr = f"{'вариант':>7} | {'|w>':>8} | {'k точн':>6} | {'k эксп':>6} | {'P эксп(k эксп)':>14}"
print(hdr)
print("-" * len(hdr))
k_exact_group, k_exp_group = [], []
for i, state in enumerate(GROUP):
    o = build_oracle(n7, state)
    d = build_diffuser(n7)
    Pex = [prob_marked(n7, o, d, [state], k) for k in K7]
    Pexp = [run_P(n7, o, d, state, k, 1024, (2 + i) * 100 + k) for k in K7]
    kex = next(k for k in range(1, 15) if Pex[k] > Pex[k - 1] and Pex[k] >= Pex[k + 1])
    kep = int(np.argmax(Pexp))
    k_exact_group.append(kex)
    k_exp_group.append(kep)
    print(f"{1 + i:>7} | {state:>8} | {kex:>6} | {kep:>6} | {Pexp[kep]:>14.6f}")

print(f"\nВсе k точн равны {k_ex7}: {all(k == k_ex7 for k in k_exact_group)}; "
      f"k эксп принимает значения {sorted(set(k_exp_group))} "
      f"(разброс — только статистика 1024 shots).")

# %%
print("=== ЗАДАНИЕ 7.4: влияние двухкубитного шума ===")
print("Шум: 1q деполяризующий p1=0.001 на ['rz','sx','x'], 2q деполяризующий p2 на ['cx']\n")

def noisy_sweep(n, marked, p2, shots=1024, seed=7):
    oracle, diffuser = build_oracle(n, marked), build_diffuser(n)
    tqcs = [transpile(grover_circuit(n, oracle, diffuser, k), basis_gates=['rz', 'sx', 'x', 'cx'],
                      optimization_level=1) for k in K7]
    cx_per_iter = tqcs[1].count_ops().get('cx', 0) - tqcs[0].count_ops().get('cx', 0)
    nm = build_noise_model(p2)
    P = []
    for k in K7:
        counts = sim.run(tqcs[k], shots=shots, noise_model=nm,
                         seed_simulator=seed * 100 + k).result().get_counts()
        P.append(counts.get(marked, 0) / shots)
    return P, cx_per_iter, tqcs[-1].depth()

hdr = f"{'вариант':>7} | {'p2':>5} | {'CX за итерацию':>14} | {'глубина k=15':>12} | {'argmax k':>8} | {'max P(k)':>9}"
print(hdr)
print("-" * len(hdr))
noise_results = {}
for variant, nv, state in [(2, 5, "10101"), (1, 5, "01010")]:
    for p2 in (0.005, 0.02):
        P, cx_iter, depth_last = noisy_sweep(nv, state, p2)
        noise_results[(variant, p2)] = (P, cx_iter, depth_last)
        print(f"{variant:>7} | {p2:>5} | {cx_iter:>14} | {depth_last:>12} | "
              f"{int(np.argmax(P)):>8} | {max(P):>9.4f}")

print("\nТеоретическая оценка выживания без ошибок: (1 - 15/16·p2)^(CX за итерацию)")
for nv, cx_iter in [(5, noise_results[(2, 0.005)][1])]:
    for p2 in (0.005, 0.02):
        surv = (1 - 15 / 16 * p2) ** cx_iter
        print(f"  n={nv}, p2={p2}: p_eff={15 / 16 * p2:.5f}, (1-p_eff)^{cx_iter} = {surv:.4f}")

plt.figure(figsize=(9, 4.4))
plt.plot(K7, P_exact7, 'k-', label='без шума (точная $P(k)$)')
for p2, style in [(0.005, 'b--o'), (0.02, 'r:^')]:
    P = noise_results[(2, p2)][0]
    plt.plot(K7, P, style, label=f'вариант 2, $p_2={p2}$')
plt.axhline(1 / N7, color='gray', linestyle=':', label='$1/N = 0.03125$')
plt.xlabel('Число итераций Гровера $k$')
plt.ylabel('Вероятность $P(k)$')
plt.title('Вариант 2 ($n=5$): влияние двухкубитного шума')
plt.xticks(K7)
plt.grid(True)
plt.legend()
plt.tight_layout()
_show('fig7_grover_noise.png')

# %%
print("\n=== РАБОТА ЗАВЕРШЕНА ===")
print(f"Вариант 2: F(A,B,C,D) = (A ⊕ B) ∧ (C ∨ D); N = {N7}, |w> = |{marked7}>.")

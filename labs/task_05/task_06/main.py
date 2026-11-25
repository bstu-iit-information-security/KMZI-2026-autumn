"""Лабораторная работа 6: алгоритм Гровера при нескольких решениях.

Численные результаты и PNG рассчитываются NumPy без обязательного Qiskit.
При установленном Qiskit выполняется дополнительная проверка цепей с Operator/Statevector.
"""
from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

N_QUBITS = 6
N = 1 << N_QUBITS
M_VALUES = (1, 2, 3, 4, 8)
SEED = 20261122
K_VALUES = np.arange(16)
OUTPUT = Path(__file__).resolve().parent / 'output'
OUTPUT.mkdir(exist_ok=True)


def choose_marked(m: int, seed: int = SEED) -> tuple[str, ...]:
    """Детерминированные неповторяющиеся состояния, Qiskit bit ordering (q5...q0)."""
    rng = np.random.default_rng(seed + 101 * m)
    indices = rng.choice(N, size=m, replace=False)
    return tuple(format(int(i), f'0{N_QUBITS}b') for i in indices)


def exact_probabilities(marked: tuple[str, ...]) -> np.ndarray:
    """Точное моделирование statevector, включая составной фазовый оракул."""
    ids = np.array([int(x, 2) for x in marked], dtype=int)
    assert len(set(ids.tolist())) == len(ids)
    psi = np.ones(N, dtype=np.complex128) / np.sqrt(N)
    probabilities = []
    for k in K_VALUES:
        probabilities.append(float(np.sum(np.abs(psi[ids]) ** 2)))
        if k < K_VALUES[-1]:
            # Оракул = произведение фазовых инверсий для всех отмеченных строк.
            psi[ids] *= -1
            # Диффузор 2|s><s| - I = инверсия амплитуд относительно среднего.
            psi = 2 * np.mean(psi) - psi
            assert np.isclose(np.linalg.norm(psi), 1.0, atol=1e-12)
    return np.array(probabilities)


def theoretical_probabilities(m: int) -> np.ndarray:
    theta = np.arcsin(np.sqrt(m / N))
    return np.sin((2 * K_VALUES + 1) * theta) ** 2


def first_local_peak(prob: np.ndarray, tol: float = 1e-11) -> int:
    # Плато: выбираем самый ранний k с локально максимальным значением.
    for k in range(len(prob)):
        left_ok = (k == 0 or prob[k] + tol >= prob[k - 1])
        right_ok = (k == len(prob) - 1 or prob[k] + tol >= prob[k + 1])
        if left_ok and right_ok:
            return k
    return int(np.argmax(prob))


def earliest_global_peak(prob: np.ndarray, tol: float = 1e-11) -> int:
    return next(i for i, p in enumerate(prob) if p >= max(prob) - tol)


def build_oracle(n: int, marked: tuple[str, ...]):
    """В Qiskit U = product_w (I-2|w><w|), rightmost character maps to q0."""
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(n, name='oracle')
    for word in marked:
        assert len(word) == n and set(word) <= {'0', '1'}
        for q, c in enumerate(reversed(word)):
            if c == '0':
                qc.x(q)
        if n == 1:
            qc.z(0)
        else:
            qc.h(n - 1)
            qc.mcx(list(range(n - 1)), n - 1)
            qc.h(n - 1)
        for q, c in enumerate(reversed(word)):
            if c == '0':
                qc.x(q)
    return qc


def build_diffuser(n: int):
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(n, name='diffuser')
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
    # Standard H X MCZ X H = I-2|s><s|, so correct sign:
    qc.global_phase += np.pi
    return qc


def build_grover(n: int, marked: tuple[str, ...], iterations: int):
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(n)
    qc.h(range(n))
    oracle = build_oracle(n, marked)
    diffuser = build_diffuser(n)
    for _ in range(iterations):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    return qc


def optional_qiskit_check(cases: dict[int, tuple[str, ...]], exact: dict[int, np.ndarray]):
    try:
        from qiskit.quantum_info import Statevector, Operator
    except ImportError:
        print('Qiskit не установлен: квантовые схемы доступны в коде; результаты рассчитаны NumPy.')
        return
    # Check a phase oracle on every basis state (sample M) and diffuser identity.
    for m, marked in cases.items():
        phase = np.ones(N)
        phase[[int(w, 2) for w in marked]] = -1
        matrix = Operator(build_oracle(N_QUBITS, marked)).data
        assert np.allclose(matrix, np.diag(phase), atol=1e-9)
        for k in range(16):
            psi = Statevector.from_instruction(build_grover(N_QUBITS, marked, k))
            result = sum(abs(psi.data[int(w, 2)]) ** 2 for w in marked)
            assert np.isclose(result, exact[m][k], atol=1e-9), (m, k, result)
        print(f'Qiskit: M={m}, все k=0..15 проверены')
    s = np.ones(N)/np.sqrt(N)
    assert np.allclose(Operator(build_diffuser(N_QUBITS)).data, 2*np.outer(s, s)-np.eye(N))
    print('Qiskit: оракулы, диффузор и вероятности проверены.')


def write_csv(path: Path, columns: list[str], rows: list[list]):
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(rows)


def run():
    marked_cases = {m: choose_marked(m) for m in (*M_VALUES, 32, 48)}
    probabilities = {}
    rows, summary = [], []
    for m in (*M_VALUES, 32, 48):
        p = exact_probabilities(marked_cases[m])
        t = theoretical_probabilities(m)
        assert np.allclose(p, t, atol=1e-12), (m, np.max(np.abs(p-t)))
        probabilities[m] = p
        k_loc = first_local_peak(p)
        k_global = earliest_global_peak(p)
        k_est = int(np.floor(np.pi / 4 * np.sqrt(N/m)))
        theta = np.arcsin(np.sqrt(m / N))
        k_angle = np.pi/(4*theta)-0.5
        summary.append([m, k_est, k_loc, round(p[k_loc], 9), k_global,
                        round(p[k_global], 9), round(k_angle, 6)])
        print(f'M={m:2d}; k_est={k_est}; first={k_loc} P={p[k_loc]:.6f}; '
              f'global={k_global} P={p[k_global]:.6f}; marked={marked_cases[m]}')
        for k, pk in enumerate(p):
            rows.append([m, k, round(float(pk), 12), round(float(t[k]), 12)])

    write_csv(OUTPUT/'probabilities.csv', ['M','k','P_exact','P_theory'], rows)
    write_csv(OUTPUT/'summary.csv',
              ['M','floor_pi_over_4_sqrt_N_over_M','k_first_local','P_first_local',
               'k_global_0_15','P_global','continuous_first_peak_k'], summary)
    write_csv(OUTPUT/'marked_states.csv', ['M', 'marked_bits'],
              [[m, ' '.join(words)] for m, words in marked_cases.items()])

    plt.figure(figsize=(11, 6.5))
    for m in M_VALUES:
        plt.plot(K_VALUES, probabilities[m], marker='o', ms=3.5, linewidth=1.8, label=f'M = {m}')
    plt.xlabel('Number of Grover iterations k')
    plt.ylabel('Probability of a marked state P(k)')
    plt.title('Grover search, N = 64: exact statevector probabilities')
    plt.xticks(K_VALUES)
    plt.ylim(-0.04, 1.05)
    plt.grid(alpha=.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT/'grover_multiple_solutions.png', dpi=200)
    plt.close()

    plt.figure(figsize=(10, 5.7))
    for m in (1, 8, 32, 48):
        plt.plot(K_VALUES, probabilities[m], marker='o', ms=3.5, label=f'M = {m}')
    plt.xlabel('Number of Grover iterations k')
    plt.ylabel('Probability P(k)')
    plt.title('When Grover amplification stops being useful, N = 64')
    plt.xticks(K_VALUES)
    plt.ylim(-.04, 1.05)
    plt.grid(alpha=.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(OUTPUT/'large_M_comparison.png', dpi=200)
    plt.close()

    optional_qiskit_check(marked_cases, probabilities)
    print('Saved outputs in:', OUTPUT)


if __name__ == '__main__':
    run()

"""Задание 5: алгоритм Гровера, 7 кубитов, marked=1010011.

Режимы:
  - Qiskit + Qiskit Aer: Statevector и измерения AerSimulator;
  - без Qiskit: точный NumPy-вектор и статистически эквивалентная выборка
    из распределения вычислительного базиса (НЕ запуск Qiskit Aer).

Результаты сохраняются в output/.  Запуск: python main.py
"""
from __future__ import annotations

import csv
import math
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

MARKED = '1010011'
N_QUBITS = len(MARKED)
N = 1 << N_QUBITS
MARKED_INDEX = int(MARKED, 2)  # строки Qiskit справа налево: q6...q0
K_VALUES = list(range(16))
SHOTS_MAIN = 1024
SHOT_LEVELS = [16, 64, 256, 1024]
RUNS = 20
SEED = 20261122
OUT = Path(__file__).resolve().parent / 'output'
OUT.mkdir(parents=True, exist_ok=True)

try:
    from qiskit import QuantumCircuit, transpile
    from qiskit.quantum_info import Statevector
    from qiskit_aer import AerSimulator
    HAS_QISKIT = True
except ImportError:
    HAS_QISKIT = False


def mc_z(qc, n):
    qc.h(n - 1)
    qc.mcx(list(range(n - 1)), n - 1)
    qc.h(n - 1)


def build_oracle(n: int, marked: str):
    if not HAS_QISKIT:
        raise RuntimeError('Для построения QuantumCircuit установите Qiskit')
    if len(marked) != n or set(marked) - {'0', '1'}:
        raise ValueError('Неверное отмеченное состояние')
    qc = QuantumCircuit(n, name='Oracle')
    for q, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(q)
    mc_z(qc, n)
    for q, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(q)
    return qc


def build_diffuser(n: int):
    if not HAS_QISKIT:
        raise RuntimeError('Для построения QuantumCircuit установите Qiskit')
    qc = QuantumCircuit(n, name='Diffuser')
    qc.h(range(n))
    qc.x(range(n))
    mc_z(qc, n)
    qc.x(range(n))
    qc.h(range(n))
    qc.global_phase += math.pi
    return qc


def build_grover(n: int, marked: str, k: int):
    if not HAS_QISKIT:
        raise RuntimeError('Для построения QuantumCircuit установите Qiskit')
    qc = QuantumCircuit(n)
    qc.h(range(n))
    oracle = build_oracle(n, marked)
    diffuser = build_diffuser(n)
    for _ in range(k):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    return qc


def numpy_state(k: int):
    """Точное идеальное эволюционирование вектора, НЕ аналитическая формула."""
    state = np.full(N, 1 / math.sqrt(N), dtype=np.complex128)
    for _ in range(k):
        state[MARKED_INDEX] *= -1  # фазовый оракул
        mean = state.mean()
        state = 2 * mean - state  # D=2|s><s|-I
    return state


def theoretical_probability(k):
    theta = math.asin(1 / math.sqrt(N))
    return math.sin((2 * k + 1) * theta) ** 2


def state_for_k(k):
    if HAS_QISKIT:
        return Statevector.from_instruction(build_grover(N_QUBITS, MARKED, k)).data
    return numpy_state(k)


def sample_marked_probability(state, shots, seed, simulator=None, compiled=None):
    if HAS_QISKIT:
        # Измеряем все кубиты. Знак состояния в counts: q6...q0.
        result = simulator.run(compiled, shots=int(shots), seed_simulator=int(seed)).result()
        counts = result.get_counts()
        return counts.get(MARKED, 0) / shots
    # Без Qiskit: выборка из ТОЧНОГО распределения всех 128 состояний.
    # Нельзя выдавать её за измерения AerSimulator.
    rng = np.random.default_rng(int(seed))
    outcomes = rng.choice(N, size=int(shots), p=np.abs(state) ** 2)
    return float(np.mean(outcomes == MARKED_INDEX))


def configure_plot():
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10,
                         'axes.grid': True, 'grid.alpha': .25})


def save_csv(path, rows, fields):
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    print('Задание 5 | w=|1010011> | n=7 | N=128')
    print('Бэкенд:', 'Qiskit Statevector + AerSimulator' if HAS_QISKIT else
          'NumPy точные состояния + выборка из точного распределения (без Aer)')
    theta = math.asin(1 / math.sqrt(N))
    approximation = math.pi / 4 * math.sqrt(N)
    optimum_continuous = math.pi / (4 * theta) - .5
    k_theory = max(K_VALUES, key=theoretical_probability)
    print('π/4 √N =', approximation, '| floor =', math.floor(approximation))
    print('Точная точка максимума непрерывного k =', optimum_continuous,
          '| оптимальное целое k =', k_theory)
    configure_plot()
    states = [state_for_k(k) for k in K_VALUES]
    p_exact = [float(abs(state[MARKED_INDEX]) ** 2) for state in states]
    p_formula = [theoretical_probability(k) for k in K_VALUES]
    assert np.allclose(p_exact, p_formula, atol=1e-10)
    assert np.allclose([np.vdot(s, s).real for s in states], 1, atol=1e-10)

    sim = AerSimulator(method='automatic') if HAS_QISKIT else None
    compiled = []
    if HAS_QISKIT:
        for k in K_VALUES:
            q = build_grover(N_QUBITS, MARKED, k)
            q.measure_all()
            compiled.append(transpile(q, sim, optimization_level=1))

    main_rows = []
    main_sample = []
    print('\n k    Точно       Теория     Измерения (1024)')
    for k in K_VALUES:
        p_shot = sample_marked_probability(states[k], SHOTS_MAIN,
                     SEED + 10_000 + k, sim, compiled[k] if HAS_QISKIT else None)
        main_rows.append({'k':k,'P_exact':p_exact[k], 'P_theory':p_formula[k],
                          'P_shots_1024':p_shot, 'correct_count':round(p_shot*SHOTS_MAIN)})
        main_sample.append(p_shot)
        print(f'{k:2d}   {p_exact[k]:.7f}   {p_formula[k]:.7f}   {p_shot:.7f}')
    save_csv(OUT/'probabilities.csv', main_rows, list(main_rows[0]))
    k_emp = int(np.argmax(main_sample))
    print('\nОптимум теории:',k_theory,'| оптимум в одном опыте (1024 shots):',k_emp)
    fig, ax = plt.subplots(figsize=(10.5, 5.7))
    ax.plot(K_VALUES, p_formula, label='Теория sin²((2k+1)θ)', linewidth=2.1)
    ax.plot(K_VALUES, p_exact, 'o', label='Точная вероятность Statevector' if HAS_QISKIT else 'Точный вектор состояния (NumPy)', ms=5)
    ax.plot(K_VALUES, main_sample, 'x--', label='1024 shots (Aer)' if HAS_QISKIT else '1024 выборки (NumPy)', ms=6, alpha=.85)
    ax.axvline(k_theory, ls=':', label=f'Теоретический оптимум k={k_theory}')
    ax.set(xlabel='Число итераций Гровера, k', ylabel='Вероятность правильного результата',
           title='Гровер: n=7, отмечено |1010011⟩')
    ax.set_xticks(K_VALUES)
    ax.set_ylim(0,1.06)
    ax.legend(loc='best')
    fig.tight_layout()
    fig.savefig(OUT/'probability_curves.png', dpi=180)
    plt.close(fig)

    reliability_rows = []
    all_runs = []
    for shots in SHOT_LEVELS:
        correct_count = 0
        for run in range(RUNS):
            observations = []
            for k in K_VALUES:
                # Каждый опыт/k/число измерений получает свой независимый seed.
                seed = SEED + shots * 1000 + run * 100 + k
                observations.append(sample_marked_probability(
                    states[k], shots, seed, sim, compiled[k] if HAS_QISKIT else None))
            empirical_k = int(np.argmax(observations)) # ничья: меньшее k
            matched = empirical_k == k_theory
            correct_count += matched
            all_runs.append({'shots':shots,'run':run+1,'seed_base':SEED+shots*1000+run*100,
                             'empirical_k':empirical_k,'theoretical_k':k_theory,
                             'match':int(matched), 'p_at_k8':observations[8],
                             'p_at_k9':observations[9]})
        reliability_rows.append({'shots':shots, 'matches':correct_count,'runs':RUNS,
                                 'match_fraction':correct_count/RUNS})
    save_csv(OUT/'reliability.csv',reliability_rows,list(reliability_rows[0]))
    save_csv(OUT/'all_20_runs.csv',all_runs,list(all_runs[0]))

    fig, ax = plt.subplots(figsize=(8.8, 5.4))
    xs = [r['shots'] for r in reliability_rows]
    ys = [100*r['match_fraction'] for r in reliability_rows]
    ax.plot(xs,ys,'o-',lw=2,markersize=7,label='Совпадение оптимального k')
    ax.axhline(90, ls='--', label='Порог 90%')
    ax.set(xscale='log', xlabel='Число измерений, shots (логарифмическая шкала)',
           ylabel='Доля совпадений в 20 запусках, %',
           title='Надёжность определения оптимального числа итераций')
    ax.set_xticks(SHOT_LEVELS,labels=[str(s) for s in SHOT_LEVELS])
    ax.set_ylim(0,105)
    for x,y in zip(xs,ys): ax.annotate(f'{y:.0f}%', (x,y),xytext=(0,9),textcoords='offset points',ha='center')
    ax.legend(loc='best')
    fig.tight_layout()
    fig.savefig(OUT/'optimal_k_reliability.png',dpi=180)
    plt.close(fig)
    minimum = next((r['shots'] for r in reliability_rows if r['match_fraction']>=.9),None)
    print('\nДоля совпадений оптимального k с теорией (из 20):')
    for r in reliability_rows:
        print(f"{r['shots']:4d} shots: {r['matches']:2d}/20 = {r['match_fraction']:.0%}")
    print('Минимальное из заданных shots при доле >=90%:',minimum if minimum else 'нет')
    print('ВНИМАНИЕ: 20 запусков не гарантируют истинную вероятность ≥90%;')
    print('это только наблюдаемая доля. Результаты зависят от seed.')
    print('Файлы в:',OUT)

if __name__ == '__main__':
    main()

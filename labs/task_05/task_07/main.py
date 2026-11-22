"""Задание 7, вариант 12, |w>=|110010>, n=6.
Запуск: python main.py
Опционально: python main.py --noise-variant1 (требуется Qiskit Aer).

Без Qiskit доступны точная эволюция NumPy и выборка по распределению,
НЕ называем их реальным Qiskit Statevector/AerSimulator.
"""
import argparse
import csv
import math
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from grover_core import build_oracle, build_grover

VARIANT = 12
MARKED = '110010'
N_QUBITS = 6
N = 1 << N_QUBITS
K_VALUES = range(16)
SHOTS = 1024
SEED = 20261122
OUT = Path(__file__).resolve().parent / 'output'
OUT.mkdir(exist_ok=True)

try:
    from qiskit import transpile
    from qiskit.quantum_info import Statevector
    from qiskit_aer import AerSimulator
    from qiskit_aer.noise import NoiseModel, depolarizing_error
    HAVE_AER = True
except ImportError:
    HAVE_AER = False


def numpy_state(n, marked, k):
    """Точная векторная эволюция, не подстановка формулы вероятности."""
    dim = 1 << n
    state = np.full(dim, 1 / math.sqrt(dim), dtype=np.complex128)
    index = int(marked, 2)
    for _ in range(k):
        state[index] = -state[index]  # U_w
        state = 2 * np.mean(state) - state  # диффузор
    return state


def theory(n, k):
    theta = math.asin(1 / math.sqrt(1 << n))
    return math.sin((2*k+1)*theta)**2


def exact_probabilities(n, marked):
    result = []
    for k in K_VALUES:
        if HAVE_AER:
            state = Statevector.from_instruction(build_grover(n, marked, k)).data
        else:
            state = numpy_state(n, marked, k)
        p = float(abs(state[int(marked, 2)])**2)
        assert abs(p-theory(n, k)) < 1e-9, (n, marked, k, p)
        result.append(p)
    return result


def experimental_probabilities(n, marked, seed=SEED):
    """1024 shots отдельно для каждого k; точно указана природа бэкенда."""
    rng = np.random.default_rng(seed)
    if HAVE_AER:
        sim = AerSimulator()
        out = []
        for k in K_VALUES:
            circuit = build_grover(n, marked, k, measure=True)
            compiled = transpile(circuit, sim, optimization_level=0)
            counts = sim.run(compiled, shots=SHOTS,
                             seed_simulator=int(rng.integers(0, 2**31))).result().get_counts()
            out.append(counts.get(marked, 0) / SHOTS)
        return out
    out = []
    for k in K_VALUES:
        state = numpy_state(n, marked, k)
        # Эквивалент выборки из распределения всех базисных состояний.
        sample = rng.choice(1 << n, size=SHOTS, p=np.abs(state)**2)
        out.append(float(np.mean(sample == int(marked, 2))))
    return out


def first_local_maximum(y):
    """Первый внутренний максимум, либо граница при отсутствии внутренних."""
    for k in range(1, len(y)-1):
        if y[k] >= y[k-1] and y[k] >= y[k+1]:
            return k
    return int(np.argmax(y))


def save_csv(path, rows, cols):
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        writer.writerows(rows)


def make_variant_plot(p_exact, p_exp, p_formula, k_theory, k_exact, k_exp):
    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(16)
    ax.plot(x, np.array(p_formula)*100, '-', lw=2.2, label='Теоретическая формула')
    ax.plot(x, np.array(p_exact)*100, 'o', ms=5, label='Точный вектор состояния')
    ax.plot(x, np.array(p_exp)*100, 's--', ms=4, lw=1.2, label='1024 измерения')
    ax.axvline(k_exact, alpha=.5, linestyle=':', label=f'Первый максимум k={k_exact}')
    ax.set(title=f'Алгоритм Гровера — вариант {VARIANT}, N={N}, |w⟩=|{MARKED}⟩',
           xlabel='Число итераций k', ylabel='Вероятность правильного ответа, %', ylim=(0,105))
    ax.set_xticks(x)
    ax.grid(alpha=.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT/'variant12_probabilities.png', dpi=170)
    plt.close(fig)


def make_groups_plot():
    fig, ax = plt.subplots(figsize=(10, 5.4))
    summary=[]
    for n, marked in [(5,'0'*5),(6,MARKED),(7,'0'*7)]:
        data = exact_probabilities(n, marked)
        k = first_local_maximum(data)
        ax.plot(list(K_VALUES), np.array(data)*100, '-o', ms=3.5,
                label=f'N={2**n}, k первого максимума={k}')
        summary.append({'N':2**n,'n':n,'representative_marked':marked,
                        'k_theoretical_floor':math.floor(math.pi/4*math.sqrt(2**n)),
                        'k_first_max':k,'P_first_max':data[k]})
    ax.set(title='Группы размеров N: точные кривые при M=1',
           xlabel='Число итераций k', ylabel='Вероятность успеха, %', ylim=(0,105))
    ax.set_xticks(list(K_VALUES))
    ax.grid(alpha=.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT/'groups_theoretical.png',dpi=170)
    plt.close(fig)
    save_csv(OUT/'groups_summary.csv', summary, list(summary[0]))


def run_noise_variant1():
    """Дополнительный п.4: это ВАРИАНТ 1, не вариант 12!"""
    if not HAVE_AER:
        print('Шумовой опыт требует: pip install qiskit qiskit-aer')
        return
    n, marked, p1, p2 = 5, '00000', 0.02, 0.05
    noise = NoiseModel()
    error_1 = depolarizing_error(p1, 1)
    error_2 = depolarizing_error(p2, 2)
    for op in ('h','x','p'):
        noise.add_all_qubit_quantum_error(error_1, op)
    noise.add_all_qubit_quantum_error(error_2, 'cx')
    simulator = AerSimulator(noise_model=noise)
    rows=[]
    for k in K_VALUES:
        qc=build_grover(n,marked,k,measure=True)
        compiled=transpile(qc, simulator, basis_gates=['h','x','p','cx'],optimization_level=0)
        counts=simulator.run(compiled,shots=1024,seed_simulator=SEED+k).result().get_counts()
        rows.append({'k':k,'P_theory':theory(n,k), 'P_noisy':counts.get(marked,0)/1024,
                     'n_cx':compiled.count_ops().get('cx',0),'depth':compiled.depth()})
    kmax=max(rows,key=lambda r:r['P_noisy'])['k']
    kideal=first_local_maximum([r['P_theory'] for r in rows])
    save_csv(OUT/'noise_variant1.csv',rows,list(rows[0]))
    fig,ax=plt.subplots(figsize=(10,5.4))
    ax.plot([r['k'] for r in rows], [100*r['P_theory'] for r in rows], '-o', label='Без шума')
    ax.plot([r['k'] for r in rows], [100*r['P_noisy'] for r in rows], '-s', label='С шумом (1024 shots)')
    ax.set(title=f'Вариант 1: p1={p1}, p2={p2}, оптимум без шума={kideal}, с шумом={kmax}',
           xlabel='Итерации k',ylabel='Вероятность успеха, %')
    ax.grid(alpha=.25);ax.legend();fig.tight_layout()
    fig.savefig(OUT/'noise_variant1.png',dpi=170);plt.close(fig)
    print('Вариант 1 с шумом: k_ideal=',kideal,'k_noisy=',kmax,
          'число CX при k=1:',rows[1]['n_cx'],'глубина:',rows[1]['depth'])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--noise-variant1',action='store_true',help='Дополнительный опыт с шумом для варианта 1')
    args=parser.parse_args()
    plt.rcParams['font.family']='DejaVu Sans'
    print('Вариант:', VARIANT, '| N=',N,'| отмеченное состояние:',MARKED)
    print('Моделирование:', 'Qiskit Statevector + AerSimulator' if HAVE_AER
          else 'точная эволюция NumPy + случайная выборка, НЕ Qiskit Aer')
    exact=exact_probabilities(N_QUBITS, MARKED)
    exp=experimental_probabilities(N_QUBITS,MARKED)
    formulas=[theory(N_QUBITS,k) for k in K_VALUES]
    k_theory=math.floor(math.pi/4*math.sqrt(N))
    k_exact=first_local_maximum(exact)
    k_exp=int(np.argmax(exp))
    rows=[{'k':k,'P_formula':formulas[k], 'P_exact':exact[k],
           'P_1024shots':exp[k], 'correct_hits':round(exp[k]*SHOTS)} for k in K_VALUES]
    save_csv(OUT/'variant12_probabilities.csv', rows, list(rows[0]))
    make_variant_plot(exact,exp,formulas,k_theory,k_exact,k_exp)
    make_groups_plot()
    print('k_teor (floor):',k_theory,'| k_exact first max:',k_exact,
          '| k_exp argmax:',k_exp,'| P_exact max:',round(exact[k_exact],8))
    print(' k  P_formula  P_exact  P_1024shots')
    for r in rows:
        print(f"{r['k']:2d}  {r['P_formula']:.6f}   {r['P_exact']:.6f}   {r['P_1024shots']:.6f}")
    if args.noise_variant1:
        run_noise_variant1()
    print('Файлы в:',OUT)

if __name__=='__main__':
    main()

"""Noise study for F(A,B,C,D,E) = MAJ(A,B,C) XOR MAJ(C,D,E).

Run after installing requirements:
    python noise_experiment.py

Creates: results.csv, resources.csv, noise_comparison.png.
"""
import csv
from itertools import product
from pathlib import Path

import matplotlib.pyplot as plt
from qiskit import transpile
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error

from majority_circuits import make_circuit, classical_f, make_computation

# The problem statement omitted numeric probabilities: change these to match teacher's data.
P1 = 0.001  # single-qubit depolarizing error on x and sx
P2_VALUES = [0.0, 0.005, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10]
SHOTS = 1024
SEED = 2026
VERSIONS = ('baseline', 'optimized')
BASIS_GATES = ['x', 'sx', 'rz', 'cx']
OUT = Path(__file__).resolve().parent


def noise_model(p1: float, p2: float) -> NoiseModel:
    if not (0 <= p1 <= 1 and 0 <= p2 <= 1):
        raise ValueError('Noise probabilities must be in [0,1]')
    model = NoiseModel()
    model.add_all_qubit_quantum_error(depolarizing_error(p1, 1), ['x', 'sx'])
    model.add_all_qubit_quantum_error(depolarizing_error(p2, 2), ['cx'])
    # rz is considered a virtual, ideal Z rotation in this experiment.
    # Preparation and measurement errors are not added.
    return model


def compiled_circuits(version: str):
    bits_list = list(product([0, 1], repeat=5))
    circuits = [make_circuit(version, bits, measure=True) for bits in bits_list]
    compiled = transpile(circuits, basis_gates=BASIS_GATES,
                         optimization_level=0, seed_transpiler=SEED)
    assert all('ccx' not in c.count_ops() for c in compiled)
    return bits_list, compiled


def count_resources():
    rows = []
    for version in VERSIONS:
        qc = make_circuit(version, measure=True)
        tqc = transpile(qc, basis_gates=BASIS_GATES,
                        optimization_level=0, seed_transpiler=SEED)
        ops = tqc.count_ops()
        rows.append({'version': version, 'qubits': tqc.num_qubits,
                     'cx_after_transpile': ops.get('cx', 0),
                     'x': ops.get('x', 0), 'sx': ops.get('sx', 0),
                     'rz': ops.get('rz', 0), 'depth': tqc.depth()})
    with (OUT / 'resources.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print('\nResources after transpile:')
    for row in rows:
        print(row)
    return rows


def run_all():
    if SHOTS < 100:
        raise ValueError('SHOTS must be >= 100')
    print(f'p1={P1}; p2 grid={P2_VALUES}; shots={SHOTS}')
    count_resources()
    transpiled_by_version = {v: compiled_circuits(v) for v in VERSIONS}
    result_rows = []
    for p2 in P2_VALUES:
        model = noise_model(P1, p2)
        simulator = AerSimulator(method='matrix_product_state', noise_model=model)
        for version in VERSIONS:
            bits_list, circuits = transpiled_by_version[version]
            result = simulator.run(circuits, shots=SHOTS, seed_simulator=SEED).result()
            correct_output = 0
            correct_and_clean = 0
            for i, bits in enumerate(bits_list):
                expected = classical_f(*bits)
                anc_count = len(make_computation(version)[2])
                counts = result.get_counts(i)
                for observed, count in counts.items():
                    observed = observed.replace(' ', '')
                    # c0 (output) is the rightmost bit in Qiskit's count keys.
                    output_bit = int(observed[-1])
                    all_ancilla_zero = (observed[:-1] == '0' * anc_count)
                    if output_bit == expected:
                        correct_output += count
                        if all_ancilla_zero:
                            correct_and_clean += count
            denominator = len(bits_list) * SHOTS
            row = {'version': version, 'p1': P1, 'p2': p2,
                   'shots_per_input': SHOTS, 'inputs': len(bits_list),
                   'correct_output_fraction': correct_output / denominator,
                   'correct_and_clean_fraction': correct_and_clean / denominator}
            result_rows.append(row)
            print(f'{version:<10} p2={p2:0.3f}  '
                  f'P(output correct)={row["correct_output_fraction"]:.4%}  '
                  f'P(output correct & anc=0)={row["correct_and_clean_fraction"]:.4%}')
    with (OUT / 'results.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(result_rows[0]))
        writer.writeheader()
        writer.writerows(result_rows)
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for version in VERSIONS:
        rows = [r for r in result_rows if r['version'] == version]
        ax.plot([r['p2'] for r in rows],
                [100 * r['correct_output_fraction'] for r in rows],
                marker='o', label=version)
    ax.set_xlabel('Two-qubit depolarizing parameter p2 (CX)')
    ax.set_ylabel('Correct output (%) across 32 inputs')
    ax.set_title(f'MAJ(A,B,C) XOR MAJ(C,D,E) | p1={P1}, {SHOTS} shots/input')
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT / 'noise_comparison.png', dpi=180)
    plt.close(fig)
    print('\nSaved results.csv, resources.csv and noise_comparison.png')


if __name__ == '__main__':
    run_all()

"""Переиспользуемые функции из задания 4: оракул, диффузор, Гровер.
Строки битов соответствуют порядку Qiskit q_(n-1)..q_0.
"""
import math


def build_oracle(n, marked):
    from qiskit import QuantumCircuit
    if n < 1 or len(marked) != n or set(marked) - {'0', '1'}:
        raise ValueError('Некорректное отмеченное состояние')
    qc = QuantumCircuit(n, name=f'Oracle_{marked}')
    for qubit, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(qubit)
    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)
    for qubit, bit in enumerate(reversed(marked)):
        if bit == '0':
            qc.x(qubit)
    return qc


def build_diffuser(n):
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(n, name=f'Diffuser_{n}')
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
    qc.global_phase += math.pi
    return qc


def build_grover(n, marked, k, measure=False):
    from qiskit import QuantumCircuit
    if k < 0:
        raise ValueError('k должно быть неотрицательным')
    qc = QuantumCircuit(n, n if measure else 0)
    qc.h(range(n))
    oracle = build_oracle(n, marked)
    diffuser = build_diffuser(n)
    for _ in range(k):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    if measure:
        qc.measure(range(n), range(n))
    return qc

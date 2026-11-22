from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Operator, Statevector

OUT = Path(__file__).resolve().parent / "output"


def _validate(n: int, marked: str) -> None:
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise ValueError("n должно быть положительным целым числом")
    if not isinstance(marked, str) or len(marked) != n or set(marked) - {"0", "1"}:
        raise ValueError("marked должна быть двоичной строкой длины n")


def _mc_z(qc: QuantumCircuit, n: int) -> None:
    """Многократно управляемый Z на |11...1> без дополнительных кубитов."""
    if n == 1:
        qc.z(0)
    else:
        qc.h(n - 1)
        qc.mcx(list(range(n - 1)), n - 1)
        qc.h(n - 1)


def build_oracle(n: int, marked: str) -> QuantumCircuit:
    """U_w|x> = -|x> при x == marked, иначе |x>."""
    _validate(n, marked)
    qc = QuantumCircuit(n, name=f"Oracle_{marked}")
    # Строка marked, как и Qiskit, записана от q_(n-1) к q_0.
    zero_qubits = [i for i, bit in enumerate(reversed(marked)) if bit == "0"]
    for qubit in zero_qubits:
        qc.x(qubit)
    _mc_z(qc, n)
    for qubit in reversed(zero_qubits):
        qc.x(qubit)
    return qc


def build_diffuser(n: int) -> QuantumCircuit:
    """Точная матрица D = 2|s><s| - I, включая глобальную фазу."""
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise ValueError("n должно быть положительным целым числом")
    qc = QuantumCircuit(n, name=f"Diffuser_{n}")
    for q in range(n):
        qc.h(q)
        qc.x(q)
    _mc_z(qc, n)
    for q in range(n):
        qc.x(q)
        qc.h(q)
    # Без этой глобальной фазы схема реализует I - 2|s><s|.
    qc.global_phase += math.pi
    return qc


def build_grover(n: int, marked: str, iterations: int) -> QuantumCircuit:
    """Подготовка равномерной суперпозиции и k итераций D @ U_w."""
    _validate(n, marked)
    if not isinstance(iterations, int) or iterations < 0:
        raise ValueError("iterations должно быть неотрицательным целым")
    qc = QuantumCircuit(n, name=f"Grover_{n}_{iterations}")
    qc.h(range(n))
    oracle = build_oracle(n, marked)
    diffuser = build_diffuser(n)
    for _ in range(iterations):
        qc.compose(oracle, inplace=True)
        qc.compose(diffuser, inplace=True)
    return qc


def check_oracles() -> None:
    print("1. Проверка оракулов для n = 2, 3, 4, 5")
    total = 0
    for n in range(2, 6):
        dim = 1 << n
        for value in range(dim):
            marked = format(value, f"0{n}b")
            oracle = build_oracle(n, marked)
            # Проверяем действие на ВСЕ базисные состояния, а не только marked.
            for x in range(dim):
                initial = Statevector.from_int(x, dims=[2] * n)
                actual = initial.evolve(oracle).data
                expected = np.zeros(dim, dtype=complex)
                expected[x] = -1 if x == value else 1
                assert np.allclose(actual, expected, atol=1e-10), (n, marked, x)
                total += 1
        print(f"  n={n}: {dim} оракулов × {dim} состояний = {dim * dim}: PASS")
    print(f"  Всего базисных проверок: {total}\n")


def check_diffusers() -> None:
    print("2. Проверка матриц диффузора")
    for n in range(2, 6):
        dim = 1 << n
        uniform = np.ones(dim, dtype=complex) / math.sqrt(dim)
        expected = 2 * np.outer(uniform, uniform.conj()) - np.eye(dim)
        actual = Operator(build_diffuser(n)).data
        error = float(np.max(np.abs(actual - expected)))
        assert np.allclose(actual, expected, atol=1e-10), (n, error)
        print(f"  n={n}: размер {dim}×{dim}, max|D-D_ref|={error:.2e}: PASS")
    print()


def check_grover() -> None:
    print("3. Алгоритм Гровера: n=3, M=1")
    n = 3
    N = 1 << n
    theta = math.asin(1 / math.sqrt(N))
    print(f"  theta = arcsin(1/sqrt({N})) = {theta:.10f} рад")
    print("  marked    k      P(квантовая)     P(теория)       статус")
    for value in range(N):
        marked = format(value, f"0{n}b")
        for k in (1, 2):
            state = Statevector.from_instruction(build_grover(n, marked, k))
            probability = float(abs(state.data[value]) ** 2)
            expected = math.sin((2 * k + 1) * theta) ** 2
            assert abs(probability - expected) < 1e-10, (marked, k)
            print(f"  {marked:>6s}    {k}      {probability:.10f}      {expected:.10f}      PASS")
    print()


def save_examples() -> None:
    OUT.mkdir(exist_ok=True)
    examples = [
        ("oracle_n3_101.txt", build_oracle(3, "101")),
        ("diffuser_n3.txt", build_diffuser(3)),
        ("grover_n3_101_k2.txt", build_grover(3, "101", 2)),
    ]
    for filename, circuit in examples:
        (OUT / filename).write_text(str(circuit.draw(output="text")), encoding="utf-8")
    print(f"4. Текстовые квантовые схемы сохранены в: {OUT}")


def save_probability_plot() -> None:
    # Необязательный наглядный график теории и Qiskit для k=0..5.
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib не установлен: построение графика пропущено")
        return
    n, marked = 3, "101"
    index = int(marked, 2)
    k_values = list(range(6))
    measured = [float(abs(Statevector.from_instruction(build_grover(n, marked, k)).data[index]) ** 2)
                for k in k_values]
    theta = math.asin(1 / math.sqrt(1 << n))
    theoretical = [math.sin((2 * k + 1) * theta) ** 2 for k in k_values]
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.plot(k_values, theoretical, "-", label="Theory", linewidth=2)
    ax.scatter(k_values, measured, marker="o", s=55, label="Qiskit Statevector", zorder=3)
    ax.set(xlabel="Grover iterations, k", ylabel="Probability of marked state", title="Grover search: n=3, marked=101")
    ax.set_ylim(0, 1.05)
    ax.set_xticks(k_values)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    destination = OUT / "grover_probabilities.png"
    fig.savefig(destination, dpi=170)
    plt.close(fig)
    print(f"5. График теории и Statevector: {destination}")


if __name__ == "__main__":
    check_oracles()
    check_diffusers()
    check_grover()
    save_examples()
    save_probability_plot()
    print("Все assert-проверки завершены успешно.")

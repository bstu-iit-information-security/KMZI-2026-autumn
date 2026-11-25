"""
Лабораторная работа №6. Вариант 7.
Квантовые алгоритмы Дойча, Дойча–Йожи и Шора (Qiskit 2.x).

Параметры варианта 7:
- Задание 1 (алгоритм Дойча): 7 mod 5 = 2 -> функция №2 (f_2(x) = x, сбалансированная);
  пункты 1.3–1.5 выполнены для всех 4 функций.
- Задание 2 (алгоритм Дойча–Йожи): 7 mod 5 = 2 -> n = 3 входных кубита (>= 5 запусков);
  пункты 2.2–2.4 выполнены для всех вариантов.
- Задания 3–4 (алгоритм Шора, Таблица А): N = 35, a = 2 (n = 6, m = 2n = 12, всего 18 кубитов).
- Задание 5: относится только к вариантам 16–30 (Таблица Б) и для варианта 7 не выполняется.
- Задание 6: универсальная функция факторизации shor_factor(N, bases) и ответы на вопросы.
"""

import math
from fractions import Fraction
import numpy as np
import matplotlib.pyplot as plt
import sympy

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.primitives import BackendSamplerV2
from qiskit.quantum_info import Statevector, partial_trace
from qiskit.circuit.library import UnitaryGate

backend_sim = AerSimulator()
sampler = BackendSamplerV2(backend=backend_sim)


def run_counts(qc: QuantumCircuit, shots: int = 1024, seed: int | None = None) -> dict[str, int]:
    """Запуск квантовой схемы на симуляторе Aer и получение словаря частот измерений."""
    if seed is None:
        job = sampler.run([qc], shots=shots)
    else:
        seeded_sampler = BackendSamplerV2(backend=AerSimulator(seed_simulator=seed))
        job = seeded_sampler.run([qc], shots=shots)
    pub_result = job.result()[0]
    creg_data = next(iter(pub_result.data.values()))
    return creg_data.get_counts()


# ==============================================================================
# ЗАДАНИЕ 1. АЛГОРИТМ ДОЙЧА
# ==============================================================================

def twobit_function(case: int) -> QuantumCircuit:
    """Оракул для одной из четырёх булевых функций одного бита (case in {1, 2, 3, 4})."""
    if case not in (1, 2, 3, 4):
        raise ValueError("`case` должен принимать значение 1, 2, 3 или 4.")
    f = QuantumCircuit(2)
    if case in (2, 3):
        f.cx(0, 1)
    if case in (3, 4):
        f.x(1)
    return f


def classical_type_1bit(case: int) -> str:
    """Классическое определение типа однобитовой функции."""
    return {
        1: "постоянная",        # f(0)=0, f(1)=0
        2: "сбалансированная",  # f(0)=0, f(1)=1
        3: "сбалансированная",  # f(0)=1, f(1)=0
        4: "постоянная",        # f(0)=1, f(1)=1
    }[case]


def deutsch_decide(oracle: QuantumCircuit) -> str:
    """Определяет тип однобитового оракула за 1 вызов без просмотра его внутренней структуры."""
    gate = oracle.to_gate()
    gate.name = "U_f"

    qc = QuantumCircuit(2, 1)
    qc.x(1)
    qc.h([0, 1])
    qc.append(gate, [0, 1])
    qc.h(0)
    qc.measure(0, 0)

    assert qc.count_ops().get("U_f", 0) == 1, "Оракул должен вызываться ровно 1 раз!"
    counts = run_counts(qc, shots=128)
    return "сбалансированная" if max(counts, key=counts.get) == "1" else "постоянная"


def run_task_1() -> None:
    print("=" * 72)
    print("ЗАДАНИЕ 1. АЛГОРИТМ ДОЙЧА (вариант 7 -> 7 mod 5 = 2 -> case = 2)")
    print("=" * 72)

    # Пункт 1.1: запуск схемы для twobit_function(2)
    qc_1_1 = QuantumCircuit(2, 1)
    qc_1_1.x(1)
    qc_1_1.h([0, 1])
    qc_1_1.barrier()
    qc_1_1.compose(twobit_function(2), inplace=True)
    qc_1_1.barrier()
    qc_1_1.h(0)
    qc_1_1.measure(0, 0)

    counts_1_1 = run_counts(qc_1_1, shots=1024)
    measured_bit = max(counts_1_1, key=counts_1_1.get)
    quantum_ans = "сбалансированная" if measured_bit == "1" else "постоянная"
    print(f"[1.1] Измерения для case=2: {counts_1_1} -> '{quantum_ans}'")
    assert quantum_ans == classical_type_1bit(2)

    # Пункт 1.2: редуцированное состояние кубита 0 после оракула
    print("\n[1.2] Редуцированное состояние кубита 0 после действия оракула:")
    sv_plus = Statevector.from_label("+")
    sv_minus = Statevector.from_label("-")
    for case in (1, 2, 3, 4):
        qc_sv = QuantumCircuit(2)
        qc_sv.x(1)
        qc_sv.h([0, 1])
        qc_sv.compose(twobit_function(case), inplace=True)

        sv_after = Statevector.from_instruction(qc_sv)
        psi_0 = partial_trace(sv_after, [1]).to_statevector()
        is_plus = np.allclose(np.abs(np.vdot(psi_0, sv_plus)), 1.0)
        is_minus = np.allclose(np.abs(np.vdot(psi_0, sv_minus)), 1.0)
        actual = "|+>" if is_plus else ("|->" if is_minus else "иное")
        expected = "|+>" if case in (1, 4) else "|->"
        print(f"  f_{case} ({classical_type_1bit(case)}): состояние кубита 0 = {actual}")
        assert actual == expected

    # Пункт 1.3: удаление вентиля X на целевом кубите 1
    print("\n[1.3] Без вентиля X на целевом кубите 1:")
    for case in (1, 2, 3, 4):
        qc_no_x = QuantumCircuit(2, 1)
        qc_no_x.h([0, 1])
        qc_no_x.compose(twobit_function(case), inplace=True)
        qc_no_x.h(0)
        qc_no_x.measure(0, 0)
        counts = run_counts(qc_no_x, shots=1024)
        res = "сбалансированная" if max(counts, key=counts.get) == "1" else "постоянная"
        print(f"  f_{case}: counts={counts} -> '{res}' (истина: '{classical_type_1bit(case)}')")

    # Пункт 1.4: удаление первого вентиля H на управляющем кубите 0
    print("\n[1.4] Без первого вентиля H на управляющем кубите 0:")
    for case in (1, 2, 3, 4):
        qc_no_h0 = QuantumCircuit(2, 1)
        qc_no_h0.x(1)
        qc_no_h0.h(1)
        qc_no_h0.compose(twobit_function(case), inplace=True)
        qc_no_h0.h(0)
        qc_no_h0.measure(0, 0)
        counts = run_counts(qc_no_h0, shots=1024)
        print(f"  f_{case}: counts={counts} (истина: '{classical_type_1bit(case)}')")

    # Пункт 1.5: универсальная функция deutsch_decide(oracle)
    rng = np.random.default_rng(7)
    for case in (1, 2, 3, 4):
        assert deutsch_decide(twobit_function(case)) == classical_type_1bit(case)
    for _ in range(100):
        case = int(rng.integers(1, 5))
        oracle = twobit_function(case)
        f0 = int(np.argmax(np.abs(Statevector.from_label("00").evolve(oracle).data)) >> 1)
        f1 = int(np.argmax(np.abs(Statevector.from_label("01").evolve(oracle).data)) >> 1)
        expected = "постоянная" if f0 == f1 else "сбалансированная"
        assert deutsch_decide(oracle) == expected
    print("\n[1.5] Все тесты deutsch_decide (4 базовых + 100 случайных) пройдены успешно.")


# ==============================================================================
# ЗАДАНИЕ 2. АЛГОРИТМ ДОЙЧА–ЙОЖИ
# ==============================================================================

def dj_function(n: int, rng: np.random.Generator | None = None) -> QuantumCircuit:
    """Генератор случайного постоянного или сбалансированного оракула на n битах."""
    if rng is None:
        rng = np.random.default_rng()
    qc = QuantumCircuit(n + 1)
    is_balanced = bool(rng.integers(0, 2))
    if not is_balanced:
        if rng.integers(0, 2):
            qc.x(n)
    else:
        mask = int(rng.integers(1, 2**n))
        for i in range(n):
            if (mask >> i) & 1:
                qc.cx(i, n)
        if rng.integers(0, 2):
            qc.x(n)
    return qc


def true_type_by_truth_table(oracle: QuantumCircuit, n: int) -> tuple[str, str]:
    """Полное восстановление таблицы истинности оракула и определение его истинного типа."""
    outputs = []
    for x in range(2**n):
        qc_test = QuantumCircuit(n + 1, 1)
        for i in range(n):
            if (x >> i) & 1:
                qc_test.x(i)
        qc_test.compose(oracle, inplace=True)
        qc_test.measure(n, 0)
        counts = run_counts(qc_test, shots=1)
        outputs.append(max(counts, key=counts.get))
    bitstring = "".join(outputs)
    ones = outputs.count("1")
    if ones in (0, 2**n):
        ftype = "постоянная"
    elif ones == 2 ** (n - 1):
        ftype = "сбалансированная"
    else:
        ftype = "иная"
    return bitstring, ftype


def run_dj(oracle: QuantumCircuit, n: int, shots: int = 1024) -> str:
    """Запуск квантового алгоритма Дойча–Йожи для оракула на n входных кубитах."""
    qc = QuantumCircuit(n + 1, n)
    qc.x(n)
    qc.h(range(n + 1))
    qc.compose(oracle, inplace=True)
    qc.h(range(n))
    qc.measure(range(n), range(n))

    counts = run_counts(qc, shots=shots)
    top = max(counts, key=counts.get)
    return "постоянная" if top == "0" * n else "сбалансированная"


def dj_from_truth_table(f_vals: list[int]) -> QuantumCircuit:
    """Синтез квантового оракула по заданной таблице истинности длины 2^n."""
    size = len(f_vals)
    n = int(round(math.log2(size)))
    assert 2**n == size, "Длина таблицы истинности должна быть степенью двойки."

    qc = QuantumCircuit(n + 1)
    for x, val in enumerate(f_vals):
        if val == 1:
            zeros = [i for i in range(n) if not ((x >> i) & 1)]
            if zeros:
                qc.x(zeros)
            qc.mcx(list(range(n)), n)
            if zeros:
                qc.x(zeros)
    return qc


def run_task_2() -> None:
    print("\n" + "=" * 72)
    print("ЗАДАНИЕ 2. АЛГОРИТМ ДОЙЧА–ЙОЖИ (вариант 7 -> 7 mod 5 = 2 -> n = 3)")
    print("=" * 72)

    # Пункт 2.1: 6 случайных запусков при n = 3
    rng = np.random.default_rng(7)
    print("[2.1] Проверка 6 случайных оракулов для n = 3:")
    for idx in range(1, 7):
        oracle = dj_function(3, rng)
        bits, truth = true_type_by_truth_table(oracle, 3)
        alg_ans = run_dj(oracle, 3, shots=1024)
        assert alg_ans == truth
        print(f"  Запуск {idx}: таблица={bits}, алгоритм='{alg_ans}', истина='{truth}'")

    # Пункт 2.2: проверка dj_from_truth_table для n = 2, 3, 4 (по 50 постоянных и 50 сбалансированных)
    rng_tt = np.random.default_rng(707)
    for n_val in (2, 3, 4):
        n_in = 2**n_val
        for _ in range(50):
            c = int(rng_tt.integers(0, 2))
            assert run_dj(dj_from_truth_table([c] * n_in), n_val, shots=64) == "постоянная"
        for _ in range(50):
            f_vals = [0] * (n_in // 2) + [1] * (n_in // 2)
            rng_tt.shuffle(f_vals)
            assert run_dj(dj_from_truth_table(f_vals), n_val, shots=64) == "сбалансированная"
    print("\n[2.2] Все 300 тестов dj_from_truth_table (n=2,3,4) пройдены успешно.")

    # Пункт 2.3: нарушение обещания (1, 2 и 3 единицы при n = 3)
    print("\n[2.3] Нарушение обещания (n = 3, k единиц в таблице истинности):")
    for k in (1, 2, 3):
        f_vals = [1] * k + [0] * (8 - k)
        oracle = dj_from_truth_table(f_vals)
        qc = QuantumCircuit(4, 3)
        qc.x(3)
        qc.h(range(4))
        qc.compose(oracle, inplace=True)
        qc.h(range(3))
        qc.measure(range(3), range(3))

        counts = run_counts(qc, shots=20000)
        p_sim = counts.get("000", 0) / 20000
        p_th = ((8 - 2 * k) / 8) ** 2
        print(f"  k = {k}: теория P(000) = {p_th:.4f}, симуляция = {p_sim:.4f}")

    # Пункт 2.4: масштабирование n = 2..7 и сравнение сложности
    print("\n[2.4] Масштабирование при n = 2..7:")
    rng_scale = np.random.default_rng(77)
    ns = list(range(2, 8))
    det_queries, prob_queries, quant_queries = [], [], []

    for n_val in ns:
        oracle = dj_function(n_val, rng_scale)
        _, truth = true_type_by_truth_table(oracle, n_val)
        qc = QuantumCircuit(n_val + 1, n_val)
        qc.x(n_val)
        qc.h(range(n_val + 1))
        qc.compose(oracle, inplace=True)
        qc.h(range(n_val))
        qc.measure(range(n_val), range(n_val))

        t_qc = transpile(qc, backend_sim)
        counts = run_counts(t_qc, shots=256)
        ans = "постоянная" if max(counts, key=counts.get) == "0" * n_val else "сбалансированная"
        assert ans == truth

        d_q = 2 ** (n_val - 1) + 1
        det_queries.append(d_q)
        quant_queries.append(1)

        for q in range(1, d_q + 1):
            p_err = 0.0 if q > 2 ** (n_val - 1) else 2 * math.comb(2 ** (n_val - 1), q) / math.comb(2**n_val, q)
            if p_err <= 0.01:
                prob_queries.append(q)
                break

        print(f"  n={n_val}: кубитов={n_val+1}, глубина={t_qc.depth()}, дет.={d_q}, вер.(P_err<=0.01)={prob_queries[-1]}")

    balanced_arr = np.array([0] * 4 + [1] * 4)
    trials = 100_000
    errors = sum(
        1 for _ in range(trials)
        if np.all((s := rng_scale.choice(balanced_arr, size=3, replace=False)) == s[0])
    )
    p_mc = errors / trials
    p_exact = 2 * math.comb(4, 3) / math.comb(8, 3)
    print(f"  Монте-Карло (n=3, q=3): оценка = {p_mc:.5f}, точная формула = {p_exact:.5f}")

    plt.figure(figsize=(8, 5))
    plt.plot(ns, det_queries, marker="o", label="Классический детерминированный ($2^{n-1}+1$)")
    plt.plot(ns, prob_queries, marker="s", label="Классический вероятностный ($P_{err} \\leq 0.01$)")
    plt.plot(ns, quant_queries, marker="^", label="Квантовый Дойча–Йожи ($1$ запрос)")
    plt.xlabel("Число входных кубитов n")
    plt.ylabel("Число запросов к оракулу")
    plt.title("Сравнение запросной сложности (задача Дойча–Йожи)")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()
    plt.tight_layout()
    plt.savefig("dj_complexity_variant_7.png", dpi=150)
    plt.close()


# ==============================================================================
# ЗАДАНИЯ 3, 4 И 6. АЛГОРИТМ ШОРА (вариант 7: N = 35, a = 2)
# ==============================================================================

def inverse_qft(n_qubits: int) -> QuantumCircuit:
    """Обратное квантовое преобразование Фурье на n_qubits кубитах."""
    qc = QuantumCircuit(n_qubits, name="IQFT")
    for i in range(n_qubits // 2):
        qc.swap(i, n_qubits - 1 - i)
    for j in range(n_qubits):
        for k in range(j):
            qc.cp(-np.pi / (2 ** (j - k)), k, j)
        qc.h(j)
    return qc


def mod_mult_gate(b: int, N: int, n_bits: int) -> UnitaryGate:
    """Унитарный оператор модулярного умножения M_b |x> = |b*x mod N> (для x < N)."""
    dim = 2 ** n_bits
    U = np.zeros((dim, dim), dtype=complex)
    for x in range(N):
        U[(b * x) % N, x] = 1.0
    for x in range(N, dim):
        U[x, x] = 1.0

    for x in range(N):
        vec = np.zeros(dim, dtype=complex)
        vec[x] = 1.0
        expected = np.zeros(dim, dtype=complex)
        expected[(b * x) % N] = 1.0
        assert np.allclose(U @ vec, expected), f"Ошибка перестановки для b={b}, x={x}"

    return UnitaryGate(U, label=f"M_{b}")


def build_shor_order_circuit(N: int, a: int, m: int, n_bits: int) -> QuantumCircuit:
    """Квантовая схема оценки фазы для поиска порядка r числа a по модулю N."""
    qc = QuantumCircuit(m + n_bits, m)
    qc.x(m)
    qc.h(range(m))

    for k in range(m):
        b = pow(a, 2 ** k, N)
        if b != 1:
            c_mult = mod_mult_gate(b, N, n_bits).control(1)
            qc.append(c_mult, [k] + list(range(m, m + n_bits)))

    qc.compose(inverse_qft(m), qubits=range(m), inplace=True)
    qc.measure(range(m), range(m))
    return qc


def quantum_order_finding(N: int, a: int, shots: int = 512) -> int | None:
    """Поиск порядка r числа a по модулю N с помощью квантовой схемы."""
    n_bits = math.ceil(math.log2(N))
    m = 2 * n_bits
    qc = build_shor_order_circuit(N, a, m, n_bits)
    counts = run_counts(transpile(qc, backend_sim), shots=shots)

    for bitstr, _ in sorted(counts.items(), key=lambda item: item[1], reverse=True):
        y = int(bitstr, 2)
        r_cand = Fraction(y, 2 ** m).limit_denominator(N).denominator
        if r_cand > 1 and pow(a, r_cand, N) == 1:
            return r_cand
    return None


def shor_factor(N: int, bases: list[int]) -> tuple[tuple[int, int], int, int]:
    """Универсальная функция факторизации числа N по списку оснований bases."""
    attempts = 0
    for a in bases:
        attempts += 1
        g = math.gcd(a, N)
        if 1 < g < N:
            p, q = sorted((g, N // g))
            return (p, q), a, attempts

        r = quantum_order_finding(N, a)
        if r is None or r % 2 != 0:
            continue

        x = pow(a, r // 2, N)
        if x == N - 1:
            continue

        for cand in (math.gcd(x - 1, N), math.gcd(x + 1, N)):
            if 1 < cand < N:
                p, q = sorted((cand, N // cand))
                return (p, q), a, attempts

    raise ValueError(f"Не удалось разложить N={N} по основаниям {bases}")


def run_tasks_3_4_6() -> None:
    print("\n" + "=" * 72)
    print("ЗАДАНИЯ 3–4 И 6. АЛГОРИТМ ШОРА (вариант 7: N = 35, a = 2)")
    print("=" * 72)

    N, a = 35, 2
    assert math.gcd(a, N) == 1
    r_true = next(k for k in range(1, N) if pow(a, k, N) == 1)
    phi_r = sum(1 for k in range(1, r_true + 1) if math.gcd(k, r_true) == 1)
    print(f"[3.1] N = {N} = 5 * 7, a = {a}, gcd(a, N) = 1, порядок r = {r_true}, phi(r)/r = {phi_r / r_true:.4f}")

    n_bits = math.ceil(math.log2(N))  # 6
    m = 2 * n_bits                    # 12
    qc_shor = build_shor_order_circuit(N, a, m, n_bits)
    t_shor = transpile(qc_shor, backend_sim)
    counts_shor = run_counts(t_shor, shots=2000)

    valid_shots = 0
    found_orders: dict[int, int] = {}
    for bs, cnt in counts_shor.items():
        rc = Fraction(int(bs, 2), 2 ** m).limit_denominator(N).denominator
        if rc > 1 and pow(a, rc, N) == 1:
            valid_shots += cnt
            found_orders[rc] = found_orders.get(rc, 0) + cnt

    print(f"[3.3] Доля успешных измерений (2000 shots): {valid_shots / 2000:.4f} (теория: {phi_r / r_true:.4f})")

    r_found = max(found_orders, key=found_orders.get)
    x = pow(a, r_found // 2, N)
    d1, d2 = math.gcd(x - 1, N), math.gcd(x + 1, N)
    print(f"[3.4] r = {r_found}, x = {x}, делители: d1 = {d1}, d2 = {d2}")
    assert d1 * d2 == N and 1 < d1 < N and 1 < d2 < N

    print("\n[3.5] Влияние числа управляющих кубитов m in {n+1 .. 2n}:")
    for m_val in range(n_bits + 1, 2 * n_bits + 1):
        qc_m = build_shor_order_circuit(N, a, m_val, n_bits)
        counts_m = run_counts(transpile(qc_m, backend_sim), shots=2000)
        ok = sum(
            cnt for bs, cnt in counts_m.items()
            if (rc := Fraction(int(bs, 2), 2 ** m_val).limit_denominator(N).denominator) > 1
            and pow(a, rc, N) == 1
        )
        print(f"  m = {m_val:2d}: доля успехов = {ok / 2000:.4f}")

    # Задание 4: 5 независимых запусков
    shares_4_1 = []
    for seed in (107, 207, 307, 407, 507):
        res = run_counts(t_shor, shots=1024, seed=seed)
        ok = sum(
            cnt for bs, cnt in res.items()
            if (rc := Fraction(int(bs, 2), 2 ** m).limit_denominator(N).denominator) > 1
            and pow(a, rc, N) == 1
        )
        shares_4_1.append(ok / 1024)

    p_hat = float(np.mean(shares_4_1))
    std_hat = float(np.std(shares_4_1, ddof=1))
    T_min = math.ceil(math.log(0.01) / math.log(1 - phi_r / r_true))
    print(f"\n[4.1] Средняя доля по 5 запускам: p_hat = {p_hat:.4f} ± {std_hat:.4f}")
    print(f"[4.2] Минимальное число повторов T для P >= 0.99: T = {T_min}")

    # Задание 6: shor_factor (34 имеет порядок 2 -> x = 34 mod 35 = -1 -> отбрасывается; 2 даёт r=12 -> 5*7)
    factors, used_base, tries = shor_factor(35, [34, 2, 3])
    p, q = factors
    assert p * q == 35 and 1 < p < 35 and 1 < q < 35
    assert {p, q} == set(sympy.factorint(35).keys())
    print(f"\n[6] shor_factor(35, [34, 2, 3]) -> 35 = {p} * {q} (основание a = {used_base}, попыток = {tries})")


if __name__ == "__main__":
    run_task_1()
    run_task_2()
    run_tasks_3_4_6()

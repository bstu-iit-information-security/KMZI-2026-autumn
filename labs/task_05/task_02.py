"""Lab 2: F(A,B,C,D,E) = MAJ(A,B,C) XOR MAJ(C,D,E).

Run: pip install -r requirements.txt && python main.py
Requires Qiskit and Qiskit Aer. All basis input cases are checked with 128 shots.
"""

from itertools import product

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

SHOTS = 128
INPUT_LABELS = "ABCDE"


# Reversible logical primitives: t := t XOR operation(inputs).
# A zero-initialized t then holds the requested logical function.
def add_not(qc: QuantumCircuit, a: int, t: int) -> None:
    qc.cx(a, t)
    qc.x(t)


def add_and(qc: QuantumCircuit, a: int, b: int, t: int) -> None:
    qc.ccx(a, b, t)


def add_or(qc: QuantumCircuit, a: int, b: int, t: int) -> None:
    qc.cx(a, t)
    qc.cx(b, t)
    qc.ccx(a, b, t)


def add_xor(qc: QuantumCircuit, a: int, b: int, t: int) -> None:
    qc.cx(a, t)
    qc.cx(b, t)


def add_nand(qc: QuantumCircuit, a: int, b: int, t: int) -> None:
    add_and(qc, a, b, t)
    qc.x(t)


def add_nor(qc: QuantumCircuit, a: int, b: int, t: int) -> None:
    add_or(qc, a, b, t)
    qc.x(t)


def add_maj(
    qc: QuantumCircuit,
    a: int,
    b: int,
    c: int,
    t: int,
    pair_targets: tuple[int, int, int] | None = None,
) -> None:
    """t ^= MAJ(a,b,c) via ab XOR ac XOR bc.

    With pair_targets, compute and keep three separate AND terms (baseline).
    Without them, accumulate pairwise AND terms directly in t (optimized).
    """
    if pair_targets is None:
        add_and(qc, a, b, t)
        add_and(qc, a, c, t)
        add_and(qc, b, c, t)
    else:
        ab, ac, bc = pair_targets
        add_and(qc, a, b, ab)
        add_and(qc, a, c, ac)
        add_and(qc, b, c, bc)
        add_xor(qc, ab, ac, t)
        qc.cx(bc, t)


def majority(a: int, b: int, c: int) -> int:
    return int(a + b + c >= 2)


def classical_f(a: int, b: int, c: int, d: int, e: int) -> int:
    return majority(a, b, c) ^ majority(c, d, e)


def make_computation(version: str) -> tuple[QuantumCircuit, int, list[int]]:
    """Create only the compute block, leaving inputs and output untouched."""
    if version == "baseline":
        # q0..q4: A B C D E; q5: output; q6..q14: 9 clean ancillas
        qc = QuantumCircuit(15, name="compute_baseline")
        add_maj(qc, 0, 1, 2, 12, pair_targets=(6, 7, 8))
        add_maj(qc, 2, 3, 4, 13, pair_targets=(9, 10, 11))
        add_xor(qc, 12, 13, 14)
        return qc, 14, list(range(6, 15))
    if version == "optimized":
        # q0..q4: inputs, q5: output, q6: only one ancilla F.
        qc = QuantumCircuit(7, name="compute_optimized")
        add_maj(qc, 0, 1, 2, 6)
        add_maj(qc, 2, 3, 4, 6)
        return qc, 6, [6]
    raise ValueError(f"Unknown version: {version}")


def make_circuit(version: str, bits: tuple[int, ...] | None = None,
                 measure: bool = False) -> QuantumCircuit:
    """Prepare input, compute F, copy F to output, undo work, optionally measure.

    Classical bit 0 is output; bits 1.. are ancilla measurements.
    """
    computation, f_ancilla, ancillas = make_computation(version)
    n = computation.num_qubits
    n_clbits = 1 + len(ancillas) if measure else 0
    qc = QuantumCircuit(n, n_clbits, name=version)
    if bits is not None:
        if len(bits) != 5 or any(bit not in (0, 1) for bit in bits):
            raise ValueError("bits must be a five-tuple of 0/1")
        for i, bit in enumerate(bits):
            if bit:
                qc.x(i)
    qc.compose(computation, inplace=True)
    qc.cx(f_ancilla, 5)  # output = F; initial output qubit is |0>
    qc.compose(computation.inverse(), inplace=True)  # uncompute all ancillas
    if measure:
        qc.measure(5, 0)
        for i, ancilla in enumerate(ancillas, start=1):
            qc.measure(ancilla, i)
    return qc


def verify_all_cases(shots: int = SHOTS) -> list[tuple[tuple[int, ...], int, int]]:
    if shots < 100:
        raise ValueError("At least 100 shots required")
    versions = ("baseline", "optimized")
    combinations = list(product((0, 1), repeat=5))
    jobs = [(version, bits) for version in versions for bits in combinations]
    circuits = [make_circuit(version, bits, measure=True) for version, bits in jobs]
    # Batched simulation of 64 circuits, each with at least 100 shots.
    result = AerSimulator().run(circuits, shots=shots, seed_simulator=42).result()
    results_by_version = {}
    for index, (version, bits) in enumerate(jobs):
        expected = classical_f(*bits)
        ancilla_count = len(make_computation(version)[2])
        # Qiskit classical bit order is c_{n-1} ... c_1 c_0.
        expected_count_key = "0" * ancilla_count + str(expected)
        counts = result.get_counts(index)
        assert counts == {expected_count_key: shots}, (
            f"FAIL {version} {bits}: expected {expected_count_key} x{shots}, got {counts}"
        )
        results_by_version[(version, bits)] = expected
    rows = []
    print("\nTruth table: each version passed 128 shots (or configured SHOTS), ancillas=0")
    print("A B C D E | F classical | F baseline | F optimized | Status")
    print("-" * 64)
    for bits in combinations:
        expected = classical_f(*bits)
        got_baseline = results_by_version[("baseline", bits)]
        got_optimized = results_by_version[("optimized", bits)]
        print(" ".join(map(str, bits)), f"|      {expected}      |      {got_baseline}     |      {got_optimized}      | PASS")
        rows.append((bits, expected, got_optimized))
    print(f"\nPASS: 32 inputs x 2 circuits x {shots} shots; all ancillas were 0.")
    return rows


def print_resource_comparison() -> None:
    print("\nResource comparison (no input preparation, no measurements):")
    print(f"{'Version':<13} {'qubits':>7} {'CX':>7} {'CCX':>7} {'depth':>7}")
    for version in ("baseline", "optimized"):
        qc = make_circuit(version)
        ops = qc.count_ops()
        print(f"{version:<13} {qc.num_qubits:>7} {ops.get('cx', 0):>7} "
              f"{ops.get('ccx', 0):>7} {qc.depth():>7}")
        print(f"\n{version} circuit:\n{qc.draw(output='text')}")


def main() -> None:
    print("F(A,B,C,D,E) = MAJ(A,B,C) XOR MAJ(C,D,E)")
    print_resource_comparison()
    verify_all_cases(shots=SHOTS)


if __name__ == "__main__":
    main()

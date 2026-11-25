"""Laboratory: quantum full adders and 2/3/4-bit ripple-carry adders."""
from itertools import product
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator

SHOTS = 1024
A0, B0, X0 = 1, 0, 1  # Change to the assigned values if needed.


def expected_full(a, b, x):
    return a ^ b ^ x, (a & b) | (x & (a ^ b))


def optimized_full(qc, a, b, x, s, c):
    """5 qubits, 5 CX + 2 CCX, restores a,b,x."""
    qc.ccx(a, b, c)          # ab
    qc.cx(a, b)             # b <- a XOR b
    qc.ccx(x, b, c)         # c <- ab XOR x(a XOR b)
    qc.cx(a, b)             # restore b
    qc.cx(a, s)
    qc.cx(b, s)
    qc.cx(x, s)


def five_qubit_adder(a=0, b=0, x=0):
    qc = QuantumCircuit(5)
    for value, index in [(a, 0), (b, 1), (x, 2)]:
        if value:
            qc.x(index)
    optimized_full(qc, 0, 1, 2, 3, 4)
    return qc


def half_adders_or(a=0, b=0, x=0):
    """7 qubits: a,b,x,s,c,carry1,carry2. Explicit OR is reversible."""
    qc = QuantumCircuit(7)
    for value, index in [(a, 0), (b, 1), (x, 2)]:
        if value:
            qc.x(index)
    # First half-adder: t=a XOR b in q3; carry1=ab in q5.
    qc.cx(0, 3)
    qc.cx(1, 3)
    qc.ccx(0, 1, 5)
    # Second half-adder: carry2 = t AND x; sum = t XOR x.
    qc.ccx(3, 2, 6)
    qc.cx(2, 3)
    # Reversible OR: c=carry1 XOR carry2 XOR (carry1 AND carry2).
    qc.cx(5, 4)
    qc.cx(6, 4)
    qc.ccx(5, 6, 4)
    return qc


def basis_output(qc):
    state = Statevector.from_instruction(qc)
    probabilities = state.probabilities()
    position = max(range(len(probabilities)), key=lambda i: probabilities[i])
    assert abs(probabilities[position] - 1) < 1e-10
    return [(position >> i) & 1 for i in range(qc.num_qubits)]


def stats(qc):
    # Remove input-preparation X gates, which depend on a,b,x.
    ops = qc.count_ops()
    return qc.num_qubits, ops.get('cx', 0), ops.get('ccx', 0), qc.depth()


def no_initial_x_stats(qc):
    # Build gate-level logic on all-zero input to compare architectural depth.
    return stats(qc)


def exact_basis_sim(qc):
    """Exact gate-by-gate basis simulator, for circuits with only X,CX,CCX."""
    values = [0] * qc.num_qubits
    for inst in qc.data:
        name = inst.operation.name
        indexes = [qc.find_bit(qubit).index for qubit in inst.qubits]
        if name == 'x':
            values[indexes[0]] ^= 1
        elif name == 'cx':
            values[indexes[1]] ^= values[indexes[0]]
        elif name == 'ccx':
            values[indexes[2]] ^= values[indexes[0]] & values[indexes[1]]
        else:
            raise ValueError(f'Unsupported gate: {name}')
    return values


def ripple_adder(n, left=0, right=0):
    """4n+1 qubits: A[n], B[n], S[n], carry[n+1]."""
    qc = QuantumCircuit(4 * n + 1)
    for i in range(n):
        if (left >> i) & 1:
            qc.x(i)
        if (right >> i) & 1:
            qc.x(n + i)
    for i in range(n):
        optimized_full(qc, i, n + i, 3*n + i, 2*n + i, 3*n + i + 1)
    return qc


def output_integer(bits):
    return sum(value << i for i, value in enumerate(bits))


def run():
    print('PART 1: statevector and 1024 shots')
    q = five_qubit_adder(A0, B0, X0)
    s, c = expected_full(A0, B0, X0)
    print('Inputs:', A0, B0, X0, 'Expected S,C:', s, c)
    print('Circuit without measurements:\n', q.draw(output='text'))
    print('Statevector (nonzero amplitudes):', Statevector.from_instruction(q).to_dict())
    measured = q.copy()
    measured.measure_all()
    counts = AerSimulator().run(measured, shots=SHOTS).result().get_counts()
    print('Counts:', counts)
    assert counts == {''.join(str(bit) for bit in basis_output(q)[::-1]): SHOTS}

    print('\nPART 2: optimized 5-qubit full adder')
    print('A B X | S_expected C_expected | S_observed C_observed')
    for a, b, x in product((0, 1), repeat=3):
        out = basis_output(five_qubit_adder(a, b, x))
        expected_s, expected_c = expected_full(a, b, x)
        assert out[:3] == [a, b, x]
        assert (out[3], out[4]) == (expected_s, expected_c)
        print(a, b, x, '|', expected_s, expected_c, '|', out[3], out[4])
    print('All 8 optimized tests passed.')

    print('\nPART 3: two half-adders + OR')
    for a, b, x in product((0, 1), repeat=3):
        out = basis_output(half_adders_or(a, b, x))
        s, c = expected_full(a, b, x)
        assert out[:3] == [a, b, x]
        assert (out[3], out[4]) == (s, c)
        print(a, b, x, '|', s, c, '|', out[3], out[4])
    print('All 8 half-adder tests passed.')
    for name, circuit in [('5-qubit', five_qubit_adder()),
                          ('Half-adders + OR', half_adders_or())]:
        print(name, '(qubits,CX,CCX,depth):', no_initial_x_stats(circuit))
        print(circuit.draw(output='text'))

    print('\nPART 4: ripple adder')
    for n in (2, 3, 4):
        passed = 0
        for left in range(1 << n):
            for right in range(1 << n):
                circuit = ripple_adder(n, left, right)
                out = exact_basis_sim(circuit)
                assert output_integer(out[:n]) == left
                assert output_integer(out[n:2*n]) == right
                result = output_integer(out[2*n:3*n]) | (out[4*n] << n)
                assert result == left + right, (n, left, right, result)
                passed += 1
        no_input = ripple_adder(n)
        print(f'n={n}: tested {passed} pairs, all correct; '
              f'(qubits,CX,CCX,depth)={no_initial_x_stats(no_input)}')
    demo = ripple_adder(4, 9, 6)
    print('Example 9+6 =>', output_integer(exact_basis_sim(demo)[8:12]) |
          (exact_basis_sim(demo)[16] << 4))
    print('4-bit circuit (no input preparation):\n', ripple_adder(4).draw(output='text'))


if __name__ == '__main__':
    run()

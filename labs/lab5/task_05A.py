#!/usr/bin/env python3
"""Lab 5 variant 7: Quantum adders + Grover's algorithm."""
import numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from math import pi, floor, sin, asin, gcd
from collections import Counter
from fractions import Fraction

from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit.circuit.library import UnitaryGate
from qiskit.quantum_info import Statevector, Operator, partial_trace
from qiskit.visualization import plot_histogram
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error

sim = AerSimulator()
print("Qiskit ready")

# ========== TASK 1: FULL ADDER ==========
print("\n=== TASK 1: Full adder A=1,B=0,X=1 ===")
qc = QuantumCircuit(5, 2)
qc.x(0); qc.x(2)
qc.cx(0, 3); qc.cx(1, 3); qc.cx(2, 3)
qc.ccx(0, 1, 4); qc.ccx(1, 2, 4); qc.ccx(0, 2, 4)
qc.measure(3, 0); qc.measure(4, 1)
res = sim.run(qc, shots=1024).result().get_counts()
print("Result:", res, "(expected S=0, C=1)")

def full_adder_5q(a_val, b_val, x_val):
    qc = QuantumCircuit(5, 2)
    if a_val: qc.x(0)
    if b_val: qc.x(1)
    if x_val: qc.x(2)
    qc.cx(0, 3); qc.cx(1, 3); qc.cx(2, 3)
    qc.ccx(0, 1, 4); qc.ccx(1, 2, 4); qc.ccx(0, 2, 4)
    qc.measure(3, 0); qc.measure(4, 1)
    return qc

truth = [(0,0,0,0,0),(0,0,1,1,0),(0,1,0,1,0),(0,1,1,0,1),
         (1,0,0,1,0),(1,0,1,0,1),(1,1,0,0,1),(1,1,1,1,1)]
print("\nFull adder 5q test:")
for a,b,x,exp_s,exp_c in truth:
    qc = full_adder_5q(a,b,x)
    counts = sim.run(qc, shots=1024).result().get_counts()
    got = list(counts.keys())[0]
    got_c, got_s = int(got[0]), int(got[1])
    ok = "✓" if (got_s==exp_s and got_c==exp_c) else "✗"
    print(f"  A={a} B={b} X={x}: S={got_s} C={got_c} (exp S={exp_s} C={exp_c}) {ok}")

def half_adder(qc, a, b, s, c):
    qc.cx(a, s); qc.cx(b, s)
    qc.ccx(a, b, c)

def full_adder_ha(a_val, b_val, x_val):
    qc = QuantumCircuit(8, 2)
    if a_val: qc.x(0)
    if b_val: qc.x(1)
    if x_val: qc.x(2)
    half_adder(qc, 0, 1, 3, 4)
    half_adder(qc, 3, 2, 5, 6)
    qc.x(4); qc.x(6)
    qc.ccx(4, 6, 7)
    qc.x(7)
    qc.x(4); qc.x(6)
    qc.measure(5, 0); qc.measure(7, 1)
    return qc

print("\nHA-based full adder test:")
for a,b,x,exp_s,exp_c in truth:
    qc = full_adder_ha(a,b,x)
    counts = sim.run(qc, shots=1024).result().get_counts()
    got = list(counts.keys())[0]
    got_c, got_s = int(got[0]), int(got[1])
    ok = "✓" if (got_s==exp_s and got_c==exp_c) else "✗"
    print(f"  A={a} B={b} X={x}: S={got_s} C={got_c} (exp S={exp_s} C={exp_c}) {ok}")

qc5 = full_adder_5q(0,0,0); qc5.remove_final_measurements()
qc_ha = full_adder_ha(0,0,0); qc_ha.remove_final_measurements()
print(f"\nComparison: 5q: qubits={qc5.num_qubits} CX={qc5.count_ops().get('cx',0)} CCX={qc5.count_ops().get('ccx',0)} depth={qc5.depth()}")
print(f"HA-based: qubits={qc_ha.num_qubits} CX={qc_ha.count_ops().get('cx',0)} CCX={qc_ha.count_ops().get('ccx',0)} depth={qc_ha.depth()}")

def ripple_adder_gates(n):
    total = 4*n + 1
    qc = QuantumCircuit(total)
    for i in range(n):
        ai, bi, si = i, n+i, 2*n+i
        ci_in = 3*n + i
        ci_out = 3*n + i + 1
        qc.cx(ai, si); qc.cx(bi, si); qc.cx(ci_in, si)
        qc.ccx(ai, bi, ci_out); qc.ccx(bi, ci_in, ci_out); qc.ccx(ai, ci_in, ci_out)
    return qc

def test_ripple(n):
    gates = ripple_adder_gates(n)
    for a in range(2**n):
        for b in range(2**n):
            expected = a + b
            qc = QuantumCircuit(gates.num_qubits, n+1)
            for i in range(n):
                if (a>>i)&1: qc.x(i)
                if (b>>i)&1: qc.x(n+i)
            qc.compose(gates, inplace=True)
            qc.measure([3*n+n] + list(range(3*n-1, 2*n-1, -1)), list(range(n+1)))
            counts = sim.run(qc, shots=100).result().get_counts()
            result = int(list(counts.keys())[0], 2)
            if result != expected: return False
    return True

print("\nRipple-carry adder tests:")
for n_b in [2,3,4]:
    ok = test_ripple(n_b)
    print(f"  {n_b}-bit: {'OK' if ok else 'FAIL'}")
    qc = ripple_adder_gates(n_b)
    print(f"    qubits={qc.num_qubits} CX={qc.count_ops().get('cx',0)} CCX={qc.count_ops().get('ccx',0)} depth={qc.depth()}")

# ========== TASK 2: BOOLEAN FUNCTION VAR 7 ==========
print("\n=== TASK 2: F(A,B,C,D) = (A∧B)∨(C∧D)∨(A∧C) ===")

def F_classical(A,B,C,D):
    return (A & B) | (C & D) | (A & C)

def gate_MAJ(qc, a, b, c, out):
    qc.ccx(a, b, out); qc.ccx(b, c, out); qc.ccx(a, c, out)

def F_quantum_basic():
    qc = QuantumCircuit(10, 1)
    qc.ccx(0, 1, 5)  # t1 = A∧B -> q5
    qc.ccx(2, 3, 6)  # t2 = C∧D -> q6
    qc.ccx(0, 2, 7)  # t3 = A∧C -> q7
    # out = t1 ∨ t2 -> q8 via anc q9
    qc.x(5); qc.x(6)
    qc.ccx(5, 6, 9)
    qc.x(9)
    qc.x(5); qc.x(6)
    qc.cx(9, 8)
    # out = out ∨ t3 -> q4
    qc.x(8); qc.x(7)
    qc.ccx(8, 7, 9)
    qc.x(9)
    qc.x(8); qc.x(7)
    qc.cx(9, 4)
    # uncompute
    qc.ccx(0, 2, 7); qc.ccx(2, 3, 6); qc.ccx(0, 1, 5)
    qc.measure(4, 0)
    return qc

def F_quantum_opt():
    qc = QuantumCircuit(7, 1)
    # t1 = B∨C -> q5 via anc q6
    qc.x(1); qc.x(2)
    qc.ccx(1, 2, 6)
    qc.x(6)
    qc.x(1); qc.x(2)
    qc.cx(6, 5)
    # t2 = A∧t1 -> q6
    qc.ccx(0, 5, 6)
    # t3 = C∧D -> q5
    qc.ccx(2, 3, 5)
    # out = t2 ∨ t3 -> q4
    qc.x(6); qc.x(5)
    qc.ccx(6, 5, 4)
    qc.x(4)
    qc.x(6); qc.x(5)
    # uncompute
    qc.ccx(2, 3, 5); qc.ccx(0, 5, 6)
    qc.x(1); qc.x(2)
    qc.ccx(1, 2, 6)
    qc.x(6)
    qc.x(1); qc.x(2)
    qc.cx(6, 5)
    qc.measure(4, 0)
    return qc

def test_F(builder, name):
    ok = 0
    for bits in range(16):
        A=(bits>>3)&1; B=(bits>>2)&1; C=(bits>>1)&1; D=bits&1
        exp = F_classical(A,B,C,D)
        qc = QuantumCircuit(builder().num_qubits, 1)
        if A: qc.x(0)
        if B: qc.x(1)
        if C: qc.x(2)
        if D: qc.x(3)
        qc.compose(builder(), inplace=True)
        counts = sim.run(qc, shots=100).result().get_counts()
        if int(list(counts.keys())[0]) == exp: ok += 1
    print(f"  {name}: {ok}/16 correct")
    return ok == 16

assert test_F(F_quantum_basic, "basic")
assert test_F(F_quantum_opt, "optimized")

qc_b = F_quantum_basic(); qc_b.remove_final_measurements()
qc_o = F_quantum_opt(); qc_o.remove_final_measurements()
print(f"Basic: qubits={qc_b.num_qubits} CX={qc_b.count_ops().get('cx',0)} CCX={qc_b.count_ops().get('ccx',0)} depth={qc_b.depth()}")
print(f"Optimized: qubits={qc_o.num_qubits} CX={qc_o.count_ops().get('cx',0)} CCX={qc_o.count_ops().get('ccx',0)} depth={qc_o.depth()}")

# ========== TASK 3: NOISE ==========
print("\n=== TASK 3: Noise modeling ===")
def test_F_noise(builder, p2):
    noise = NoiseModel()
    noise.add_all_qubit_quantum_error(depolarizing_error(0.001, 1), ['x','h','z'])
    noise.add_all_qubit_quantum_error(depolarizing_error(p2, 2), ['cx'])
    tqc = transpile(builder(), sim, optimization_level=1)
    correct = 0
    for bits in range(16):
        A=(bits>>3)&1; B=(bits>>2)&1; C=(bits>>1)&1; D=bits&1
        exp = F_classical(A,B,C,D)
        qc = QuantumCircuit(tqc.num_qubits, 1)
        if A: qc.x(0)
        if B: qc.x(1)
        if C: qc.x(2)
        if D: qc.x(3)
        qc.compose(tqc, inplace=True)
        counts = sim.run(qc, shots=100, noise_model=noise).result().get_counts()
        if int(max(counts, key=counts.get)) == exp: correct += 1
    return correct/16

for p2 in [0, 0.001, 0.005, 0.01, 0.02]:
    ab = test_F_noise(F_quantum_basic, p2)
    ao = test_F_noise(F_quantum_opt, p2)
    print(f"  p2={p2:.3f}: basic={ab:.3f} opt={ao:.3f}")

# ========== TASK 4: GROVER ORACLE & DIFFUSER ==========
print("\n=== TASK 4: Grover oracle & diffuser ===")
def build_oracle(n, marked):
    qc = QuantumCircuit(n)
    for i, bit in enumerate(reversed(marked)):
        if bit == '0': qc.x(i)
    qc.h(n-1); qc.mcx(list(range(n-1)), n-1); qc.h(n-1)
    for i, bit in enumerate(reversed(marked)):
        if bit == '0': qc.x(i)
    return qc

def build_diffuser(n):
    qc = QuantumCircuit(n)
    qc.h(range(n)); qc.x(range(n))
    qc.h(n-1); qc.mcx(list(range(n-1)), n-1); qc.h(n-1)
    qc.x(range(n)); qc.h(range(n))
    return qc

for n in [2,3,4]:
    for bits in range(2**n):
        marked = format(bits, f'0{n}b')
        oracle = build_oracle(n, marked)
        op = Operator(oracle)
        diag = np.real(np.diag(op.data))
        for x in range(2**n):
            assert abs(diag[x] - (-1 if x==bits else 1)) < 1e-10
    d = build_diffuser(n)
    op = Operator(d).data
    s = np.ones(2**n)/np.sqrt(2**n)
    target = 2*np.outer(s,s) - np.eye(2**n)
    assert np.allclose(op, target) or np.allclose(op, -target)
print("Oracles and diffusers verified for n=2,3,4")

# ========== TASK 5: GROVER N=2^7 |1010011> ==========
print("\n=== TASK 5: Grover N=2^7, |1010011> ===")
n5, marked5 = 7, "1010011"
N5 = 2**n5
theta5 = asin(1/np.sqrt(N5))
k_opt_theory = round((pi/4)*np.sqrt(N5))
print(f"N={N5}, k_opt_theory={k_opt_theory}")

oracle5 = build_oracle(n5, marked5)
diffuser5 = build_diffuser(n5)

P_exact, P_exp = [], []
for k in range(16):
    qc = QuantumCircuit(n5, n5); qc.h(range(n5))
    for _ in range(k):
        qc.compose(oracle5, inplace=True)
        qc.compose(diffuser5, inplace=True)
    sv = Statevector(qc)
    P_exact.append(sv.probabilities_dict().get(marked5[::-1], 0))
    qc.measure(range(n5), range(n5))
    P_exp.append(sim.run(qc, shots=1024).result().get_counts().get(marked5, 0)/1024)

theory_curve = [sin((2*k+1)*theta5)**2 for k in range(16)]
plt.figure(figsize=(10,5))
plt.plot(range(16), P_exact, 'b-o', label='P exact')
plt.plot(range(16), P_exp, 'r--x', label='P exp')
plt.plot(range(16), theory_curve, 'g:', label='sin^2((2k+1)theta)')
plt.axvline(k_opt_theory, color='gray', linestyle='--', label=f'k_opt_theory={k_opt_theory}')
plt.xlabel('k'); plt.ylabel('P(|w>)'); plt.title(f'Grover N=2^7, |w>=|{marked5}>')
plt.legend(); plt.grid(True); plt.tight_layout(); plt.savefig('grover_task5_var7.png', dpi=100)

k_exact_best = np.argmax(P_exact)
k_exp_best = np.argmax(P_exp)
print(f"k_exact={k_exact_best}, P_max={P_exact[k_exact_best]:.4f}")
print(f"k_exp={k_exp_best}, P_max={P_exp[k_exp_best]:.4f}")

# ========== TASK 6: MULTIPLE SOLUTIONS ==========
print("\n=== TASK 6: Grover with M solutions ===")
n6, N6 = 6, 64
np.random.seed(42)
for M in [1, 2, 3, 4, 8]:
    marked_indices = sorted(np.random.choice(list(range(N6)), M, replace=False))
    marked_strings = [format(x, f'0{n6}b') for x in marked_indices]
    oracle6 = QuantumCircuit(n6)
    for ms in marked_strings:
        oracle6.compose(build_oracle(n6, ms), inplace=True)
    diffuser6 = build_diffuser(n6)
    P6 = []
    for k in range(16):
        qc = QuantumCircuit(n6, n6); qc.h(range(n6))
        for _ in range(k):
            qc.compose(oracle6, inplace=True)
            qc.compose(diffuser6, inplace=True)
        sv = Statevector(qc)
        probs = sv.probabilities_dict()
        P6.append(sum(probs.get(ms[::-1], 0) for ms in marked_strings))
    first_max = next(k for k in range(1, len(P6)-1) if P6[k] > P6[k-1] and P6[k] > P6[k+1])
    k_theory = floor(pi/4 * np.sqrt(N6/M))
    print(f"  M={M}: k_theory={k_theory}, k_max={first_max}, P_max={P6[first_max]:.4f}")

# ========== TASK 7: VARIANT 7 ==========
print("\n=== TASK 7: Variant 7 — N=2^5, |10010> ===")
n7, marked7 = 5, "10010"
N7 = 2**n7
theta7 = asin(1/np.sqrt(N7))
k_opt7 = floor(pi/4 * np.sqrt(N7))
print(f"Variant 7: N={N7}, |w>=|{marked7}>, k_theory={k_opt7}")

oracle7 = build_oracle(n7, marked7)
diffuser7 = build_diffuser(n7)

P_exact7, P_exp7 = [], []
for k in range(16):
    qc = QuantumCircuit(n7, n7); qc.h(range(n7))
    for _ in range(k):
        qc.compose(oracle7, inplace=True)
        qc.compose(diffuser7, inplace=True)
    sv = Statevector(qc)
    P_exact7.append(sv.probabilities_dict().get(marked7[::-1], 0))
    qc.measure(range(n7), range(n7))
    P_exp7.append(sim.run(qc, shots=1024).result().get_counts().get(marked7, 0)/1024)

theory7 = [sin((2*k+1)*theta7)**2 for k in range(16)]
plt.figure(figsize=(10,5))
plt.plot(range(16), P_exact7, 'b-o', label='P exact')
plt.plot(range(16), P_exp7, 'r--x', label='P exp')
plt.plot(range(16), theory7, 'g:', label='sin^2((2k+1)theta)')
plt.axvline(k_opt7, color='gray', linestyle='--', label=f'k_theory={k_opt7}')
plt.xlabel('k'); plt.ylabel('P(|w>)'); plt.title(f'Var 7: Grover N=2^5, |w>=|{marked7}>')
plt.legend(); plt.grid(True); plt.tight_layout(); plt.savefig('grover_var7.png', dpi=100)

k_exact7 = np.argmax(P_exact7)
k_exp7 = np.argmax(P_exp7)
print(f"k_exact={k_exact7}, P_max_exact={P_exact7[k_exact7]:.4f}")
print(f"k_exp={k_exp7}, P_max_exp={P_exp7[k_exp7]:.4f}")

print("\n=== Lab 5 variant 7 DONE ===")

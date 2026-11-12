// Quantum coin for the harbour lottery.
OPENQASM 3.0;
include "stdgates.inc";

gate flip q { h q; }

qubit[1] q;
bit[1] c;

flip q[0];
c[0] = measure q[0];

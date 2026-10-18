## Formal proofs (Lean 4.35.0, core only, no mathlib)

`proofs/` is a Lake project, and every file in it was written for this repository. `proofs/check.sh` fails if any of these occur:
- a `sorry` or `admit` (comments are stripped first);
- a user-declared `axiom`;
- a build error;
- a theorem that `#print axioms` shows depending on `sorryAx`.

The list of theorems checked with `#print axioms` is generated from the sources, so every theorem is covered. The only axioms used are Lean's standard `propext`, `Quot.sound` and `Classical.choice`.

**Result: PASS. 46 theorems, 0 sorry, 0 declared axioms.**

| File | Main theorems | What they establish |
|---|---|---|
| `Proofs/Crdt.lean` | `same_set_same_state`, `reorder_invariant`, `duplicate_invariant`, `merge_replicas`, `deliver_append`, `deliver_mem`, `join_comm`, `join_assoc`, `join_idem`, `join_empty` | **CRDT convergence.** The gossip state is a grow-only set and merge is pointwise union. Delivering any list of envelopes yields exactly "delivered at least once". Two replicas that received the same set are therefore identical, whatever the order, duplicates or delays. Merging two replicas equals delivering both lists |
| `Proofs/Quorum.lean` | `intersection`, `unique_root`, `demo_quorum_ok`, `demo_quorum_live`, plus the counting lemmas `cnt_le`, `cnt_or_and`, `cnt_split`, `exists_of_cnt_pos` | **Quorum intersection.** Two signer sets of size ≥ Q with 2Q > n + f share a non-faulty member. If honest nodes co-sign at most one root per close attempt, at most one root can reach a quorum. The demo's Q = max(n−1, ⌊(n+f)/2⌋+1) always satisfies 2Q > n + f, and for f = 1, n ≥ 4 it is reachable by the honest nodes |
| `Proofs/SecAgg.lean` | `masks_cancel`, `masked_sum_eq_plain_sum`, `masked_floor_mean_eq`, `masked_sum_mod`, plus helpers | With antisymmetric pairwise masks the masks sum to 0 over all n participants. So any node's sum of the masked updates, and ACFA's floor-mean, equals the plain sum or mean. Holds over ℤ (no modulus), as implemented |
| `Proofs/Clip.lean` | `clip_vec_bound`, `masked_clip_range` | Every coordinate of a clamped vector lies in [−b, b]. A clamped value plus a mask in [−M, M] lies in [−(b+M), b+M], so masked Q16.16 values stay inside ±2³¹ |
| `Proofs/Gate.lean` | `gate_accept_no_regression`, `reject_keeps_model`, `installed_within_tol`, `gate_deterministic` | An accepted model is no worse than the one it replaces by more than tol on any axis. A rejected one leaves the installed model unchanged. Nodes that see the same reports decide the same way |
| `Proofs/Budget.lean` | `budget_halt_safe`, `halt_is_permanent`, `run_mono`, `step_mono`, `step_le_cap`, `total_append_mono` | The halting rule never lets the cumulative budget exceed the cap, and once a round is refused the budget stays fixed |
| `Proofs/Determinism.lean` | `order_independent_sum`, `order_independent_floor_mean` | The aggregate doesn't depend on arrival order. With `Crdt.same_set_same_state`, every node computes the identical model |
| `Proofs/Basics.lean` | `sum_perm`, `sum_append_eq`, `withinTol_bound`, `clamp_range`, `clamp_id` | Elementary lemmas used above |

**Not formally proved:**
- the DP Gaussian mechanism and the RDP bound (the accountant is cross-checked numerically against opacus);
- the cryptography (Ed25519, X25519, HKDF and SHAKE-256 are standard primitives);
- liveness under real network timing;
- that the Python implementation matches the Lean model. The tests check that link: for example, shuffled, duplicated and delayed gossip giving identical state hashes, and quorum parameters for n = 4…11.

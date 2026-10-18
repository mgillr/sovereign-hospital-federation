# Threat model and claims: sovereign-hospital-federation (leaderless mesh)

This is a **demonstration on synthetic data**. Every claim below is scoped to what the code and the evidence bundle show. Nothing here claims "complete privacy", legal compliance or certification.

## Parties and trust assumptions
There is **no coordinator, aggregator, relay, auditor or leader** in the protocol. The parties are:

| Party | Trusted for | Not trusted for |
|---|---|---|
| Hospital peer (CH, DE, FR, AT, IT) | its own data, keys and computation | other peers' honesty, the network |
| The network (peer-to-peer links) | eventual delivery between honest peers while they are connected | order, timeliness, uniqueness (messages can be reordered, delayed or duplicated, and links can be partitioned) |
| Consortium PKI | binding node IDs to Ed25519 and X25519 keys | nothing else. Keys are distributed out of band; here they are **throwaway demo keys generated at runtime** |
| Offline verifier (anyone) | nothing: it re-checks the published evidence | n/a, it is not a network participant |

- **Fault model.** At most **f = 1** of n = 5 peers is Byzantine. Quorum Q = max(n − 1, ⌊(n + f)/2⌋ + 1) = 4 (capped at n). Quorum intersection needs **2Q > n + f** (Lean: `Quorum.intersection`, `Quorum.unique_root`, `Quorum.demo_quorum_ok`). With f = 1 and n ≥ 4 the honest peers alone can reach Q (`Quorum.demo_quorum_live`).
- **Timing model.** Partial synchrony, simulated in logical ticks.
  - A round closes when every participant's contribution is held, or when at least Q are held after a deadline.
  - If no root gathers Q co-signatures within the timeout, every node re-closes (up to 4 attempts).
  - **Safety never depends on timing:** without a quorum nothing is installed.
  - **Liveness needs** at most f faulty peers and partitions that heal within the round's tick budget.
  - The demo simulates asynchrony; it does not run over a real WAN.
- **Secure aggregation (blind mode)** assumes honest-but-curious, non-colluding peers. An honest node's update stays hidden as long as at least one of its pairwise masks is unknown to the observer, that is, at least one other participant is honest and does not collude.

## Claims, mechanisms and evidence
| Claim | Mechanism | Evidence | Proof / test |
|---|---|---|---|
| **No central party.** | Full mesh; every protocol step runs on every node from its own CRDT state | `network-egress.log` (every message is a direct `A->B` link) | `test_no_coordinator_anywhere_in_code_or_ui`; `verify_bundle.py` |
| **Convergence.** Same delivered set → same state. | Grow-only set of signed envelopes in crdt-merge `CRDTMergeState`; union is commutative, associative, idempotent; delta anti-entropy per link | `mesh.json` per-tick state hashes | `Crdt.same_set_same_state`, `reorder_invariant`, `duplicate_invariant`, `merge_replicas`; tests with shuffled, duplicated and delayed gossip and healed partitions |
| **One accepted root.** | Each node runs ACFA locally and co-signs (state root, output root, receipt hash, candidate hash, leaves); accept only with ≥ Q matching valid co-signatures | `rounds/*/cosignatures.json` | `Quorum.unique_root`; `test_accepted_root_has_quorum_of_valid_cosignatures` |
| **Divergence and equivocation are detected.** | A co-signature whose root does not follow from its own declared leaves is *divergent* (evidence). One that does but on a partial set is *stale* (no penalty; the node recomputes on the quorum's leaves). Two signed contributions from one node in one round are *equivocation*, seen by every peer in the CRDT | `model-manifest.json`, `peer-trust.json` | `test_divergent_root_*`, `test_equivocation_*`, `test_a_stale_close_is_not_punished_but_a_lying_root_is` |
| **Misbehaving peers are excluded.** | Evidence is recorded with crdt-merge's E4 `TypedTrustScore` (public API: `record_evidence`, `trust_for_dimension`, `QUARANTINE_THRESHOLD`). A peer at ≤ 0.1 in any evidenced dimension is quarantined by every honest node | `peer-trust.json` | `test_equivocation_is_detected_through_the_crdt_and_downgrades_trust`, `test_forged_signature_downgrades_integrity_trust` |
| **Data locality.** No peer receives a patient record. | Data is only read inside the node; one egress function; DLP scanner at every node's gateway; per-link scan | `network-egress.log`, `egress-payloads/`, `local-data-manifest.json` | `test_no_peer_receives_another_nodes_raw_data`, `test_leaky_node_is_caught_and_blocked` |
| **Bounded record-level leakage.** | DP-SGD per node (per-record clip C = 1, Gaussian σ, Poisson sampling) + RDP accountant | `privacy-budget.json`: **ε = {{EPS}} at δ = {{DELTA}}** (max over nodes), cap {{CAP}} | `test_rdp_accountant_matches_opacus`; halting rule `Budget.budget_halt_safe` |
| **Peers can't read individual updates (blind mode).** | Pairwise X25519 masks over the integers; every node sums the masked set itself | `contributions.json` (masked only) | `SecAgg.masks_cancel`, `SecAgg.masked_sum_eq_plain_sum`; `test_blind_mode_no_peer_ever_sees_a_clear_update` |
| **Attributable contributions.** | Ed25519 over (ctx, rule, f, round, node, tensor hash); ctx = H(manifest) pins the base model hash; every node checks signatures itself | `rounds/*/contributions.json` | acfa-rs; `test_forged_signature_is_not_admitted` |
| **Exact aggregate over the shown set.** | ACFA integer kernel + receipt, verified by upstream `acfa-verify` on every node before install, and offline | `verification.txt` | `Determinism.order_independent_sum`; `test_every_honest_node_verifies_its_own_receipt_before_installing` |
| **No regression beyond tol.** | Signed eval reports gossiped; every node applies the gate to the same reports; rollback on fail | `evaluation.json` | `Gate.gate_accept_no_regression`, `Gate.gate_deterministic`; `test_gate_is_applied_by_every_node_identically` |
| **Robustness (robust mode).** A poisoning outlier isn't selected. | ACFA multi-Krum f = 1 on every node | `adversarial-report.json` | `test_poisoning_attacker_is_rejected_by_krum` |

## What peers can see
- **Robust mode:** every peer receives every other peer's **DP-noised, clipped** update. That is the price of per-update filtering without a trusted party. DP bounds what any peer (or the public) can learn about a single record.
- **Blind mode:** peers receive only masked vectors. In a **dispute** (aggregate norm above S, or a gate failure), each disputed node gossips the opening of its signed commitment (its DP-noised update and its pair seeds) **to all peers**. Every honest node checks masked − mask = opening and ‖x‖ ≤ S itself and reaches the same verdict. **This is not zero-knowledge:** during a dispute, all peers learn that attempt's DP-noised updates. Production should use ZK norm proofs (Bulletproofs-style range or norm proofs, as in RoFL or ELSA).
- **Dropouts in blind mode** are handled by **re-masking** over the survivors in a new attempt (new ctx), not by Bonawitz secret-shared seed recovery. It costs one more gossip round. If survivors disagree about who dropped (a partition), the co-signature quorum decides; without a quorum nothing is installed.

## What DP proves here, and what it doesn't
- **Proves (given the mechanism is implemented as specified):** for any single patient record at any one hospital, anything an observer computes from everything that hospital released changes its probability by at most a factor e^ε, plus δ. This holds for every other hospital and for the public. It also caps any membership-inference advantage at (e^ε − 1 + 2δ)/(e^ε + 1).
- **Doesn't prove:**
  - hospital-level privacy;
  - group privacy beyond kε for records duplicated k times;
  - **the DP mechanism itself**: the Lean proofs cover the budget arithmetic and the halting rule, not the Gaussian mechanism; the accountant is cross-checked against opacus;
  - safety against floating-point side channels in the noise sampler (numpy PCG64, not a cryptographic RNG).
- The measured attacks are **evidence, not proofs**.

## Residual risks, stated plainly
1. Weights and updates leak population-level information. DP bounds record-level leakage only.
2. Robust aggregation is distance-based.
   - Non-IID hospitals can be dropped as if they were attackers. The per-site selection counts are reported (some honest sites are rarely selected).
   - Within-norm attackers aren't filtered (acfa-rs paper §7.1).
   - Blind mode does not filter in-bound attackers at all.
3. **Liveness is not guaranteed** with more than f faulty or silent peers, or an unhealed partition: the round fails safe and nothing is installed. Example: a leaky honest node blocked by its own gateway plus a Byzantine peer is 2 faults with f = 1, so no quorum.
4. **Withholding.** A receipt proves an honest computation over the set *shown*. In the mesh, every node computes over its own synced set, and the co-signed leaf set makes any difference visible.
5. **Key theft** lets an attacker impersonate a node. Conviction is of the key; revocation and quarantine appeals are a PKI and governance matter that isn't implemented here.
6. **Simulation.** One process simulates five peers and the network. Isolation is by code structure and the egress gate, **not OS or network isolation**. Asynchrony is simulated in logical ticks.
7. **Legal.** Sovereignty (nFADP or GDPR compliance, transfer impact assessments) requires legal review. This demo provides technical evidence only.

## Licences
- The demo is BSL 1.1 (see LICENSE). Its grant covers research, education, evaluation and non-commercial pilots.
- acfa-rs is Apache-2.0 and used unmodified.
- crdt-merge is BSL 1.1 under its own (broader) grant, used as a PyPI dependency through its public API; see its LICENSE and PATENTS files.

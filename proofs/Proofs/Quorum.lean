/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Quorum intersection for co-signed state roots. Nodes are 0..n-1; a set of nodes is a predicate.
If two signer sets each have at least Q members and 2Q > n + f, they share a member outside any
faulty set of size at most f. Hence, if honest nodes co-sign at most one root per close attempt,
at most one root can reach a quorum. Self-contained Lean 4 (core only).
-/
namespace Quorum

/-- Number of `i < k` with `p i`. -/
def cnt (p : Nat → Bool) : Nat → Nat
  | 0 => 0
  | k + 1 => cnt p k + (if p k then 1 else 0)

theorem cnt_le (p : Nat → Bool) (k : Nat) : cnt p k ≤ k := by
  induction k with
  | zero => simp [cnt]
  | succ k ih => simp only [cnt]; split <;> omega

theorem cnt_or_and (A B : Nat → Bool) (k : Nat) :
    cnt (fun i => A i || B i) k + cnt (fun i => A i && B i) k = cnt A k + cnt B k := by
  induction k with
  | zero => simp [cnt]
  | succ k ih =>
      simp only [cnt]
      by_cases ha : A k = true <;> by_cases hb : B k = true <;> simp [ha, hb] <;> omega

theorem cnt_split (P F : Nat → Bool) (k : Nat) :
    cnt P k ≤ cnt (fun i => P i && !F i) k + cnt F k := by
  induction k with
  | zero => simp [cnt]
  | succ k ih =>
      simp only [cnt]
      by_cases hp : P k = true <;> by_cases hf : F k = true <;> simp [hp, hf] <;> omega

theorem exists_of_cnt_pos (p : Nat → Bool) (k : Nat) (h : 0 < cnt p k) : ∃ i, i < k ∧ p i = true := by
  induction k with
  | zero => simp [cnt] at h
  | succ k ih =>
      simp only [cnt] at h
      by_cases hk : p k = true
      · exact ⟨k, Nat.lt_succ_self k, hk⟩
      · simp [hk] at h
        obtain ⟨i, hi, hp⟩ := ih h
        exact ⟨i, Nat.lt_succ_of_lt hi, hp⟩

/-- Quorum intersection: two quorums share a non-faulty member. -/
theorem intersection (n Q f : Nat) (A B F : Nat → Bool)
    (hA : Q ≤ cnt A n) (hB : Q ≤ cnt B n) (hF : cnt F n ≤ f) (hQ : n + f < 2 * Q) :
    ∃ i, i < n ∧ A i = true ∧ B i = true ∧ F i = false := by
  have h1 := cnt_or_and A B n
  have h2 := cnt_le (fun i => A i || B i) n
  have h3 := cnt_split (fun i => A i && B i) F n
  have hpos : 0 < cnt (fun i => (A i && B i) && !F i) n := by omega
  obtain ⟨i, hi, hp⟩ := exists_of_cnt_pos _ n hpos
  refine ⟨i, hi, ?_, ?_, ?_⟩ <;> cases hAi : A i <;> cases hBi : B i <;> cases hFi : F i <;> simp_all

/-- Safety: if every non-faulty node co-signs at most one root, two quorum roots are equal. -/
theorem unique_root {Root : Type} (n Q f : Nat) (sig : Nat → Root → Bool) (F : Nat → Bool) (r₁ r₂ : Root)
    (h₁ : Q ≤ cnt (fun i => sig i r₁) n) (h₂ : Q ≤ cnt (fun i => sig i r₂) n)
    (hF : cnt F n ≤ f) (hQ : n + f < 2 * Q)
    (honest : ∀ i, F i = false → sig i r₁ = true → sig i r₂ = true → r₁ = r₂) : r₁ = r₂ := by
  obtain ⟨i, _, ha, hb, hf⟩ := intersection n Q f _ _ F h₁ h₂ hF hQ
  exact honest i hf ha hb

/-- The demo's quorum rule Q = max(n - 1, (n + f)/2 + 1) always satisfies 2Q > n + f. -/
theorem demo_quorum_ok (n f : Nat) : n + f < 2 * max (n - 1) ((n + f) / 2 + 1) := by
  have := Nat.le_max_right (n - 1) ((n + f) / 2 + 1)
  omega

/-- Liveness bound for f = 1: with n ≥ 4 the quorum is reachable by the n - 1 honest nodes. -/
theorem demo_quorum_live (n : Nat) (hn : 4 ≤ n) : max (n - 1) ((n + 1) / 2 + 1) ≤ n - 1 := by
  apply Nat.max_le.mpr; constructor <;> omega

end Quorum

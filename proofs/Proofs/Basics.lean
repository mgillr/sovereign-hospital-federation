/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Elementary lemmas used by the other files, written for this repository.
Self-contained Lean 4 (core only, no mathlib). Nothing here is new mathematics.
-/
namespace Basics

/-! ### Integer sums are order independent -/

theorem sum_perm {l₁ l₂ : List Int} (h : l₁.Perm l₂) : l₁.sum = l₂.sum := by
  induction h with
  | nil => rfl
  | cons a _ ih => rw [List.sum_cons, List.sum_cons, ih]
  | swap a b l => rw [List.sum_cons, List.sum_cons, List.sum_cons, List.sum_cons]; omega
  | trans _ _ ih₁ ih₂ => rw [ih₁, ih₂]

theorem sum_append_eq (l₁ l₂ : List Int) : (l₁ ++ l₂).sum = l₁.sum + l₂.sum := by
  induction l₁ with
  | nil => simp
  | cons a t ih => rw [List.cons_append, List.sum_cons, List.sum_cons, ih]; omega

/-! ### Tolerance gate: acceptance means no axis regressed by more than `tol` -/

/-- `score a` is an axis score (site or common benchmark, scaled to naturals). -/
def withinTol (before after : String → Nat) (tol : Nat) : Prop :=
  ∀ a, ¬ (after a + tol < before a)

theorem withinTol_bound {before after : String → Nat} {tol : Nat}
    (h : withinTol before after tol) (a : String) : before a ≤ after a + tol :=
  Nat.le_of_not_lt (h a)

/-! ### Symmetric clamp -/

def clamp (b d : Int) : Int := max (-b) (min b d)

theorem clamp_range (b d : Int) (hb : 0 ≤ b) : -b ≤ clamp b d ∧ clamp b d ≤ b := by
  unfold clamp
  constructor
  · exact Int.le_max_left _ _
  · exact Int.max_le.mpr ⟨by omega, Int.min_le_left _ _⟩

theorem clamp_id (b d : Int) (h₁ : -b ≤ d) (h₂ : d ≤ b) : clamp b d = d := by
  unfold clamp
  rw [Int.min_eq_right h₂, Int.max_eq_right h₁]

end Basics

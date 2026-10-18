/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

DP budget-cap halting rule. Costs are per-round privacy costs in fixed units (e.g. RDP at one order,
which composes ADDITIVELY across rounds — Mironov 2017, Prop. 1; the (eps, delta) conversion is
monotone in that total). Every node runs a round only if cum + cost <= cap, otherwise it halts (each node checks its own budget).
Proved: cumulative cost is monotone, never exceeds the cap, and halting is permanent for a fixed
cost. NOT proved: that DP-SGD satisfies the stated RDP (the mechanism proof is out of scope).
-/
namespace Budget

/-- One scheduling decision: spend if it fits, otherwise halt (cumulative unchanged). -/
def step (cap cum cost : Nat) : Nat := if cum + cost ≤ cap then cum + cost else cum

/-- Run a sequence of rounds from a starting cumulative cost. -/
def run (cap : Nat) : Nat → List Nat → Nat
  | cum, [] => cum
  | cum, c :: cs => run cap (step cap cum c) cs

theorem step_mono (cap cum cost : Nat) : cum ≤ step cap cum cost := by
  unfold step; split <;> omega

theorem step_le_cap (cap cum cost : Nat) (h : cum ≤ cap) : step cap cum cost ≤ cap := by
  unfold step; split <;> omega

/-- The cumulative budget only ever grows (composition is monotone). -/
theorem run_mono (cap : Nat) : ∀ (costs : List Nat) (cum : Nat), cum ≤ run cap cum costs := by
  intro costs
  induction costs with
  | nil => intro cum; exact Nat.le_refl _
  | cons c cs ih => intro cum; exact Nat.le_trans (step_mono cap cum c) (ih _)

/-- SAFETY: starting within the cap, training never exceeds it, for any sequence of round costs. -/
theorem budget_halt_safe (cap : Nat) : ∀ (costs : List Nat) (cum : Nat), cum ≤ cap → run cap cum costs ≤ cap := by
  intro costs
  induction costs with
  | nil => intro cum h; exact h
  | cons c cs ih => intro cum h; exact ih _ (step_le_cap cap cum c h)

/-- Once a round of cost c is refused, every later round of the same cost is refused too. -/
theorem halt_is_permanent (cap cum c : Nat) (h : ¬ cum + c ≤ cap) : step cap cum c = cum := by
  unfold step; simp [h]

/-- Prefix sums of non-negative costs are monotone (plain additive composition). -/
def total : List Nat → Nat
  | [] => 0
  | c :: cs => c + total cs

theorem total_append_mono (a b : List Nat) : total a ≤ total (a ++ b) := by
  induction a with
  | nil => exact Nat.zero_le _
  | cons c cs ih => simp only [total, List.cons_append]; omega

end Budget

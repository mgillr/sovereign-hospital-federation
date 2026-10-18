/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Convergence of the grow-only gossip set (the CRDT that carries signed envelopes).
A replica state is a membership predicate; merge is pointwise `||`. Delivering any list of
envelopes (any order, any duplicates, any delays) yields the predicate "was delivered at least
once", so two replicas that received the same SET of envelopes have identical states.
Self-contained Lean 4 (core only).
-/
namespace Crdt

set_option linter.unusedSectionVars false

variable {α : Type} [DecidableEq α]

abbrev GSet (α : Type) := α → Bool

def empty : GSet α := fun _ => false
def single (x : α) : GSet α := fun y => decide (y = x)
def join (s t : GSet α) : GSet α := fun a => s a || t a

theorem join_comm (s t : GSet α) : join s t = join t s := by
  funext a; simp [join, Bool.or_comm]

theorem join_assoc (s t u : GSet α) : join (join s t) u = join s (join t u) := by
  funext a; simp [join, Bool.or_assoc]

theorem join_idem (s : GSet α) : join s s = s := by
  funext a; simp [join]

theorem join_empty (s : GSet α) : join s empty = s := by
  funext a; simp [join, empty]

/-- A replica applies deliveries one by one. -/
def deliver (s : GSet α) (l : List α) : GSet α := l.foldl (fun acc x => join acc (single x)) s

theorem deliver_mem (s : GSet α) (l : List α) (a : α) :
    deliver s l a = true ↔ (s a = true ∨ a ∈ l) := by
  induction l generalizing s with
  | nil => simp [deliver]
  | cons x xs ih =>
      show deliver (join s (single x)) xs a = true ↔ _
      rw [ih]
      simp [join, single]
      constructor
      · rintro ((h | h) | h) <;> simp_all
      · rintro (h | h | h) <;> simp_all

/-- Convergence: same delivered set ⇒ same state (covers reordering, duplication and delay). -/
theorem same_set_same_state (l₁ l₂ : List α) (h : ∀ a, a ∈ l₁ ↔ a ∈ l₂) :
    deliver empty l₁ = deliver empty l₂ := by
  funext a
  have h₁ := deliver_mem (empty : GSet α) l₁ a
  have h₂ := deliver_mem (empty : GSet α) l₂ a
  simp [empty] at h₁ h₂
  cases e : deliver empty l₁ a <;> cases e' : deliver empty l₂ a <;> simp_all

theorem reorder_invariant (l₁ l₂ : List α) (h : l₁.Perm l₂) :
    deliver empty l₁ = deliver empty l₂ :=
  same_set_same_state l₁ l₂ (fun _ => h.mem_iff)

theorem duplicate_invariant (l : List α) (x : α) (hx : x ∈ l) :
    deliver empty (x :: l) = deliver empty l :=
  same_set_same_state _ _ (fun a => by simp; intro h; subst h; exact hx)

/-- Anti-entropy: two replicas exchanging their states reach the state of the union of deliveries. -/
theorem deliver_append (s : GSet α) (l₁ l₂ : List α) :
    deliver s (l₁ ++ l₂) = deliver (deliver s l₁) l₂ := by
  simp [deliver, List.foldl_append]

theorem merge_replicas (l₁ l₂ : List α) :
    join (deliver empty l₁) (deliver empty l₂) = deliver empty (l₁ ++ l₂) := by
  funext a
  have h₁ := deliver_mem (empty : GSet α) l₁ a
  have h₂ := deliver_mem (empty : GSet α) l₂ a
  have h₃ := deliver_mem (empty : GSet α) (l₁ ++ l₂) a
  simp [empty] at h₁ h₂ h₃
  simp only [join]
  cases e₁ : deliver empty l₁ a <;> cases e₂ : deliver empty l₂ a <;>
    cases e₃ : deliver empty (l₁ ++ l₂) a <;> simp_all

end Crdt

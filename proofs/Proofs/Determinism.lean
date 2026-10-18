/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Aggregation order-independence. ACFA aggregates in integer fixed point, so any two nodes that hold
the same multiset of (masked or clear) contributions compute the same sum in any order. Together
with Crdt.same_set_same_state (same gossiped set) and SecAgg.masked_sum_eq_plain_sum, every node that sums the
masked set itself obtains the sum of the hidden updates.
-/
import Proofs.Basics
namespace Determinism
open Basics

theorem order_independent_sum {l1 l2 : List Int} (h : l1.Perm l2) : l1.sum = l2.sum := sum_perm h

/-- Floor-mean (ACFA select-all band) is order-independent too. -/
theorem order_independent_floor_mean {l1 l2 : List Int} (h : l1.Perm l2) (n : Int) :
    l1.sum / n = l2.sum / n := by rw [sum_perm h]

end Determinism

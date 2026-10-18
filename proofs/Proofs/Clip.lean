/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Clipping bounds (coordinate-wise integer clamp). The demo's L2 clip is float code
(fed/node.py clip_l2) and is NOT proved here; what is proved is the per-coordinate integer bound
that the Q16.16 range check and the secure-aggregation headroom rely on.
-/
import Proofs.Basics
namespace Clip
open Basics

/-- Every coordinate of a clamped integer vector lies in [-b, b]. -/
theorem clip_vec_bound (v : List Int) (b : Int) (hb : 0 ≤ b) :
    ∀ y ∈ v.map (clamp b), -b ≤ y ∧ y ≤ b := by
  intro y hy
  obtain ⟨d, _, rfl⟩ := List.mem_map.mp hy
  exact clamp_range b d hb

/-- A clamped coordinate plus any mask in [-M, M] stays in [-(b+M), b+M]: the masked value fits
the integer range whenever b + (n-1)M <= 2^31 - 1 (fed/secagg.py mask_range). -/
theorem masked_clip_range (d b r M : Int) (hb : 0 ≤ b) (hr : -M ≤ r ∧ r ≤ M) :
    -(b + M) ≤ clamp b d + r ∧ clamp b d + r ≤ b + M := by
  have h := clamp_range b d hb
  omega

end Clip

/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Pairwise-mask secure aggregation, exactly as fed/secagg.py implements it:
node i adds +m(i,j) for every peer j > i and -m(j,i) for every peer j < i, over the INTEGERS
(no modulus). For ANY number of nodes n and ANY mask values the masks cancel in the sum, so the
masked sum equals the plain sum, and ACFA's floor-mean over masked vectors equals the floor-mean
of the hidden updates. One coordinate is modelled; coordinates are independent.
-/
namespace SecAgg

/-- sum_{i<n} g i -/
def sumTo : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | n + 1, g => sumTo n g + g n

theorem sumTo_add (n : Nat) (g h : Nat → Int) :
    sumTo n (fun i => g i + h i) = sumTo n g + sumTo n h := by
  induction n with
  | zero => simp [sumTo]
  | succ k ih => simp only [sumTo]; rw [ih]; omega

theorem sumTo_neg (n : Nat) (g : Nat → Int) :
    sumTo n (fun i => - g i) = - sumTo n g := by
  induction n with
  | zero => simp [sumTo]
  | succ k ih => simp only [sumTo]; rw [ih]; omega

theorem sumTo_congr (n : Nat) (g h : Nat → Int) (e : ∀ i, i < n → g i = h i) :
    sumTo n g = sumTo n h := by
  induction n with
  | zero => rfl
  | succ k ih =>
      simp only [sumTo]
      rw [ih (fun i hi => e i (Nat.lt_succ_of_lt hi)), e k (Nat.lt_succ_self k)]

/-- Double sum over the square n x n. -/
def dsum (n : Nat) (f : Nat → Nat → Int) : Int := sumTo n (fun i => sumTo n (fun j => f i j))

/-- Any antisymmetric pairing sums to zero over the square, for every n. -/
theorem antisym_dsum_zero (f : Nat → Nat → Int) (hf : ∀ i j, f i j = - f j i) :
    ∀ n, dsum n f = 0 := by
  intro n
  induction n with
  | zero => simp [dsum, sumTo]
  | succ k ih =>
      have hkk : f k k = 0 := by have := hf k k; omega
      have row : ∀ i, sumTo (k + 1) (fun j => f i j) = sumTo k (fun j => f i j) + f i k := fun i => rfl
      have split : dsum (k + 1) f =
          (sumTo k (fun i => sumTo k (fun j => f i j)) + sumTo k (fun i => f i k)) +
          (sumTo k (fun j => f k j) + f k k) := by
        unfold dsum
        show sumTo k (fun i => sumTo (k + 1) (fun j => f i j)) + sumTo (k + 1) (fun j => f k j) = _
        rw [sumTo_congr k (fun i => sumTo (k + 1) (fun j => f i j))
              (fun i => sumTo k (fun j => f i j) + f i k) (fun i _ => row i)]
        rw [sumTo_add]; rfl
      have col : sumTo k (fun i => f i k) = - sumTo k (fun j => f k j) := by
        rw [← sumTo_neg]; exact sumTo_congr k _ _ (fun i _ => hf i k)
      have h0 : sumTo k (fun i => sumTo k (fun j => f i j)) = 0 := ih
      rw [split, h0, col, hkk]; omega

/-- Sign of a pair as in the implementation: +1 if i < j, -1 if j < i, 0 on the diagonal. -/
def sgn (i j : Nat) : Int := if i < j then 1 else if j < i then -1 else 0

/-- The mask shared by the unordered pair {i, j} (one value; m is arbitrary). -/
def pairMask (m : Nat → Nat → Int) (i j : Nat) : Int := m (min i j) (max i j)

/-- Node i's total mask over n participants. -/
def nodeMask (m : Nat → Nat → Int) (n i : Nat) : Int := sumTo n (fun j => sgn i j * pairMask m i j)

theorem term_antisym (m : Nat → Nat → Int) (i j : Nat) :
    sgn i j * pairMask m i j = - (sgn j i * pairMask m j i) := by
  unfold sgn pairMask
  rw [Nat.min_comm j i, Nat.max_comm j i]
  by_cases h1 : i < j
  · have : ¬ j < i := Nat.lt_asymm h1
    simp [h1, this]
  · by_cases h2 : j < i
    · simp [h1, h2]
    · simp [h1, h2]

/-- MASKS CANCEL: for any n and any masks, the participants' masks sum to exactly zero. -/
theorem masks_cancel (m : Nat → Nat → Int) (n : Nat) :
    sumTo n (fun i => nodeMask m n i) = 0 := by
  have := antisym_dsum_zero (fun i j => sgn i j * pairMask m i j) (term_antisym m) n
  simpa [dsum, nodeMask] using this

/-- Any node's sum of the masked values equals the sum of the hidden updates. -/
theorem masked_sum_eq_plain_sum (x : Nat → Int) (m : Nat → Nat → Int) (n : Nat) :
    sumTo n (fun i => x i + nodeMask m n i) = sumTo n x := by
  rw [sumTo_add, masks_cancel]; omega

/-- ACFA's select-all-band aggregate is a floor-mean; it is the same on masked and plain inputs. -/
theorem masked_floor_mean_eq (x : Nat → Int) (m : Nat → Nat → Int) (n : Nat) :
    sumTo n (fun i => x i + nodeMask m n i) / (n : Int) = sumTo n x / (n : Int) := by
  rw [masked_sum_eq_plain_sum]

/-- Residues agree for every modulus too (the ZMod-style statement, as a corollary). -/
theorem masked_sum_mod (x : Nat → Int) (m : Nat → Nat → Int) (n : Nat) (q : Int) :
    sumTo n (fun i => x i + nodeMask m n i) % q = sumTo n x % q := by
  rw [masked_sum_eq_plain_sum]

end SecAgg

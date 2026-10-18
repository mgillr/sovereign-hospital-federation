/-
SPDX-License-Identifier: BUSL-1.1
Copyright 2026 Ryan Gillespie / Optitransfer

Regression gate. fed/federation.py regression_gate scores accuracies in integer basis points and
accepts iff no axis (site or common benchmark) falls below before - tol. Every node applies the
gate itself to the gossiped, signed eval reports; acceptance implies no regression beyond tol on
EVERY axis.
-/
import Proofs.Basics
namespace Gate
open Basics

abbrev Metrics := String → Nat

/-- The demo's gate, as implemented: accept iff no axis has after + tol < before. -/
def gateAccepts (before after : Metrics) (tol : Nat) : Prop := withinTol before after tol

theorem gate_accept_no_regression {before after : Metrics} {tol : Nat}
    (h : gateAccepts before after tol) : ∀ axis, before axis ≤ after axis + tol :=
  withinTol_bound h

/-- Rolling back on rejection keeps the installed model: the installed scores never change on reject. -/
def install (before after : Metrics) (accept : Bool) : Metrics := if accept then after else before

theorem reject_keeps_model (before after : Metrics) : install before after false = before := rfl

/-- Over a run, every installed model is within tol of the one it replaced, on every axis. -/
theorem installed_within_tol {before after : Metrics} {tol : Nat} (h : gateAccepts before after tol) :
    ∀ axis, before axis ≤ install before after true axis + tol := by
  intro axis; exact gate_accept_no_regression h axis

/-- Nodes that see the same reports decide the same way (the gate is a function of its inputs). -/
theorem gate_deterministic (before after : Metrics) (tol : Nat) [Decidable (gateAccepts before after tol)]
    (d₁ d₂ : Bool) (h₁ : d₁ = decide (gateAccepts before after tol)) (h₂ : d₂ = decide (gateAccepts before after tol)) :
    d₁ = d₂ := by rw [h₁, h₂]

end Gate

#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
# Fails on any build error, any `sorry`/`admit`, any user-declared axiom, or any theorem depending on sorryAx.
# Every theorem in Proofs/ is checked with #print axioms (the list is generated, not hand-maintained).
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v lake >/dev/null 2>&1; then echo "PROOFS: lean/lake not installed (install elan); SKIPPED"; exit 2; fi
echo "toolchain: $(cat lean-toolchain)  ($(lean --version))"
strip() { perl -0pe 's{/-.*?-/}{}gs; s{--[^\n]*}{}g' "$1"; }
for f in Proofs.lean Proofs/*.lean; do
  if strip "$f" | grep -nE '\bsorry\b|\badmit\b'; then echo "PROOFS: FAIL (sorry/admit in $f)"; exit 1; fi
  if strip "$f" | grep -nE '^\s*axiom\s'; then echo "PROOFS: FAIL (user axiom in $f)"; exit 1; fi
done
lake build 2>&1 | tail -5
mkdir -p .lake
ax=.lake/axioms_check.lean
{ echo "import Proofs"
  for f in Proofs/*.lean; do
    ns=$(perl -ne 'print "$1\n" and exit if /^namespace\s+(\S+)/' "$f")
    strip "$f" | perl -ne 'print "$1\n" if /^theorem\s+(\S+)/' | while read -r t; do echo "#print axioms ${ns}.${t}"; done
  done; } > "$ax"
n=$(grep -c '^#print' "$ax")
out=$(lake env lean "$ax" 2>&1)
echo "$out"
if echo "$out" | grep -q sorryAx; then echo "PROOFS: FAIL (sorryAx)"; exit 1; fi
if echo "$out" | grep -qiE 'error'; then echo "PROOFS: FAIL (error)"; exit 1; fi
m=$(echo "$out" | grep -cE "depends on axioms|does not depend on any axioms")
if [ "$m" -ne "$n" ]; then echo "PROOFS: FAIL (checked $m of $n theorems)"; exit 1; fi
echo "PROOFS: PASS ($n theorems, each checked with #print axioms; 0 sorry, 0 axioms declared)"

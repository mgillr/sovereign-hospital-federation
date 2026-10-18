# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Thin wrapper over the acfa-bridge binary (acfa-rs @ d19fb56) and upstream `acfa-verify`.
No aggregation, hashing or signing is re-implemented in Python."""
import json, os, shutil, subprocess

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACFA_REV = "d19fb56b043ddad3ac0448ed9ceede51ba6c2c47"


def _bin(env, *cands):
    p = os.environ.get(env)
    if p: return p
    for c in cands:
        if os.path.exists(c): return c
        w = shutil.which(os.path.basename(c))
        if w: return w
    raise FileNotFoundError(f"set {env}")


def bridge_bin():
    return _bin("ACFA_BRIDGE_BIN", os.path.join(_HERE, "bridge/target/release/acfa-bridge"), "/usr/local/bin/acfa-bridge")


def verify_bin():
    return _bin("ACFA_VERIFY_BIN", os.path.join(_HERE, ".bin/bin/acfa-verify"), "/usr/local/bin/acfa-verify")


def call(cmd, payload):
    p = subprocess.run([bridge_bin(), cmd], input=json.dumps(payload), capture_output=True, text=True, timeout=60)
    out = json.loads(p.stdout or "{}")
    if p.returncode != 0 or "error" in out:
        raise RuntimeError(f"acfa-bridge {cmd}: {out.get('error', p.stderr)}")
    return out


def verify(receipt_path, pki_path, ctx_hex, f, expect_root):
    args = [verify_bin(), receipt_path, "--pki", pki_path, "--rule", "krum", "--ctx", ctx_hex, "--f", str(f),
            "--expect-state-root", expect_root, "--max-coordinates", "50000000"]
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    return {"argv": ["acfa-verify"] + args[1:], "exit_code": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

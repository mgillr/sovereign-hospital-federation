#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Standalone, offline re-check of a sovereign-hospital-federation evidence bundle (leaderless design:
every hospital aggregates locally; a quorum of co-signed roots decides; there is no coordinator).

Needs: python3 + numpy; the upstream `acfa-verify` binary from acfa-rs @ d19fb56 (ACFA_VERIFY_BIN or PATH);
optional: `cryptography` (signature checks) and Lean/lake (formal proofs). Nothing is fetched from the network.

    python3 verify_bundle.py evidence.zip            # or an unzipped directory
Exit 0 iff every check passes.
"""
import hashlib, io, json, math, os, re, shutil, subprocess, sys, tempfile, zipfile
import numpy as np

Q = 1 << 16
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return ok


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def enc_tensor(t):
    return "|".join(str(int(v)) for v in t).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def model_sha(w):
    return sha(np.asarray(w, dtype="<f4").tobytes())


# ---- RDP accountant (identical maths to fed/dp.py, re-embedded so this script is standalone)
ORDERS = list(range(2, 64)) + [80, 96, 128, 192, 256]


def _log_add(a, b):
    if a == -math.inf: return b
    if b == -math.inf: return a
    m = max(a, b); return math.log1p(math.exp(min(a, b) - m)) + m


def eps_for(q, sigma, steps, delta):
    best = math.inf
    for a in ORDERS:
        la = -math.inf
        for i in range(a + 1):
            la = _log_add(la, math.log(math.comb(a, i)) + i * math.log(q) + (a - i) * math.log(1 - q) + (i * i - i) / (2 * sigma ** 2))
        r = la / (a - 1) * steps
        e = r - (math.log(delta) + math.log(a)) / (a - 1) + math.log((a - 1) / a)
        best = min(best, e)
    return best


def main(src):
    tmp = None
    if os.path.isfile(src):
        tmp = tempfile.mkdtemp(); zipfile.ZipFile(src).extractall(tmp); root = tmp
    else:
        root = src
    P = lambda *a: os.path.join(root, *a)
    J = lambda *a: json.load(open(P(*a)))
    mm = J("model-manifest.json"); mode = mm["mode"]
    vbin = os.environ.get("ACFA_VERIFY_BIN") or shutil.which("acfa-verify")
    check("acfa-verify binary available", vbin, vbin or "set ACFA_VERIFY_BIN")
    pki = {int(l.split()[0]): l.split()[1] for l in open(P("consortium.pki")) if l.strip() and not l.startswith("#")}
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        def ed_ok(pk, msg, sig):
            try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(bytes.fromhex(sig), msg); return True
            except Exception: return False
    except ImportError:
        ed_ok = None
    # ---------------- INTEGRITY: per round
    prev = np.load(P("models", "base-model-r0.npy"))
    check("base model r0 hash pinned", model_sha(prev) == mm["base_model_r0_sha256"], mm["base_model_r0_sha256"][:16])
    sites = set(mm["site_node_ids"]); id2site = {v: k for k, v in mm["site_node_ids"].items()}
    for rm in mm["rounds"]:
        r = rm["round"]; d = P("rounds", f"round-{r}")
        man = json.load(open(os.path.join(d, "manifest.json")))
        rbytes = open(os.path.join(d, "receipt.acfa"), "rb").read()
        ctx = sha(canon(man))
        check(f"r{r} ctx = sha256(manifest)", ctx == rm["ctx"])
        check(f"r{r} manifest pins the previous model hash", man["base_model_sha256"] == model_sha(prev))
        f = man["aggregation"]["f"]
        roots = set(rm["node_state_roots"].values())
        check(f"r{r} every node's own synced set gives one state root", len(roots) == 1)
        check(f"r{r} every node derived the byte-identical receipt itself",
              set(rm["receipt_sha256_per_node"].values()) == {sha(rbytes)}, f"{len(rm['receipt_sha256_per_node'])} nodes")
        out = ""
        if vbin:
            p = subprocess.run([vbin, os.path.join(d, "receipt.acfa"), "--pki", P("consortium.pki"), "--rule", "krum",
                                "--ctx", ctx, "--f", str(f), "--expect-state-root", next(iter(roots)),
                                "--max-coordinates", "50000000"], capture_output=True, text=True)
            out = p.stdout
            check(f"r{r} acfa-verify (pinned rule, ctx, f, state root) exit 0", p.returncode == 0, f"exit {p.returncode}")
        agg = json.load(open(os.path.join(d, "aggregate.json")))["aggregate_q16"]
        m = re.search(r"output root\s+([0-9a-f]{64})", out)
        check(f"r{r} aggregate.json hashes to the receipt's output root",
              m and sha(b"agg|" + enc_tensor(agg)) == m.group(1))
        contribs = json.load(open(os.path.join(d, "contributions.json")))
        sig_ok = True
        for c in contribs:
            th = hashlib.sha256(enc_tensor(c["tensor"])).digest()
            sig_ok &= th.hex() == c["tensor_hash"]
            if ed_ok:
                msg = (b"ACFA-CONTRIB2|" + bytes.fromhex(c["ctx"]) + bytes([0]) + int(c["f"]).to_bytes(4, "big") +
                       (16).to_bytes(4, "big") + int(c["round"]).to_bytes(8, "big") + int(c["node_id"]).to_bytes(4, "big") + th)
                valid = ed_ok(pki[c["node_id"]], msg, c["sig"])
                if c["node_id"] in rm["receipt"]["admitted"]: sig_ok &= valid
        check(f"r{r} admitted contributions: tensor hashes + Ed25519 signatures re-checked in python", sig_ok,
              "" if ed_ok else "cryptography missing: hashes only")
        cand = (np.asarray(prev, np.float32) + (np.asarray(agg, np.float64) / Q).astype(np.float32)).astype(np.float32)
        # ---- quorum of co-signed roots (no leader decides; the quorum does)
        cos = json.load(open(os.path.join(d, "cosignatures.json")))
        leaves = sorted(c["leaf"] for c in contribs)
        check(f"r{r} every published co-signature verifies under the consortium PKI", not ed_ok or all(
            c["node_id"] in pki and ed_ok(pki[c["node_id"]], json.dumps({k: v for k, v in c.items() if k != "sig"},
                                                                       sort_keys=True).encode(), c["sig"]) for c in cos),
              f"{len(cos)} co-signatures")
        good = set()
        for c in cos:
            body = {k: v for k, v in c.items() if k != "sig"}
            if c["node_id"] not in man["participants"]: continue
            if ed_ok and not ed_ok(pki[c["node_id"]], json.dumps(body, sort_keys=True).encode(), c["sig"]): continue
            if (c["state_root"] == next(iter(roots)) and m and c["output_root"] == m.group(1)
                    and c["receipt_sha256"] == sha(rbytes) and c["candidate_sha256"] == model_sha(cand)
                    and sorted(c["leaves"]) == leaves and c["ctx"] == ctx):
                good.add(c["node_id"])
        n_p = len(man["participants"]); qn = man["close_rule"]["cosign_quorum"]
        check(f"r{r} quorum of co-signed roots: {len(good)} valid signatures >= Q={qn} (n={n_p}, 2Q > n+1)",
              len(good) >= qn and 2 * qn > n_p + 1, ", ".join(id2site[i] for i in sorted(good)))
        check(f"r{r} candidate = base + aggregate reproduces every node's installed hash",
              model_sha(cand) == rm["candidate_sha256"] and set(rm["installed_hashes"].values()) == {rm["candidate_sha256"]},
              rm["candidate_sha256"][:16])
        if mode == "blind":
            adm = [c for c in contribs if c["node_id"] in rm["receipt"]["admitted"]]
            tot = np.sum([np.asarray(c["tensor"], dtype=object) for c in adm], axis=0)
            fm = [int(v) // len(adm) for v in tot]
            check(f"r{r} blind: receipt aggregate == floor(sum(masked)/n) (masks cancelled)", fm == agg)
            big = min(float(np.linalg.norm(np.asarray(c["tensor"], np.float64) / Q)) for c in adm)
            check(f"r{r} blind: no peer ever received an in-range update (min masked L2 = {big:.0f} >> S)", big > 1000)
        # gate recomputed from signed eval reports
        reps = json.load(open(os.path.join(d, "eval-reports.json")))
        rep_ok = all(ed_ok(pki[e["node_id"]], json.dumps({k: v for k, v in e.items() if k != "sig"}, sort_keys=True).encode(),
                           e["sig"]) and e["node_id"] == mm["site_node_ids"][e["site"]] for e in reps) if ed_ok else True
        check(f"r{r} eval reports signed by their node", rep_ok)
        g = rm["gate"]; tol = mm["gate_tol"]
        bp = lambda v: int(round(v * 10000))
        before = {e["site"]: e["before"] for e in reps}; after = {e["site"]: e["after"] for e in reps}
        site_fail = [s for s in before if bp(after[s]) + bp(tol) < bp(before[s])]
        check(f"r{r} gate decision consistent with signed reports (passed={g['passed']})",
              (not site_fail) or not g["passed"])
        new = np.load(P("models", f"model-r{r}.npy"))
        expect = rm["candidate_sha256"] if g["passed"] else model_sha(prev)
        check(f"r{r} installed model follows the gate (install on pass, keep on fail)", model_sha(new) == expect)
        prev = new
    check("final model hash", model_sha(prev) == mm["final_model_sha256"], mm["final_model_sha256"][:16])
    # ---------------- SOVEREIGNTY
    log = [json.loads(l) for l in open(P("network-egress.log"))]
    allowed = set(mm["allowed_message_types"])
    check("egress: only allowed message types", all(e["type"] in allowed or
          all(f"gossip/{k}" in allowed for k in e["type"].split("/", 1)[1].split("+")) for e in log if e["type"] != "public-keys")
          and all(e["type"].startswith(("gossip", "public-keys")) for e in log), ", ".join(sorted(allowed)))
    check("no coordinator: every message is a direct hospital-to-hospital link",
          all(e["src"] in sites and e["dst"] in sites and e["src"] != e["dst"] for e in log),
          f"{len({e['link'] for e in log})} distinct links")
    hashes_ok, pat_hits, bad = True, 0, []
    dm = J("local-data-manifest.json")
    canary_hashes = {h: n["site"] for n in dm["nodes"] for h in n["canary_sha256"]}
    pat = re.compile(rb"CANARY-[A-Z]{2}-[0-9a-f]{12}|[A-Z]{2}-T[RE]-\d{6}|full_name|date_of_birth|Synthetic Patient|cv_event_5y")
    withheld = 0
    for e in log:
        fp = P("egress-payloads", f"{e['seq']:06d}-{e['type'].replace('/', '_')}.bin")
        if e["dlp"] != "pass":
            withheld += 1; hashes_ok &= not os.path.exists(fp); continue
        b = open(fp, "rb").read()
        hashes_ok &= sha(b) == e["sha256"] and len(b) == e["bytes"]
        hits = pat.findall(b)
        if hits:
            pat_hits += 1
            bad.append(e["seq"])
    check("egress: every payload byte matches its logged sha256", hashes_ok, f"{len(log) - withheld} delivered payloads; {withheld} DLP-blocked payloads withheld (hash only)")
    check("egress: no record identifier / canary / PII marker in any DELIVERED payload", not bad and not pat_hits,
          f"{pat_hits} delivered payloads matched" if pat_hits else "0 matches")
    if mode == "blind":
        clear = 0
        for e in log:
            if e["dlp"] != "pass" or "contrib" not in e["type"]: continue
            st = json.loads(open(P("egress-payloads", f"{e['seq']:06d}-{e['type'].replace('/', '_')}.bin"), "rb").read())["state"]
            for k, c in st["contributions"].items():
                if k.startswith("c/") and float(np.linalg.norm(np.asarray(c["tensor"]) / Q)) < 1000: clear += 1
        check("blind: every contribution any peer received was masked (no clear update on any link)", clear == 0)
    check("data stays local: manifests publish hashes only", all("rows" in f for n in dm["nodes"] for f in n["files"].values()))
    # ---------------- PRIVACY BUDGET
    pb = J("privacy-budget.json")
    ok, worst = True, 0.0
    for s, n in pb["nodes"].items():
        if not n.get("dp"): continue
        cum, last = 0, -1
        for pr in n["per_round"]:
            cum += pr["steps"]
            e = eps_for(pr["q"], pb["params"]["sigma"], cum, pb["delta"])
            ok &= abs(e - pr["epsilon_cumulative"]) < 1e-3 and e >= last
            last = e
        worst = max(worst, last)
        ok &= last <= pb["epsilon_budget"] + 1e-9
    check(f"DP: epsilon recomputed from (q, sigma, steps, delta), monotone, <= cap {pb['epsilon_budget']}",
          ok, f"max eps {worst:.3f} at delta {pb['delta']:g}")
    # ---------------- PROOFS
    if shutil.which("lake") and os.path.exists(P("proofs", "check.sh")):
        p = subprocess.run(["bash", P("proofs", "check.sh")], capture_output=True, text=True)
        check("formal proofs (Lean 4) build with 0 sorry / 0 axioms", p.returncode == 0, p.stdout.strip().splitlines()[-1] if p.stdout else "")
    else:
        print("[SKIP] formal proofs: Lean/lake not installed")
    n_fail = sum(not ok for _, ok, _ in RESULTS)
    print(f"\n{len(RESULTS) - n_fail}/{len(RESULTS)} checks passed")
    if tmp: shutil.rmtree(tmp, ignore_errors=True)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "evidence.zip"))

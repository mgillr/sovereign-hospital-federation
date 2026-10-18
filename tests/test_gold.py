# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Gold-standard additions: jurisdictions, secure aggregation, budget halt, privacy attacks as proofs,
the standalone verifier (incl. tamper negatives) and the formal proofs. Red first: see docs/red-first.txt."""
import hashlib, json, os, shutil, subprocess, sys, zipfile, pathlib, pytest
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parents[1]


# --- sovereignty ----------------------------------------------------------------------
def test_every_node_carries_a_jurisdiction_label(fed_dp):
    labels = {s: n.data_manifest()["jurisdiction"] for s, n in fed_dp.nodes.items()}
    assert labels["CH"].startswith("CH nFADP")
    for s in ("DE", "FR", "AT", "IT"):
        assert "GDPR" in labels[s]

def test_egress_log_records_destination_bytes_type_hash_and_border(fed_dp):
    for e in fed_dp.egress.entries:
        assert {"seq", "src", "dst", "type", "bytes", "sha256", "crosses_border", "dlp"} <= set(e)
    assert any(e["crosses_border"] for e in fed_dp.egress.entries)

def test_every_byte_is_scanned(fed_dp):
    s = fed_dp.canary_scan()
    assert s["bytes_scanned"] == sum(e["bytes"] for e in fed_dp.egress.entries)

def test_ten_canaries_per_node_live_only_in_local_data(fed_dp):
    for n in fed_dp.nodes.values():
        assert len(n.canaries) == 10
        txt = open(os.path.join(n.data_dir, "patients_train.csv")).read()
        assert all(c in txt for c in n.canaries)

def test_leaky_node_bundle_withholds_blocked_bytes(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path / "f", seed=3, adversary="none", dp=True, leaky_node="AT")
    f.setup(); f.run_round()
    z = f.build_bundle(tmp_path / "e.zip")
    zf = zipfile.ZipFile(z); blob = b"".join(zf.read(n) for n in zf.namelist())
    for n in f.nodes.values():
        for c in n.canaries:
            assert c.encode() not in blob
    log = [json.loads(l) for l in zf.read("network-egress.log").splitlines()]
    assert any(e["dlp"] != "pass" and e["src"] == "AT" for e in log)
    p = _verify(z)
    assert p.returncode == 0, p.stdout[-3000:]


# --- secure aggregation ----------------------------------------------------------------
def test_pairwise_masks_cancel_exactly():
    from fed import secagg
    keys = {i: secagg.new_x25519() for i in range(1, 6)}
    sks = {i: k[0] for i, k in keys.items()}; pks = {i: k[1] for i, k in keys.items()}
    R = secagg.mask_range(5, 1 << 21)
    xs = {i: [int(v) for v in np.random.default_rng(i).integers(-5000, 5000, 50)] for i in sks}
    tot = np.zeros(50, dtype=object)
    for i in sks:
        m, _ = secagg.mask_vector(xs[i], i, sks[i], {j: p for j, p in pks.items() if j != i}, "01" * 32, R)
        assert max(abs(v) for v in m) < 2 ** 31
        tot = tot + np.asarray(m, dtype=object)
    assert list(tot) == list(np.sum([np.asarray(x, dtype=object) for x in xs.values()], axis=0))

def test_blind_mode_no_peer_ever_sees_a_clear_update(blind_dp):
    for r in blind_dp.rounds:
        for s, p in r["_private"].items():
            seen, clear = p["observed_by_peers"], p["delta_clear"]
            assert np.linalg.norm(seen) > 1000 * max(np.linalg.norm(clear), 1e-9)

def test_blind_receipt_is_exact_mean_of_hidden_updates(blind_dp):
    from fed.node import to_q16
    r = blind_dp.rounds[-1]
    adm = [s for s in r["_private"] if blind_dp.nodes[s].node_id in r["receipt"]["admitted"]]
    tot = np.sum([np.asarray(to_q16(r["_private"][s]["delta_clear"]), dtype=object) for s in adm], axis=0)
    assert [int(v) // len(adm) for v in tot] == list(r["receipt"]["aggregate"])
    assert set(r["verify_exit_codes"].values()) == {0}
    assert len(set(r["installed_hashes"].values())) == 1

def test_blind_out_of_bound_attacker_found_by_dispute_and_excluded(blind_poison_nodp):
    r1 = blind_poison_nodp.rounds[0]
    assert any("IT" in d["violator_sites"] for d in r1["disputes"])
    assert "IT" in blind_poison_nodp.quarantined(), "every honest peer quarantines IT after the dispute"
    for r in blind_poison_nodp.rounds:
        assert 5 not in r["receipt"]["admitted"]
        for d in r["disputes"]:
            for i, c in d["checks"].items():
                if int(i) != 5:
                    assert c["opening_matches_signed_commitment"] and c["masked_minus_mask_equals_opening"]

def test_blind_dropout_is_handled_by_remasking(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path, seed=3, mode="blind", adversary="none", dp=True, leaky_node="AT")
    f.setup(); r = f.run_round()
    assert "AT" in r["blocked_nodes"] and 4 not in r["receipt"]["admitted"]
    assert len(r["attempts"]) >= 2 and r["gate"]["passed"]
    assert set(r["verify_exit_codes"].values()) == {0}

def test_blind_in_bound_attacker_limitation_is_reported(blind_dp):
    rep = blind_dp.adversarial_report()
    assert any("within-norm" in l or "in-bound" in l for l in rep["honest_limits"])


# --- DP budget -------------------------------------------------------------------------
def test_budget_cap_halts_training(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path, seed=4, adversary="none", dp=True, eps_cap=1.0)
    f.setup(); f.run_rounds(10)
    assert f.halted and len(f.rounds) < 10
    pb = f.privacy_budget()
    assert all(n["epsilon_cumulative"] <= 1.0 for n in pb["nodes"].values() if n.get("dp"))
    n_before = len(f.rounds)
    f.run_rounds(1)
    assert len(f.rounds) == n_before          # halt is permanent


# --- privacy attacks as proofs ---------------------------------------------------------
def test_mia_auc_near_chance_in_every_mode(attacks):
    mi = attacks[0]["membership_inference"]
    for k, v in mi["federations"].items():
        assert 0.40 < v["shared_model"]["auc"] < 0.58, k

def test_worst_case_mia_protection_is_causal(attacks):
    w = attacks[0]["membership_inference"]["worst_case_tiny_batch"]
    assert w["clear"]["auc"] > 0.7
    assert w["dp"]["auc"] < w["clear"]["auc"] - 0.1
    assert w["masked"]["auc"] < 0.6

def test_gradient_inversion_succeeds_unprotected_fails_protected(attacks):
    g = attacks[0]["gradient_inversion"]
    assert g["worst_case_single_record_clear"]["success"] is True
    assert g["worst_case_single_record_dp"]["success"] is False
    assert g["worst_case_single_record_masked"]["success"] is False
    assert g["intercepted_round1_update"]["success"] is False

def test_canary_exposure_reported_honestly(attacks):
    e = attacks[0]["canary_exposure"]
    assert {"robust_nodp", "robust_dp", "blind_nodp", "blind_dp"} <= set(e)
    assert "interpretation" in e


# --- standalone verifier ----------------------------------------------------------------
def _verify(path):
    e = dict(os.environ)
    e.setdefault("ACFA_VERIFY_BIN", str(ROOT / ".bin" / "bin" / "acfa-verify"))
    return subprocess.run([sys.executable, str(ROOT / "verify_bundle.py"), str(path)], capture_output=True, text=True, env=e)

def test_verify_bundle_passes_on_genuine_bundles(bundle, blind_bundle):
    for b in (bundle, blind_bundle):
        p = _verify(b)
        assert p.returncode == 0, p.stdout[-3000:]
        assert "[FAIL]" not in p.stdout

def _flip(p):
    b = bytearray(p.read_bytes()); b[len(b) // 2] ^= 1; p.write_bytes(bytes(b))

def _npy(p):
    a = np.load(p); a[0] += 1e-3; np.save(p, a)

TAMPERS = {
    "receipt_byte": ("rounds/round-1/receipt.acfa", _flip),
    "aggregate_edit": ("rounds/round-2/aggregate.json", lambda p: p.write_text(p.read_text().replace("1", "2", 1))),
    "model_swap": ("models/model-r2.npy", _npy),
    "egress_log_edit": ("network-egress.log", lambda p: p.write_text(p.read_text().replace('"bytes": ', '"bytes": 1', 1))),
    "budget_edit": ("privacy-budget.json", lambda p: p.write_text(p.read_text().replace('"sigma": 2.0', '"sigma": 4.0'))),
    "manifest_edit": ("rounds/round-1/manifest.json", lambda p: p.write_text(p.read_text().replace('"lr"', '"lr_"', 1))),
    "cosig_edit": ("rounds/round-1/cosignatures.json", lambda p: p.write_text(p.read_text().replace('"state_root": "', '"state_root": "0', 1))),
    "pki_swap": ("consortium.pki", lambda p: p.write_text(p.read_text().replace(p.read_text().split()[-1], "00" * 32))),
}

@pytest.mark.parametrize("kind", sorted(TAMPERS))
def test_verify_bundle_detects_tampering(bundle, tmp_path, kind):
    name, fn = TAMPERS[kind]
    d = tmp_path / "x"; zipfile.ZipFile(bundle).extractall(d)
    before = (d / name).read_bytes(); fn(d / name)
    assert (d / name).read_bytes() != before, "tamper did not change the file"
    p = _verify(d)
    assert p.returncode == 1, (kind, p.stdout[-2000:])

def test_verify_bundle_detects_injected_canary(bundle, fed_dp, tmp_path):
    d = tmp_path / "x"; zipfile.ZipFile(bundle).extractall(d)
    log = [json.loads(l) for l in open(d / "network-egress.log")]
    e = log[-1]; fp = d / "egress-payloads" / f"{e['seq']:06d}-{e['type'].replace('/', '_')}.bin"
    b = fp.read_bytes() + fed_dp.nodes["CH"].canaries[0].encode()
    fp.write_bytes(b); e["bytes"] = len(b); e["sha256"] = hashlib.sha256(b).hexdigest()
    (d / "network-egress.log").write_text("".join(json.dumps(x) + "\n" for x in log))
    p = _verify(d)
    assert p.returncode == 1 and "[FAIL] egress: no record identifier" in p.stdout


# --- formal proofs ------------------------------------------------------------------------
def test_lean_proofs_build_without_sorry_or_axioms():
    if not shutil.which("lake"):
        pytest.skip("Lean toolchain not installed")
    p = subprocess.run(["bash", str(ROOT / "proofs" / "check.sh")], capture_output=True, text=True)
    assert p.returncode == 0 and "PROOFS: PASS" in p.stdout, p.stdout[-2000:] + p.stderr[-2000:]

def test_proof_check_rejects_a_sorry(tmp_path):
    if not shutil.which("lake"):
        pytest.skip("Lean toolchain not installed")
    d = tmp_path / "proofs"; shutil.copytree(ROOT / "proofs", d, ignore=shutil.ignore_patterns(".lake"))
    g = d / "Proofs" / "Gate.lean"; g.write_text(g.read_text() + "\ntheorem bad_claim : 1 = 2 := by sorry\n")
    p = subprocess.run(["bash", str(d / "check.sh")], capture_output=True, text=True, cwd=d)
    assert p.returncode != 0 and "FAIL" in p.stdout

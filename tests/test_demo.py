# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Core suite, written before the implementation (red first; see docs/red-first.txt). Each test names the claim it guards."""
import json, os, zipfile, pathlib, pytest
import numpy as np

HONEST = {"CH", "DE", "FR", "AT"}

# --- 1. data locality -------------------------------------------------------------
def test_each_node_has_its_own_isolated_data_dir(fed_dp):
    dirs = {s: pathlib.Path(n.data_dir).resolve() for s, n in fed_dp.nodes.items()}
    assert set(dirs) == {"CH", "DE", "FR", "AT", "IT"}
    for a in dirs:
        for b in dirs:
            if a != b:
                assert not str(dirs[a]).startswith(str(dirs[b]))
    assert not any(pathlib.Path(fed_dp.pub_dir).rglob("*.csv")), "published artefacts must hold no patient tables"
    assert not hasattr(fed_dp, "aggregator_dir"), "leaderless: there is no aggregator"

def test_only_egress_function_crosses_boundary_and_no_raw_rows_leave(fed_dp):
    kinds = set()
    for e in fed_dp.egress.entries:
        assert e["bytes"] > 0 and len(e["sha256"]) == 64 and e["dst"] and e["src"]
        assert e["src"] in fed_dp.nodes and e["dst"] in fed_dp.nodes and e["src"] != e["dst"]   # peer to peer only
        if e["type"] != "public-keys":
            assert e["type"].startswith("gossip/"); kinds |= set(e["type"][7:].split("+"))
    assert kinds <= {"contrib", "cosig", "eval"}

# --- 2. canary scan ---------------------------------------------------------------
def test_canary_scan_zero_hits_on_honest_run(fed_dp):
    scan = fed_dp.canary_scan()
    assert scan["payloads_scanned"] == len(fed_dp.egress.entries) > 0
    assert scan["hits"] == 0

def test_leaky_node_is_caught_and_blocked(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path, seed=3, adversary="none", dp=True, leaky_node="AT")
    f.setup(); r = f.run_round()
    scan = f.canary_scan()
    assert scan["hits"] > 0
    assert any(h["src"] == "AT" for h in scan["hit_list"])
    assert "AT" in r["blocked_nodes"]
    assert 4 not in r["receipt"]["admitted"]   # AT is node 4: its leaky payload never arrived

# --- 3. signatures, pinned base, attacker -----------------------------------------
def test_updates_are_signed_and_bound_to_base_hash_and_round(fed_dp):
    r = fed_dp.rounds[-1]
    m = r["manifest"]
    assert len(m["base_model_sha256"]) == 64 and m["round"] == r["round"]
    assert r["ctx"] == fed_dp.ctx_of(m)
    for u in r["updates"].values():
        assert u["ctx"] == r["ctx"] and u["round"] == r["round"] and len(u["sig"]) == 128

def test_forged_signature_is_not_admitted(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path, seed=5, adversary="forged-signature", dp=True)
    f.setup(); r = f.run_round()
    assert 5 not in r["receipt"]["admitted"]

def test_wrong_base_hash_is_refused_by_node(fed_dp):
    with pytest.raises(ValueError):
        fed_dp.nodes["CH"].check_base(np.zeros(738, np.float32), fed_dp.rounds[-1]["manifest"])

def test_poisoning_attacker_is_rejected_by_krum(fed_dp):
    for r in fed_dp.rounds:
        rec = r["receipt"]
        assert rec["rule"] == "krum" and rec["f"] == 1 and len(rec["admitted"]) == 5
        assert rec["population_bound_met"] is True
        assert 5 not in rec["selected"], "IT (node 5, poisoning) must not be selected"
        assert len(rec["selected"]) == len(rec["admitted"]) - rec["f"] - 2  # multi-Krum keeps m = n - f - 2: reported, not hidden

def test_equivocating_attacker_is_convicted(tmp_path):
    from fed.federation import Federation
    f = Federation(tmp_path, seed=9, adversary="equivocate", dp=True)
    f.setup(); r = f.run_round()
    assert 5 in r["receipt"]["convicted"]
    assert 5 not in r["receipt"]["selected"]

# --- 4. receipts, independent verification, identical hashes -----------------------
def test_independent_verifier_accepts_and_all_nodes_install_identical_hash(fed_dp):
    r = fed_dp.rounds[-1]
    v = fed_dp.verify_independent()
    assert v["exit_code"] == 0 and "VERIFIED" in v["stdout"]
    assert len(set(r["installed_hashes"].values())) == 1
    assert set(r["installed_hashes"]) == {"CH", "DE", "FR", "AT", "IT"}
    assert len(set(r["node_state_roots"].values())) == 1  # every node's own synced set gives the same root
    assert len(set(r["receipt_sha256_per_node"].values())) == 1  # each node derived the same receipt itself

@pytest.mark.parametrize("kind", ["receipt_byte", "model_swap", "wrong_key"])
def test_tampering_fails(fed_dp, kind):
    res = fed_dp.tamper(kind)
    assert res["detected"] is True, res

# --- 5. regression gate -------------------------------------------------------------
def test_model_improves_and_gate_passes(fed_dp):
    ev = fed_dp.evaluation()
    assert ev["common"]["after"] > ev["common"]["before"] + 0.05
    assert all(r["gate"]["passed"] or r["gate"]["rolled_back"] for r in fed_dp.rounds)

def test_regression_gate_blocks_a_bad_model(fed_dp):
    from fed.federation import regression_gate
    before = {"CH": .80, "DE": .80, "common": .80}
    after = {"CH": .70, "DE": .81, "common": .79}
    assert regression_gate(before, after, tol=0.02)["passed"] is False
    assert regression_gate(before, {"CH": .79, "DE": .81, "common": .80}, tol=0.02)["passed"] is True

# --- 6. differential privacy ----------------------------------------------------------
def test_privacy_budget_recorded_and_bounded(fed_dp):
    pb = fed_dp.privacy_budget()
    assert pb["mechanism"].startswith("DP-SGD")
    assert pb["delta"] <= 1e-5
    for site in HONEST:
        n = pb["nodes"][site]
        assert 0 < n["epsilon_cumulative"] <= pb["epsilon_budget"]
        assert len(n["per_round"]) == len(fed_dp.rounds)
        assert n["per_round"][-1]["epsilon_cumulative"] == pytest.approx(n["epsilon_cumulative"])

def test_rdp_accountant_monotone_and_sane():
    from fed.dp import epsilon_for
    e1 = epsilon_for(q=0.05, sigma=1.0, steps=100, delta=1e-5)
    e2 = epsilon_for(q=0.05, sigma=1.0, steps=200, delta=1e-5)
    e3 = epsilon_for(q=0.05, sigma=2.0, steps=200, delta=1e-5)
    assert 0 < e1 < e2 and e3 < e2

def test_rdp_accountant_matches_opacus():
    opacus = pytest.importorskip("opacus.accountants.analysis.rdp")
    from fed.dp import epsilon_for, ORDERS
    q, s, n, d = 0.04, 1.1, 300, 1e-5
    rdp = opacus.compute_rdp(q=q, noise_multiplier=s, steps=n, orders=ORDERS)
    eps_ref, _ = opacus.get_privacy_spent(orders=ORDERS, rdp=rdp, delta=d)
    assert epsilon_for(q, s, n, d) == pytest.approx(eps_ref, rel=1e-6)

def test_noised_update_fits_q16_16(fed_dp):
    for r in fed_dp.rounds:
        for u in r["updates"].values():
            assert max(abs(x) for x in u["tensor"]) < 2**31

def test_dp_membership_inference_near_chance(fed_dp, fed_nodp):
    mi = fed_dp.membership_inference(baseline=fed_nodp)
    assert mi["dp"]["shared_model"]["auc"] < 0.56
    assert mi["dp"]["single_update"]["auc"] < 0.56
    # Red-first assumption corrected: in this 738-param model the NO-DP federation is already at chance
    # (nothing to protect at this scale); causality of DP/masking is shown in test_worst_case_mia_protection_is_causal.
    assert "no_dp" in mi and abs(mi["no_dp"]["single_update"]["auc"] - 0.5) < 0.06
    assert mi["theoretical_max_advantage"] < 1

# --- 7. evidence bundle ----------------------------------------------------------------
def test_evidence_bundle_contains_every_file(fed_dp, bundle):
    z = bundle
    names = set(zipfile.ZipFile(z).namelist())
    for need in ["model-manifest.json", "local-data-manifest.json", "network-egress.log", "acfa-receipt.acfa",
                 "acfa-receipt.redacted.acfa", "consortium.pki", "verification.txt", "evaluation.json",
                 "adversarial-report.json", "privacy-budget.json", "membership-inference.json", "threat-model.md",
                 "privacy-attacks.json", "verify_bundle.py", "proofs/check.sh", "NOTICE"]:
        assert need in names, need
    blob = b"".join(zipfile.ZipFile(z).read(n) for n in names)
    for node in fed_dp.nodes.values():
        for c in node.canaries:
            assert c.encode() not in blob, "bundle must not contain raw canaries"

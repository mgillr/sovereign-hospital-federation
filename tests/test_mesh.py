# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Leaderless mesh: CRDT gossip convergence under adversarial delivery, quorum of co-signed roots,
equivocation and divergent-root detection, partitions, trust downgrades. Red first: see docs/red-first.txt."""
import pathlib, pytest
import numpy as np
from fed.federation import Federation, quorum, F_BYZ

HONEST = ["CH", "DE", "FR", "AT"]


def _fed(tmp, **kw):
    kw.setdefault("seed", 7); kw.setdefault("dp", True)
    f = Federation(tmp, **kw); f.setup(); return f


# --- no coordinator ------------------------------------------------------------------------
def test_no_coordinator_anywhere_in_code_or_ui():
    root = pathlib.Path(__file__).resolve().parents[1]
    for p in list((root / "fed").glob("*.py")) + [root / "app.py"]:
        t = p.read_text().lower()
        assert "aggregator_dir" not in t and "coordinator" not in t.replace("no coordinator", "").replace(
            "zero-coordinator", "").replace("without a coordinator", ""), p.name


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("dup_p", [0.0, 0.6])
def test_shuffled_duplicated_delayed_gossip_converges_to_identical_roots(tmp_path, seed, dup_p):
    f = _fed(tmp_path, seed=seed, adversary="none", mesh={"dup_p": dup_p, "delay": [1, 5]})
    r = f.run_round()
    assert not r.get("failed")
    assert len(set(r["node_state_roots"].values())) == 1
    assert len(set(r["receipt_sha256_per_node"].values())) == 1
    assert len(set(r["installed_hashes"].values())) == 1
    last = r["mesh"]["hash_trace"][-1]
    assert len({last[s] for s in f.nodes}) == 1, "every node's CRDT state hash converged"
    if dup_p:
        assert r["mesh"]["duplicates"] > 0


def test_identical_content_gives_identical_state_hash_whatever_the_order():
    from crdt_merge.model.crdt_state import CRDTMergeState
    rng = np.random.default_rng(0); items = [(f"k{i}", rng.normal(size=8)) for i in range(6)]
    hs = set()
    for perm in (range(6), reversed(range(6)), [3, 1, 5, 0, 2, 4, 3, 1]):
        st = CRDTMergeState("weight_average")
        for i in perm:
            other = CRDTMergeState("weight_average"); other.add(items[i][1], model_id=items[i][0]); st = st.merge(other)
        hs.add(st.state_hash)
    assert len(hs) == 1


def test_partition_that_heals_still_gives_identical_roots(tmp_path):
    f = _fed(tmp_path, adversary="none", mesh={"partition": {"groups": [["CH", "DE"], ["FR", "AT", "IT"]], "from": 0, "until": 8}})
    r = f.run_round()
    assert not r.get("failed")
    assert r["mesh"]["link_down_skips"] > 0
    assert len(set(r["node_state_roots"].values())) == 1 and len(set(r["installed_hashes"].values())) == 1


def test_partition_that_never_heals_fails_safe_without_install(tmp_path):
    f = _fed(tmp_path, adversary="none", mesh={"partition": {"groups": [["CH", "DE"], ["FR", "AT", "IT"]], "from": 0, "until": 10 ** 6}})
    w0 = {s: n.w.copy() for s, n in f.nodes.items()}
    r = f.run_round()
    assert r.get("failed") and r["gate"]["passed"] is False
    for s, n in f.nodes.items():
        assert np.array_equal(n.w, w0[s]), "no model installed without a quorum"


def test_quorum_intersection_parameters():
    for n in range(4, 12):
        q = quorum(n, F_BYZ)
        assert 2 * q > n + F_BYZ and q <= n - F_BYZ


def test_accepted_root_has_quorum_of_valid_cosignatures(fed_dp):
    for r in fed_dp.rounds:
        c = r["cosign"]
        assert len(c["accepted_signers"]) >= c["quorum"] == quorum(c["n_participants"], F_BYZ)
        roots = {x["state_root"] for x in r["cosigs"] if x["node_id"] and x["state_root"] == c["accepted_root"]}
        assert roots == {c["accepted_root"]}


# --- byzantine behaviour detected by the mesh -------------------------------------------------
def test_equivocation_is_detected_through_the_crdt_and_downgrades_trust(tmp_path):
    f = _fed(tmp_path, seed=9, adversary="equivocate")
    r = f.run_round()
    assert 5 in r["receipt"]["convicted"] and 5 not in r["receipt"]["selected"]
    assert len(set(r["node_state_roots"].values())) == 1
    t = f.trust_report()
    for s in HONEST:
        v = t["views"][s]["IT"]
        assert v["quarantined"] and v["dimensions_with_evidence"].get("consistency", 1) <= 0.1
    assert "IT" in t["quarantined"]
    r2 = f.run_round()
    assert 5 not in r2["receipt"]["admitted"], "quarantined peer excluded from later rounds"


def test_divergent_root_node_is_flagged_and_quorum_still_reached(tmp_path):
    f = _fed(tmp_path, adversary="divergent-root")
    r = f.run_round()
    assert not r.get("failed") and r["gate"]["passed"]
    assert "IT" in r["cosign"]["divergent_signers"]
    assert set(HONEST) <= set(r["cosign"]["accepted_signers"])
    assert any(e["site"] == "IT" for e in r["divergent_events"])
    assert f.trust_report()["views"]["CH"]["IT"]["dimensions_with_evidence"].get("consistency", 1) < 1


def test_forged_signature_downgrades_integrity_trust(tmp_path):
    f = _fed(tmp_path, seed=5, adversary="forged-signature")
    r = f.run_round()
    assert 5 not in r["receipt"]["admitted"]
    assert f.trust_report()["views"]["DE"]["IT"]["dimensions_with_evidence"].get("integrity", 1) <= 0.1


def test_trust_uses_only_the_crdt_merge_public_api():
    src = (pathlib.Path(__file__).resolve().parents[1] / "fed" / "federation.py").read_text()
    imports = [l.strip() for l in src.splitlines() if "crdt_merge" in l and "import" in l]
    assert "._evidence" not in src and "sc._" not in src, "no private TypedTrustScore attributes"
    assert imports and all(l.startswith(("from crdt_merge.e4.typed_trust import", "from crdt_merge.model.crdt_state import")) for l in imports), imports


# --- sovereignty in the mesh -------------------------------------------------------------------
def test_no_peer_receives_another_nodes_raw_data(fed_dp, tmp_path):
    scan = fed_dp.canary_scan()
    assert scan["raw_data_received_by_any_peer"] is False and scan["hits"] == 0
    assert len(scan["per_link"]) == 20  # 5 nodes, full mesh, both directions
    f = _fed(tmp_path, seed=3, adversary="none", leaky_node="AT"); f.run_round()
    s = f.canary_scan()
    assert s["hits"] > 0 and s["raw_data_received_by_any_peer"] is False
    assert all(h["src"] == "AT" for h in s["hit_list"])


def test_blind_mode_every_node_sums_the_masked_set_itself(blind_dp):
    for r in blind_dp.rounds:
        assert set(HONEST) - set(r["blocked_nodes"]) <= set(r["secagg"]["summed_by"])
        assert len(set(r["receipt_sha256_per_node"].values())) == 1


def test_gate_is_applied_by_every_node_identically(fed_dp):
    for r in fed_dp.rounds:
        assert r["gate_identical_on_all_honest_nodes"] is True


# --- robust mode honesty ------------------------------------------------------------------------
def test_selection_counts_are_reported_per_site(fed_dp):
    sc = fed_dp.selection_counts()
    assert set(sc) == set(fed_dp.nodes)
    assert sc["IT"]["selected"] == 0
    assert sum(v["selected"] for v in sc.values()) == sum(len(r["receipt"]["selected"]) for r in fed_dp.rounds if not r.get("failed"))
    assert fed_dp.evaluation()["selection_counts"] == sc


@pytest.mark.parametrize("adv", ["forged-signature", "equivocate", "poison"])
def test_every_honest_node_verifies_its_own_receipt_before_installing(tmp_path, adv):
    f = _fed(tmp_path, adversary=adv)
    r = f.run_round()
    assert r["gate"]["passed"]
    assert set(r["verify_exit_codes"].values()) == {0}
    assert set(HONEST) <= set(r["installed_on"])
    for s in HONEST:
        assert r["installed_hashes"][s] == r["candidate_sha256"] == r["model_sha256_after"]


def test_a_stale_close_is_not_punished_but_a_lying_root_is(tmp_path):
    f = _fed(tmp_path / "a", adversary="equivocate"); f.run_rounds(2)
    assert all(e["target"] == "IT" for e in f.evidence)
    g = _fed(tmp_path / "b", adversary="divergent-root"); g.run_rounds(2)
    assert all(r["cosign"]["divergent_signers"] == ["IT"] for r in g.rounds)
    assert "IT" in g.quarantined() and all(e["target"] == "IT" for e in g.evidence)

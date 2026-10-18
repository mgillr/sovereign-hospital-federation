# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Evidence bundle: every file a third party needs to re-check the run offline (verify_bundle.py)."""
import io, json, os, shutil, zipfile
import numpy as np
from . import acfa, model
from .federation import ALLOWED, DELTA, GATE_TOL, privacy_attacks, canon, quorum

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _j(obj):
    return json.dumps(obj, indent=1, sort_keys=True, default=lambda o: o.tolist() if hasattr(o, "tolist") else str(o))


def build_bundle(fed, path, attacks=None, shadows=None):
    if attacks is None:
        attacks, shadows = privacy_attacks(fed, shadows)
    for k in ("receipt_byte", "model_swap", "wrong_key"):
        if k not in fed.tamper_results: fed.tamper(k)
    files = {}
    rounds_meta = []
    mesh = {"links": fed.link_stats, "rounds": []}
    for r in fed.rounds:
        if r.get("failed"):
            continue
        rd = f"rounds/round-{r['round']}/"
        files[rd + "receipt.acfa"] = open(r["receipt_path"], "rb").read()
        files[rd + "receipt.redacted.acfa"] = open(r["redacted_path"], "rb").read()
        files[rd + "manifest.json"] = _j(r["manifest"])
        files[rd + "aggregate.json"] = _j({"aggregate_q16": r["receipt"]["aggregate"]})
        files[rd + "contributions.json"] = _j(fed._contribs_of_dir(r))
        files[rd + "cosignatures.json"] = _j([{k: v for k, v in c.items() if k != "_key"} for c in r["cosigs"]])
        files[rd + "eval-reports.json"] = _j([e for e in fed.eval_reports if e["acfa_round"] == r["acfa_round"]])
        files[rd + "node-verification.txt"] = "\n".join(
            f"== {s} (verifies the receipt it derived itself): exit {v['exit_code']}\n$ {' '.join(v['argv'])}\n{v['stdout']}{v['stderr']}"
            for s, v in r["verify_runs"].items())
        files[f"models/model-r{r['round']}.npy"] = open(os.path.join(fed.pub_dir, f"model-r{r['round']}.npy"), "rb").read()
        mesh["rounds"].append({"round": r["round"], **r["mesh"]})
        rounds_meta.append({k: r[k] for k in ("round", "mode", "ctx", "acfa_round", "base_model_sha256", "candidate_sha256",
                                               "model_sha256_after", "models_after", "installed_hashes", "node_state_roots",
                                               "receipt_sha256_per_node", "attempts", "blocked_nodes", "round_seconds",
                                               "ctx_identical_on_all_nodes", "gate_identical_on_all_honest_nodes",
                                               "divergent_events")} |
                           {"gate": r["gate"], "receipt": {k: v for k, v in r["receipt"].items()
                                                           if k not in ("aggregate", "receipt_path", "redacted_path")},
                            "cosign": r["cosign"], "disputes": r["disputes"], "secagg": r["secagg"]})
    files["models/base-model-r0.npy"] = open(os.path.join(fed.pub_dir, "base-model-r0.npy"), "rb").read()
    files["mesh.json"] = _j(mesh)
    files["peer-trust.json"] = _j(fed.trust_report())
    last = next(r for r in reversed(fed.rounds) if not r.get("failed"))
    files["acfa-receipt.acfa"] = open(last["receipt_path"], "rb").read()
    files["acfa-receipt.redacted.acfa"] = open(last["redacted_path"], "rb").read()
    files["consortium.pki"] = fed.pki_text
    files["model-manifest.json"] = _j({
        "schema": "shf-model-manifest/v2-leaderless", "mode": fed.mode, "acfa_rs_rev": acfa.ACFA_REV,
        "topology": "leaderless peer-to-peer mesh; every node aggregates locally; no coordinator",
        "model": {"arch": "MLP 20-32-2", "n_params": model.N_PARAMS, "hash": "sha256 of float32-LE weights"},
        "base_model_r0_sha256": model.sha256(fed.w0), "final_model_sha256": model.sha256(fed.w),
        "allowed_message_types": sorted(ALLOWED[fed.mode]),
        "site_node_ids": {s: n.node_id for s, n in fed.nodes.items()}, "gate_tol": GATE_TOL, "dp_delta": DELTA,
        "eps_cap": fed.eps_cap, "rounds": rounds_meta, "halted": fed.halted})
    files["local-data-manifest.json"] = _j({"note": "raw tables never leave their node; only these hashes are published",
                                           "nodes": [n.data_manifest() for n in fed.nodes.values()]})
    files["network-egress.log"] = open(fed.egress.log_path, "rb").read()
    for e, p in zip(fed.egress.entries, fed.egress.payloads):
        if e["dlp"] == "pass":       # BLOCKED payloads contain local data: only their hash is published
            files[f"egress-payloads/{e['seq']:06d}-{e['type'].replace('/', '_')}.bin"] = p
    scan = fed.canary_scan()
    indep = fed.verify_independent()
    files["verification.txt"] = (
        f"OFFLINE VERIFIER (a third party, not a network participant; inputs: receipt, consortium.pki, manifest-derived ctx, a node's state root)\n"
        f"$ {' '.join(indep['argv'])}\nexit {indep['exit_code']}\n{indep['stdout']}{indep['stderr']}\n\n"
        f"CANARY SCAN: {scan['payloads_scanned']} payloads, {scan['bytes_scanned']} bytes, {scan['hits']} hits "
        f"({scan['hits_delivered']} delivered)\n\nTAMPER TESTS\n" +
        "\n".join(f"- {k}: detected={v['detected']} :: {v['what']}" for k, v in fed.tamper_results.items()) +
        "\n\nPER-NODE VERIFICATION (last round)\n" + files[f"rounds/round-{last['round']}/node-verification.txt"])
    ev = fed.evaluation()
    ev["no_dp_comparison"] = {k: v.evaluation()["after"] for k, v in (shadows or {}).items() if k.endswith("nodp")}
    files["evaluation.json"] = _j(ev)
    files["adversarial-report.json"] = _j(fed.adversarial_report() | {"canary_scan": {k: v for k, v in scan.items()}})
    files["privacy-budget.json"] = _j(fed.privacy_budget())
    files["membership-inference.json"] = _j(attacks["membership_inference"])
    files["privacy-attacks.json"] = _j({"gradient_inversion": attacks["gradient_inversion"],
                                        "canary_exposure": attacks["canary_exposure"], "accuracy": attacks["accuracy"]})
    tm = open(os.path.join(HERE, "threat-model.md")).read()
    eps = max((n.epsilon(DELTA) or 0) for n in fed.nodes.values())
    files["threat-model.md"] = tm.replace("{{EPS}}", f"{eps:.3f}").replace("{{DELTA}}", f"{DELTA:g}").replace(
        "{{CAP}}", f"{fed.eps_cap:g}")
    files["verify_bundle.py"] = open(os.path.join(HERE, "verify_bundle.py")).read()
    for root, _, fs in os.walk(os.path.join(HERE, "proofs")):
        if ".lake" in root: continue
        for f in fs:
            p = os.path.join(root, f); files[os.path.relpath(p, HERE)] = open(p, "rb").read()
    files["NOTICE"] = open(os.path.join(HERE, "NOTICE")).read() if os.path.exists(os.path.join(HERE, "NOTICE")) else ""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(files):
            v = files[k]; z.writestr(k, v if isinstance(v, (bytes, bytearray)) else v.encode())
    return str(path)

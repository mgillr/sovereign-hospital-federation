# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Reproduce the numbers quoted in README.md (writes docs/measurements.json). Leaderless mesh."""
import json, os, statistics, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fed.federation import Federation, privacy_attacks

ROUNDS = 7


def run(mode, adv, dp, rounds=ROUNDS, **kw):
    f = Federation(tempfile.mkdtemp(), seed=7, mode=mode, adversary=adv, dp=dp, **kw); f.setup(); f.run_rounds(rounds)
    return f


def summarise(f):
    ok = [r for r in f.rounds if not r.get("failed")]
    ev = f.evaluation() if ok else None; pb = f.privacy_budget()
    return {
        "rounds": len(f.rounds), "failed_rounds": [r["round"] for r in f.rounds if r.get("failed")],
        "round_seconds_median": round(statistics.median(r["round_seconds"] for r in f.rounds), 3),
        "ticks_median": statistics.median(r["mesh"]["ticks"] for r in ok) if ok else None,
        "crdt_converged_tick_median": statistics.median(r["mesh"]["converged_tick"] for r in ok if r["mesh"]["converged_tick"] is not None) if ok else None,
        "gossip_sends_per_round_median": statistics.median(r["mesh"]["sent"] for r in ok) if ok else None,
        "duplicates_per_round_median": statistics.median(r["mesh"]["duplicates"] for r in ok) if ok else None,
        "acc_common_before": ev["common"]["before"] if ev else None, "acc_common_after": ev["common"]["after"] if ev else None,
        "gate_passed": [r["gate"]["passed"] for r in f.rounds],
        "gate_failures": {r["round"]: r["gate"]["failing"] for r in f.rounds if not r["gate"]["passed"]},
        "selected": [r["receipt"]["selected_sites"] for r in ok],
        "selection_counts": f.selection_counts(),
        "quorum_signers": [len(r["cosign"]["accepted_signers"]) for r in ok],
        "quorum_Q": [r["cosign"]["quorum"] for r in ok],
        "divergent_signers": [r["cosign"]["divergent_signers"] for r in ok],
        "dispute_violators": [[d["violator_sites"] for d in r["disputes"]] for r in ok],
        "quarantined": f.quarantined(),
        "identical_state_roots_all_rounds": all(len(set(r["node_state_roots"].values())) == 1 for r in ok),
        "identical_receipts_all_rounds": all(len(set(r["receipt_sha256_per_node"].values())) == 1 for r in ok),
        "identical_installed_hash_all_rounds": all(len(set(r["installed_hashes"].values())) == 1 for r in ok),
        "verify_exit_codes": sorted({c for r in ok for c in r["verify_exit_codes"].values()}),
        "final_model_sha256": ok[-1]["model_sha256_after"] if ok else None,
        "epsilon_max": max((n.get("epsilon_cumulative", 0) for n in pb["nodes"].values()), default=None) if f.dp_cfg else None,
        "epsilon_per_node": {s: n.get("epsilon_cumulative") for s, n in pb["nodes"].items()} if f.dp_cfg else None}


out = {}
for mode in ("robust", "blind"):
    for dp in (False, True):
        for adv in ("none", "poison"):
            k = f"{mode}_{'dp' if dp else 'nodp'}_{adv}"
            out[k] = summarise(run(mode, adv, dp)); print(k, out[k]["acc_common_after"], out[k]["gate_passed"], flush=True)
k = "robust_nodp_poison_NO_lr_decay"
out[k] = summarise(run("robust", "poison", False, lr_decay=False)); print(k, out[k]["gate_passed"], flush=True)
for adv in ("equivocate", "divergent-root", "forged-signature", "sign-flip-in-bound"):
    for mode in ("robust", "blind"):
        k = f"{mode}_dp_{adv}"; out[k] = summarise(run(mode, adv, True, rounds=3)); print(k, out[k]["gate_passed"], flush=True)
heal = {"groups": [["CH", "DE"], ["FR", "AT", "IT"]], "from": 0, "until": 8}
out["partition_heals"] = summarise(run("robust", "none", True, rounds=2, mesh={"partition": heal}))
out["partition_never_heals"] = summarise(run("robust", "none", True, rounds=1, mesh={"partition": dict(heal, until=10 ** 6)}))
out["heavy_duplication_delay"] = summarise(run("robust", "poison", True, rounds=3, mesh={"dup_p": 0.6, "delay": [1, 5]}))
f = run("robust", "poison", True, rounds=3)
t = time.time(); a, _ = privacy_attacks(f, None); out["privacy_attacks_seconds"] = round(time.time() - t, 2)
mi = a["membership_inference"]
out["mia"] = {k: {"shared": v["shared_model"]["auc"], "update": v["single_update"]["auc"]} for k, v in mi["federations"].items()}
out["mia_worst_case"] = {k: mi["worst_case_tiny_batch"][k]["auc"] for k in ("clear", "dp", "masked")}
out["mia_theoretical_max_advantage"] = float(mi["theoretical_max_advantage_at_epsilon"])
out["accuracy_attack_federations"] = a["accuracy"]
out["inversion"] = {k: {"success": v["success"], "rmse_nearest": v["nearest_private_record_rmse"]}
                    for k, v in a["gradient_inversion"].items() if isinstance(v, dict) and "success" in v}
out["exposure"] = {k: {"mean": v["mean"], "max": v["max"]} for k, v in a["canary_exposure"].items() if isinstance(v, dict)}
out["tamper"] = {k: f.tamper(k)["detected"] for k in ("receipt_byte", "model_swap", "wrong_key")}
fl = run("robust", "none", True, rounds=1, leaky_node="AT"); sc = fl.canary_scan()
out["leaky_node"] = {"blocked": fl.rounds[-1]["blocked_nodes"], "scan_hits": sc["hits"], "delivered_hits": sc["hits_delivered"],
                     "raw_data_received_by_any_peer": sc["raw_data_received_by_any_peer"], "round_failed": fl.rounds[-1].get("failed")}
fh = run("robust", "none", True, rounds=30, eps_cap=3.0)
out["budget_halt"] = {"rounds_run": len(fh.rounds), "halted": fh.halted}
json.dump(out, open(os.path.join(os.path.dirname(__file__), "..", "docs", "measurements.json"), "w"), indent=1, default=str)
print(json.dumps({k: v for k, v in out.items() if not k.startswith(("robust", "blind"))}, indent=1, default=str))

# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Sovereign Hospital Federation: Gradio UI for the leaderless mesh. Everything shown is produced by fed/ at runtime."""
import os, subprocess, sys, tempfile
import gradio as gr
import plotly.graph_objects as go

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fed import data
from fed.federation import Federation, SITES, ADVERSARIES, ROBUST_MODE_EXPLANATION, privacy_attacks

GITHUB = "https://github.com/mgillr/sovereign-hospital-federation"
PARTITIONS = {"none": None,
              "CH+DE cut off for 8 ticks, then heals": {"groups": [["CH", "DE"], ["FR", "AT", "IT"]], "from": 0, "until": 8},
              "CH+DE cut off, never heals": {"groups": [["CH", "DE"], ["FR", "AT", "IT"]], "from": 0, "until": 10 ** 6}}


def new_fed(mode, adversary, dp, leaky, partition):
    f = Federation(tempfile.mkdtemp(prefix="shf-"), seed=7, mode=mode, adversary=adversary, dp=dp,
                   leaky_node=None if leaky == "none" else leaky, mesh={"partition": PARTITIONS[partition]})
    f.setup(); f._ui_egress_start = [0]
    return f


def _status(f, r, s):
    if r is None: return "no round yet", "#4a6"
    rec = r.get("receipt") or {}
    if s in f.quarantined(): return "QUARANTINED by every honest peer (trust evidence)", "#c22"
    if s in rec.get("convicted_sites", []): return "CONVICTED (equivocation seen in the CRDT)", "#c22"
    if s in r.get("blocked_nodes", []): return "BLOCKED by its own DLP gateway", "#c22"
    if s in (r.get("cosign") or {}).get("divergent_signers", []): return "DIVERGENT root (flagged, outvoted by quorum)", "#c60"
    if s in rec.get("selected_sites", []): return "selected by the ACFA rule", "#2a7"
    return "admitted, not selected", "#d90"


def _round_entries(f):
    if not f or not f.rounds: return []
    return f.egress.entries[f._ui_egress_start[-1]:]


def mesh_map(f):
    """Full mesh of direct hospital-to-hospital links; animation frames replay the last round's gossip per tick."""
    fig = go.Figure()
    r = f.rounds[-1] if f and f.rounds else None
    part = (r or {}).get("mesh", {}).get("partition") if r else None
    ents = _round_entries(f)
    per_link = {}
    for e in ents:
        a, b = sorted((e["src"], e["dst"])); per_link[(a, b)] = per_link.get((a, b), 0) + 1
    side = {}
    if part:
        for gi, g in enumerate(part["groups"]):
            for s in g: side[s] = gi
    pairs = [(a, b) for i, a in enumerate(SITES) for b in SITES[i + 1:]]
    for a, b in pairs:
        (la, oa), (lb, ob) = data.COORDS[a], data.COORDS[b]
        cut = part and side.get(a) != side.get(b)
        fig.add_trace(go.Scattergeo(lat=[la, lb], lon=[oa, ob], mode="lines", hoverinfo="text", showlegend=False,
                                    hovertext=f"{a}<->{b}: {per_link.get((a, b), 0)} messages this round" + (" (partitioned for a while)" if cut else ""),
                                    line=dict(width=1 + min(per_link.get((a, b), 0), 30) / 6, color="#c33" if cut else "#7a8",
                                              dash="dash" if cut else "solid")))
    for s in SITES:
        lat, lon = data.COORDS[s]; st, col = _status(f, r, s)
        adv = " (adversary)" if f and f.nodes[s].mode != "honest" else ""
        fig.add_trace(go.Scattergeo(lat=[lat], lon=[lon], mode="markers+text", text=[f"{s}{adv}"], textposition="top center",
                                    marker=dict(size=18, color=col, line=dict(width=1)), hoverinfo="text", showlegend=False,
                                    hovertext=f"{s}: {data.JURISDICTION[s]}<br>patient data stays here<br>aggregates locally<br>{st}"))
    nbase = len(fig.data)
    fig.add_trace(go.Scattergeo(lat=[], lon=[], mode="markers", marker=dict(size=9, color="#159", symbol="circle"),
                                hoverinfo="skip", showlegend=False))
    ticks = sorted({e.get("tick") for e in ents if e.get("tick") is not None})
    frames = []
    for t in ticks:
        lat, lon = [], []
        for e in ents:
            if e.get("tick") != t: continue
            (la, oa), (lb, ob) = data.COORDS[e["src"]], data.COORDS[e["dst"]]
            lat.append(la + 0.55 * (lb - la)); lon.append(oa + 0.55 * (ob - oa))
        frames.append(go.Frame(name=str(t), data=[go.Scattergeo(lat=lat, lon=lon)], traces=[nbase]))
    fig.frames = frames
    if frames:
        fig.update_layout(updatemenus=[dict(type="buttons", x=0.02, y=0.02, buttons=[dict(
            label="▶ replay gossip", method="animate",
            args=[None, dict(frame=dict(duration=450, redraw=True), fromcurrent=False)])])],
            sliders=[dict(steps=[dict(label=f.name, method="animate", args=[[f.name], dict(mode="immediate")]) for f in frames],
                          currentvalue=dict(prefix="tick "), x=0.2, len=0.75, y=0.02)])
    fig.update_geos(scope="europe", showcountries=True, countrycolor="#999", lataxis_range=[41, 56],
                    lonaxis_range=[-3, 19], showland=True, landcolor="#f4f4f0")
    fig.update_layout(height=460, margin=dict(l=0, r=0, t=10, b=0))
    return fig


def convergence_chart(f):
    """Each node's CRDT state hash per tick: colours merge into one when the gossip has converged."""
    fig = go.Figure()
    if not f or not f.rounds:
        fig.update_layout(height=260, title="CRDT state-hash convergence (run a round)"); return fig
    r = f.rounds[-1]; tr = r["mesh"]["hash_trace"]
    ids = {}
    for row in tr:
        for s in SITES: ids.setdefault(row[s], len(ids))
    z = [[ids[row[s]] for row in tr] for s in SITES]
    txt = [[row[s] for row in tr] for s in SITES]
    fig.add_trace(go.Heatmap(z=z, x=[row["rel"] for row in tr], y=SITES, text=txt, hovertemplate="%{y} tick %{x}: %{text}<extra></extra>",
                             colorscale="Turbo", showscale=False))
    ct = r["mesh"].get("converged_tick")
    fig.update_layout(height=260, margin=dict(t=40, l=40, r=10, b=30), xaxis_title="logical tick (this round)",
                      title=f"CRDT state hash per node per tick: one colour per column = converged (converged at tick {ct})")
    return fig


def tables(f):
    ents = _round_entries(f)
    eg = [[e["seq"], e.get("tick", ""), e["link"], e["type"], e.get("entries", ""), e["bytes"], e["sha256"][:16],
           "yes" if e["crosses_border"] else "no", e["dlp"]] for e in ents[-80:]][::-1]
    cos, hashes, trust, sel, links = [], [], [], [], []
    if f and f.rounds:
        r = f.rounds[-1]
        acc = (r.get("cosign") or {}).get("accepted_root"); dv = set((r.get("cosign") or {}).get("divergent_signers", []))
        ids = {n.node_id: s for s, n in f.nodes.items()}
        for c in r.get("cosigs", []):
            cos.append([ids.get(c["node_id"], c["node_id"]), c["close_attempt"], c["state_root"][:20], c["output_root"][:16],
                        c["receipt_sha256"][:16], len(c["leaves"]), "accepted quorum root" if c["state_root"] == acc else
                        "DIVERGENT (root does not follow from its leaves)" if ids.get(c["node_id"]) in dv else "stale (closed early on a partial set; recomputed)"])
        for s in SITES:
            hashes.append([s, (r.get("installed_hashes") or {}).get(s, "not installed"), (r.get("node_state_roots") or {}).get(s, "")[:24],
                           (r.get("receipt_sha256_per_node") or {}).get(s, "")[:16], (r.get("verify_exit_codes") or {}).get(s, "")])
        tr = f.trust_report()
        for tgt in SITES:
            obs = [v[tgt] for o, v in tr["views"].items() if o != tgt and f.nodes[o].mode == "honest"]
            if not obs: continue
            lo = min(obs, key=lambda v: v["overall"])
            trust.append([tgt, round(lo["overall"], 3), ", ".join(f"{d}={x}" for d, x in sorted(lo["dimensions_with_evidence"].items())) or "no evidence (probation 0.5)",
                          "yes" if tgt in tr["quarantined"] else "no"])
        for s, v in f.selection_counts().items():
            sel.append([s, v["admitted"], v["selected"], f"{(v['selected'] / v['admitted'] if v['admitted'] else 0):.0%}"])
        for l, v in sorted(f.canary_scan()["per_link"].items()):
            links.append([l, v["messages"], v["bytes"], v["hits"], v["delivered_hits"]])
    return eg, cos, hashes, trust, sel, links


def summary(f):
    if not f or not f.rounds:
        return "Press **Run round**. Every hospital trains locally, gossips signed contributions to its peers, aggregates the converged set itself and co-signs the result. There is no server."
    r = f.rounds[-1]; pb = f.privacy_budget()
    if r.get("failed"):
        return f"### Round {r['round']}: **FAILED SAFE**\n- {r['failed']}\n- every node keeps its previous model; nothing was installed"
    ev = f.evaluation(); c = r["cosign"]; m = r["mesh"]
    eps = max((n.get("epsilon_cumulative", 0) for n in pb["nodes"].values()), default=0)
    same = len(set(r["installed_hashes"].values())) == 1
    rec = r["receipt"]
    lines = [f"### Round {r['round']} ({'Robust mode: every node runs ACFA multi-Krum locally; peers see DP-noised updates' if f.mode == 'robust' else 'Blind mode: every node sums the masked set itself; norm-bound disputes'})",
             f"- gossip: {m['sent']} sends, {m['delivered']} delivered, {m['duplicates']} duplicates, delays up to {m['max_delay']} ticks"
             + (f", {m['link_down_skips']} sends lost to the partition" if m.get("link_down_skips") else "") + f"; CRDT converged at tick **{m['converged_tick']}**",
             f"- co-signed root: **{len(c['accepted_signers'])} of {c['n_participants']}** signers (quorum Q = {c['quorum']}, 2Q > n + f) "
             f"`{c['accepted_root'][:16]}…`" + (f"; divergent: **{', '.join(c['divergent_signers'])}**" if c["divergent_signers"] else "")
             + (f"; closed early then recomputed: {', '.join(c['stale_signers'])}" if c.get("stale_signers") else ""),
             f"- kept **{', '.join(rec['selected_sites'])}**; dropped **{', '.join(rec['dropped_sites']) or 'none'}**; convicted **{', '.join(rec['convicted_sites']) or 'none'}**; quarantined **{', '.join(f.quarantined()) or 'none'}**",
             f"- attempts: {len(r['attempts'])}; disputes: " + (", ".join(f"violators {d['violator_sites']}" for d in r["disputes"]) or "none"),
             f"- every node derived the same receipt: **{len(set(r['receipt_sha256_per_node'].values())) == 1}**; verified on every node: **{set(r['verify_exit_codes'].values()) == {0}}**; identical model on all nodes: **{same}** (`{r['model_sha256_after'][:16]}…`)",
             f"- regression gate (applied by each node to the gossiped eval reports): **{'PASS (installed)' if r['gate']['passed'] else 'FAIL (rolled back)'}**",
             f"- common-benchmark accuracy: {ev['common']['before']:.3f} → **{ev['common']['after']:.3f}**",
             "- privacy: " + (f"ε = **{eps:.3f}** (δ = {pb['delta']:g}), cap {pb['epsilon_budget']}" if f.dp_cfg else "**DP off**"),
             f"- round time: **{r['round_seconds']:.2f} s** (simulated mesh on one machine)"]
    if f.halted:
        lines.append(f"- ⛔ **training halted**: {f.halted['reason']} (projected {f.halted['projected']})")
    return "\n".join(lines)


def outputs(f, msg=""):
    eg, cos, hashes, trust, sel, links = tables(f)
    return (f, mesh_map(f), convergence_chart(f), summary(f) + ("\n\n" + msg if msg else ""), eg, cos, hashes, trust, sel, links)


def do_reset(mode, adversary, dp, leaky, partition):
    return outputs(new_fed(mode, adversary, dp, leaky, partition), "New federation: 5 peers, fresh throwaway keys, fresh synthetic data.")


def do_round(f, mode, adversary, dp, leaky, partition):
    if f is None or getattr(f, "_ui_cfg", None) != (mode, adversary, dp, leaky, partition):
        f = new_fed(mode, adversary, dp, leaky, partition); f._ui_cfg = (mode, adversary, dp, leaky, partition)
    if f.halted:
        return outputs(f, "Training is halted by the privacy budget.")
    if f.rounds and f.rounds[-1].get("failed"):
        return outputs(f, "The last round failed safe (no quorum). Reset the federation to continue.")
    f._ui_egress_start.append(len(f.egress.entries))
    f.run_round()
    return outputs(f)


def do_tamper(f, kind):
    if f is None or not any(not r.get("failed") for r in f.rounds):
        return "Run a successful round first."
    t = f.tamper(kind)
    how = f" (acfa-verify exit {t['exit_code']})" if t.get("exit_code") is not None else " (installed-model hash check)"
    return f"**{kind}** → detected: **{t['detected']}**{how}\n\n{t['what']}\n\n```\n{t.get('verifier_output', '')[:1500]}\n```"


def do_verify(f):
    if f is None or not any(not r.get("failed") for r in f.rounds):
        return "Run a successful round first.", None
    path = os.path.join(tempfile.mkdtemp(), "evidence.zip")
    f.build_bundle(path)
    p = subprocess.run([sys.executable, os.path.join(HERE, "verify_bundle.py"), path], capture_output=True, text=True)
    head = "✅ ALL CHECKS PASSED" if p.returncode == 0 else f"❌ verify_bundle.py exit {p.returncode}"
    return f"**{head}**  (standalone `verify_bundle.py` run on the downloaded bundle)\n```\n{p.stdout[-6000:]}{p.stderr[-1500:]}\n```", path


def do_attacks(f):
    if f is None or not f.rounds:
        return "Run a round first.", None
    a, _ = privacy_attacks(f, None)
    mi = a["membership_inference"]; gi = a["gradient_inversion"]; ce = a["canary_exposure"]
    rows = "\n".join(f"| {k} | {v['shared_model']['auc']:.3f} | {v['single_update']['auc']:.3f} | {a['accuracy'][k]:.3f} |"
                     for k, v in mi["federations"].items())
    w = mi["worst_case_tiny_batch"]
    md = (f"#### Membership inference by a peer (AUC 0.5 = coin flip)\n| federation | shared model | gossiped update | accuracy |\n|---|---|---|---|\n{rows}\n\n"
          f"**Worst case** (one SGD step on 4 records, 100 trials): clear **{w['clear']['auc']:.2f}** → DP **{w['dp']['auc']:.2f}** → masked **{w['masked']['auc']:.2f}**\n\n"
          f"#### Gradient inversion (a curious peer reconstructs a record from a gossiped update)\n"
          + "\n".join(f"- {k}: success **{v['success']}** (RMSE to nearest private record {v['nearest_private_record_rmse']}, threshold {v['success_threshold_rmse']})"
                      for k, v in gi.items() if isinstance(v, dict) and "success" in v) +
          f"\n\n#### Canary exposure (bits; ~1–2 = chance, {ce['robust_dp']['max_possible']} = fully memorised)\n"
          + "\n".join(f"- {k}: mean {v['mean']}, max {v['max']}" for k, v in ce.items() if isinstance(v, dict)) +
          f"\n\n_{ce['interpretation']}_")
    fig = go.Figure(); feats = gi["features"]
    for k, name in (("worst_case_single_record_clear", "attacker (no protection)"), ("worst_case_single_record_dp", "attacker (DP)"),
                    ("worst_case_single_record_masked", "attacker (masked)")):
        fig.add_trace(go.Bar(name=name, x=feats, y=gi[k]["reconstruction_std_units"]))
    fig.add_trace(go.Scatter(name="real record", x=feats, y=gi["worst_case_single_record_clear"]["true_record_std_units"],
                             mode="markers", marker=dict(size=10, color="black")))
    fig.update_layout(barmode="group", height=380, margin=dict(t=30), title="Gradient inversion: attacker output vs the real record (std units)")
    return md, fig


def do_proofs():
    chk = os.path.join(HERE, "proofs", "check.sh"); cached = os.path.join(HERE, "proofs", "BUILD_LOG.txt")
    try:
        p = subprocess.run(["bash", chk], capture_output=True, text=True, timeout=600)
        return f"```\n{p.stdout[-5000:]}{p.stderr[-1000:]}\n```"
    except Exception as e:
        log = open(cached).read() if os.path.exists(cached) else ""
        return f"Lean not runnable here ({e}). Build log from image build:\n```\n{log[-5000:]}\n```"


def read(p):
    fp = os.path.join(HERE, p)
    return open(fp).read() if os.path.exists(fp) else ""


with gr.Blocks(title="Sovereign Hospital Federation") as demo:
    gr.Markdown(f"""# Sovereign Hospital Federation: a leaderless mesh
Five hospitals (CH · DE · FR · AT · IT) train one model **without any patient record leaving its hospital and without any central server**.
Each hospital gossips signed contributions to its peers over a CRDT ([crdt-merge](https://pypi.org/project/crdt-merge/)), runs the
[acfa-rs](https://github.com/mgillr/acfa-rs) aggregation **itself**, and co-signs the resulting root; a model is installed only when a quorum of
hospitals has signed the same root. Synthetic data, throwaway runtime keys. [Source on GitHub]({GITHUB}) · BSL 1.1 (research/evaluation; commercial licences: rgillespie83@icloud.com | data@optitransfer.ch)""")
    state = gr.State(None)
    with gr.Tab("Mesh"):
        with gr.Row():
            mode = gr.Radio([("Robust (each node runs ACFA multi-Krum; peers see DP-noised updates)", "robust"),
                             ("Blind (pairwise masks; each node sums the masked set)", "blind")], value="robust", label="Mode")
            adversary = gr.Dropdown(list(ADVERSARIES), value="poison", label="IT peer behaviour (adversary toggle)")
            dp = gr.Checkbox(True, label="Differential privacy (DP-SGD, σ=2, ε cap 3)")
        with gr.Row():
            leaky = gr.Dropdown(["none", "CH", "DE", "FR", "AT"], value="none", label="Leaky node (negative test)")
            partition = gr.Dropdown(list(PARTITIONS), value="none", label="Network partition")
        with gr.Row():
            run = gr.Button("▶ Run round", variant="primary"); reset = gr.Button("Reset federation")
        with gr.Row():
            mp = gr.Plot(label="Full mesh of direct hospital-to-hospital links (no hub). ▶ replays this round's gossip tick by tick")
            summ = gr.Markdown()
        conv = gr.Plot(label="CRDT state-hash convergence")
        cos = gr.Dataframe(headers=["signer", "close attempt", "state root", "output root", "receipt sha256", "leaves", "verdict"],
                           label="Co-signed roots gossiped through the CRDT (installed only with a quorum)")
        hashes = gr.Dataframe(headers=["node", "installed model sha256", "state root (own synced set)", "own receipt sha256", "acfa-verify exit"],
                              label="Each node computed and verified the round itself: identical results")
    with gr.Tab("Trust & robustness"):
        gr.Markdown("#### Why robust mode keeps only some sites\n" + ROBUST_MODE_EXPLANATION)
        sel = gr.Dataframe(headers=["site", "rounds admitted", "rounds selected", "selection rate"], label="Per-site selection counts (whole run)")
        gr.Markdown("#### Peer trust (crdt-merge TypedTrustScore, public API)\nEvidence of equivocation, invalid signatures, norm violations or a divergent root lowers a peer's trust in the matching dimension; at ≤ 0.1 every honest peer quarantines it from later rounds. Shown: the lowest view across honest observers.")
        trust = gr.Dataframe(headers=["peer", "overall trust", "dimensions with evidence", "quarantined"], label="Trust")
    with gr.Tab("Egress & DLP"):
        links = gr.Dataframe(headers=["link", "messages", "bytes", "canary hits", "hits delivered"], label="Per-link canary scan (whole run)")
        egress = gr.Dataframe(headers=["seq", "tick", "link", "type", "CRDT entries", "bytes", "sha256", "cross-border", "DLP"],
                              label="Per-link egress log, this round (the ONLY way bytes leave a node)")
    with gr.Tab("Verify & tamper"):
        gr.Markdown("**Verify everything** builds the evidence bundle and runs the standalone `verify_bundle.py` against it (co-signature quorum, receipts, models, egress, DP). Tamper buttons must each FAIL verification.")
        with gr.Row():
            vb = gr.Button("✔ Verify everything", variant="primary")
            t1 = gr.Button("Tamper: flip a receipt byte"); t2 = gr.Button("Tamper: swap the model"); t3 = gr.Button("Tamper: wrong key")
        vout = gr.Markdown(); dl = gr.File(label="Evidence bundle (.zip)")
    with gr.Tab("Privacy attacks"):
        gr.Markdown("Attacks run as **proofs**: each runs with and without DP or secure aggregation to show the protection is what makes the difference. In the mesh every peer is a potential observer.")
        ab = gr.Button("Run attacks (~4 s)", variant="primary"); aout = gr.Markdown(); aplot = gr.Plot()
    with gr.Tab("Formal proofs"):
        gr.Markdown(read("docs/PROOFS.md"))
        pb = gr.Button("Run proofs/check.sh"); pout = gr.Markdown()
    with gr.Tab("How it works"):
        gr.Markdown("### System"); gr.Image(os.path.join(HERE, "docs/diagrams/system.png"), show_label=False)
        gr.Markdown("### One round"); gr.Image(os.path.join(HERE, "docs/diagrams/round.png"), show_label=False)
        gr.Markdown("### Proof map"); gr.Image(os.path.join(HERE, "docs/diagrams/proofmap.png"), show_label=False)
        gr.Markdown(read("docs/PROOF_MAP.md"))
    with gr.Tab("Threat model"):
        gr.Markdown(read("threat-model.md").replace("{{EPS}}", "(see privacy-budget.json)").replace("{{DELTA}}", "1e-5").replace("{{CAP}}", "3"))

    ins = [state, mode, adversary, dp, leaky, partition]
    outs = [state, mp, conv, summ, egress, cos, hashes, trust, sel, links]
    run.click(do_round, ins, outs, api_name="run_round")
    reset.click(do_reset, ins[1:], outs, api_name="reset")
    vb.click(do_verify, [state], [vout, dl], api_name="verify_everything")
    t1.click(lambda f: do_tamper(f, "receipt_byte"), [state], vout, api_name="tamper_receipt_byte")
    t2.click(lambda f: do_tamper(f, "model_swap"), [state], vout, api_name="tamper_model_swap")
    t3.click(lambda f: do_tamper(f, "wrong_key"), [state], vout, api_name="tamper_wrong_key")
    ab.click(do_attacks, [state], [aout, aplot], api_name="do_attacks")
    pb.click(do_proofs, None, pout)
    demo.load(lambda: (None, mesh_map(None), convergence_chart(None), summary(None), [], [], [], [], [], []), None, outs, show_api=False)

if __name__ == "__main__":
    demo.queue(max_size=16).launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 7860)))

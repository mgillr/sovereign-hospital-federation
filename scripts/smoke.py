# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Smoke test against a running app (local URL or HF Space id): run rounds, verify, download bundle, tamper, attacks."""
import sys, zipfile
from gradio_client import Client
c = Client(sys.argv[1], verbose=False)
ok = True
for i in range(2):
    out = c.predict("robust", "poison", True, "none", "none", api_name="/run_round")
    summ = out[2]; lines = summ.splitlines()
    co = [l for l in lines if "co-signed root" in l]; same = [l for l in lines if "identical model" in l]
    print(lines[0], "|", (co or ["?"])[0][:120]); print("   ", (same or ["?"])[0][:200])
    ok &= bool(same) and "**True**" in same[0]
md, path = c.predict(api_name="/verify_everything")
print(md.splitlines()[0]); print([l for l in md.splitlines() if "checks passed" in l])
ok &= "ALL CHECKS PASSED" in md
names = zipfile.ZipFile(path).namelist()
need = ["model-manifest.json", "local-data-manifest.json", "network-egress.log", "acfa-receipt.acfa", "verification.txt",
        "evaluation.json", "adversarial-report.json", "privacy-budget.json", "membership-inference.json", "threat-model.md",
        "mesh.json", "peer-trust.json", "rounds/round-1/cosignatures.json"]
print("bundle files:", len(names), "all required present:", all(n in names for n in need))
ok &= all(n in names for n in need)
for t in ("receipt_byte", "model_swap", "wrong_key"):
    r = c.predict(api_name=f"/tamper_{t}").splitlines()[0]; print(t, r); ok &= "**True**" in r
md, _ = c.predict(api_name="/do_attacks"); print("attacks:", [l for l in md.splitlines() if "Worst case" in l][0][:160])
print("SMOKE:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)

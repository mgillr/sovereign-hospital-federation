# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""The ONLY channel across a node boundary: every peer-to-peer link goes through it. Every message is
DLP-scanned at the sender before it leaves and logged per link (src -> dst, jurisdiction, type, bytes,
sha256). A payload that contains a node's canary strings or record identifiers is BLOCKED and never
delivered. There is no central party: every entry is a direct hospital-to-hospital message."""
import hashlib, json, time


class Egress:
    def __init__(self, jurisdictions, log_path, regimes=None):
        self.j = jurisdictions          # name -> country code
        self.regimes = regimes or {}    # name -> legal regime label (e.g. "CH nFADP")
        self.log_path = log_path
        self.entries, self.payloads = [], []
        self.scanners = {}              # src -> callable(bytes) -> list[str] of matched patterns
        self.seq = 0

    def register_scanner(self, src, fn):
        self.scanners[src] = fn

    def send(self, src, dst, msg_type, payload: bytes, extra=None):
        assert isinstance(payload, (bytes, bytearray))
        hits = self.scanners.get(src, lambda b: [])(payload)
        self.seq += 1
        e = {"seq": self.seq, "ts": round(time.time(), 3), "src": src, "src_jurisdiction": self.j.get(src, "?"),
             "src_regime": self.regimes.get(src, "?"),
             "dst": dst, "dst_jurisdiction": self.j.get(dst, "?"), "dst_regime": self.regimes.get(dst, "?"), "type": msg_type, "bytes": len(payload),
             "sha256": hashlib.sha256(payload).hexdigest(),
             "crosses_border": self.j.get(src) != self.j.get(dst),
             "link": f"{src}->{dst}", "dlp": "BLOCKED" if hits else "pass", "dlp_hits": len(hits), **(extra or {})}
        self.entries.append(e); self.payloads.append(bytes(payload))
        with open(self.log_path, "a") as fh:
            fh.write(json.dumps(e, sort_keys=True) + "\n")
        if hits:
            return None                 # never delivered
        return bytes(payload)

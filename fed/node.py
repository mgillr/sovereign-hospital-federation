# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""One hospital node. Owns its data dir and its throwaway runtime keys; talks to peers only via Egress."""
import hashlib, json, os
import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from . import acfa, data, dp, model, secagg

Q = 1 << 16
CLIP_MARGIN = 0.999


def to_q16(x):
    v = np.asarray(x, np.float64) * Q
    q = np.sign(v) * np.floor(np.abs(v) + 0.5)          # half away from zero, as acfa fixed::encode
    if not np.all(np.isfinite(q)) or np.any(np.abs(q) > (1 << 31) - 1):
        raise ValueError("update outside Q16.16 range")
    return [int(t) for t in q]


def from_q16(ints):
    return np.asarray(ints, np.float64) / Q


def clip_l2(x, S):
    n = float(np.linalg.norm(x))
    return x * min(1.0, S / n) if n > 0 else x, n


class Node:
    def __init__(self, site, root, seed, *, mode="honest", dp_cfg=None, clip_S=1.0):
        self.site = site
        self.node_id = data.SITES[site]["node_id"]
        self.country = data.SITES[site]["country"]
        self.dir = os.path.join(root, "nodes", site)
        self.data_dir = os.path.join(self.dir, "data")
        self.key_dir = os.path.join(self.dir, "keys")
        self.mode, self.seed, self.dp_cfg, self.clip_S = mode, seed, dp_cfg, clip_S
        self.steps_log = []            # per round: q, sigma, steps (for the accountant)
        self.synced = None             # crdt-merge CRDTMergeState of contribution envelopes

    # ---------- setup ----------
    def setup(self):
        self.canaries, self.paths, self.canary_Z, self.canary_y = data.write_site(self.site, self.data_dir, self.seed)
        _, self.Xtr, self.ytr = data.load(self.paths["train"])
        _, self.Xte, self.yte = data.load(self.paths["test"])
        os.makedirs(self.key_dir, exist_ok=True)
        # THROWAWAY DEMO KEYS: generated fresh at runtime, never reused, never committed.
        self._secret = os.urandom(32).hex()
        with open(os.path.join(self.key_dir, "THROWAWAY-demo-ed25519.secret"), "w") as fh:
            fh.write(self._secret)
        self.pubkey = acfa.call("pubkey", {"node_id": self.node_id, "secret": self._secret})["pubkey"]
        self._ed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self._secret))
        same = self._ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        assert same == self.pubkey, "RFC 8032 seed must give the same key in acfa-rs and python"
        self._x_sk, self.x25519_pub = secagg.new_x25519()

    def data_manifest(self):
        return {"site": self.site, "country": self.country, "node_id": self.node_id,
                "jurisdiction": data.JURISDICTION[self.site],
                "files": {k: {"name": os.path.basename(p), "sha256": data.file_sha256(p),
                              "rows": int(len(self.ytr) if k == "train" else len(self.yte))}
                          for k, p in self.paths.items()},
                "schema": ["patient_id", "full_name", "date_of_birth"] + data.FEATURES + ["cv_event_5y"],
                "canary_sha256": [hashlib.sha256(c.encode()).hexdigest() for c in self.canaries],
                "location": "node-local disk only; never transmitted"}

    # ---------- DLP scanner at this node's egress gateway ----------
    def patterns(self):
        return list(self.canaries) + [f"{self.site}-TR-", f"{self.site}-TE-", "CANARY-", "Synthetic Patient",
                                      "Canary Person", "full_name", "date_of_birth", "cv_event_5y"]

    def scan(self, payload: bytes):
        txt = payload.decode("utf-8", "replace")
        return [p for p in self.patterns() if p in txt]

    # ---------- integrity ----------
    @staticmethod
    def check_base(w, manifest):
        if model.sha256(w) != manifest["base_model_sha256"]:
            raise ValueError("base model hash does not match the pinned manifest: refusing to train")

    def sign_json(self, obj) -> str:
        return self._ed.sign(json.dumps(obj, sort_keys=True).encode()).hex()

    # ---------- local training: DP-SGD then update-level clip (post-processing) ----------
    def local_delta(self, w, rnd, epochs=1):
        rng = np.random.default_rng([self.seed, rnd, self.node_id])
        c = self.dp_cfg
        # LR decay: smaller steps once the model plateaus (privacy-neutral: epsilon depends on sigma, q, steps)
        decay = 1.0 / np.sqrt(rnd) if getattr(self, "lr_decay", True) else 1.0
        if c:
            d, steps, q = dp.dp_sgd_local(w, self.Xtr, self.ytr, epochs=epochs, batch=c["batch"], lr=c["lr"] * decay,
                                          clip=c["clip"], sigma=c["sigma"], rng=rng)
            self.steps_log.append({"round": rnd, "q": q, "sigma": c["sigma"], "steps": steps})
        else:
            d, steps, q = dp.sgd_local(w, self.Xtr, self.ytr, epochs=epochs, batch=64, lr=0.3 * decay, rng=rng)
        d, raw_norm = clip_l2(d, self.clip_S * CLIP_MARGIN)   # margin absorbs Q16.16 rounding
        return d, raw_norm

    def projected_steps(self, epochs=1):
        if not self.dp_cfg: return 0, 0.0
        q = self.dp_cfg["batch"] / len(self.ytr)
        return int(round(epochs / q)), q

    def epsilon(self, delta, extra_steps=0):
        if not self.dp_cfg: return None
        steps = sum(s["steps"] for s in self.steps_log) + extra_steps
        if steps == 0: return 0.0
        return dp.epsilon_for(self.dp_cfg["batch"] / len(self.ytr), self.dp_cfg["sigma"], steps, delta)

    def sign_contribution(self, tensor, ctx, rnd, f):
        return acfa.call("sign", {"node_id": self.node_id, "secret": self._secret, "ctx": ctx, "round": rnd,
                                  "f": f, "tensor": tensor})

    def envelope(self, obj) -> bytes:
        """Serializer for every outbound peer message."""
        return json.dumps(obj, sort_keys=True).encode()

    def tag_outbound(self, meta):
        """Metadata attached to this node's own contribution entry. A 'leaky' node has a debug bug that
        attaches raw rows here; its egress DLP scan then blocks every message that carries the entry."""
        if self.mode == "leaky":
            with open(self.paths["train"]) as fh:
                meta = dict(meta, debug_sample=fh.read().splitlines()[:4])
        return meta

    def allowed_peers(self, key, sites):
        """Peers this node will gossip `key` to (all, except an equivocator's per-variant restriction)."""
        return getattr(self, "restrict", {}).get(key, set(s for s in sites if s != self.site))

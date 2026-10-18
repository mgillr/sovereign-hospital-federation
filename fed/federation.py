# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""A leaderless consortium of five hospital nodes. There is NO coordinator, aggregator or relay.

Per round, every node:
  1. trains locally (DP-SGD), clips, encodes Q16.16, (blind mode) adds pairwise masks, signs;
  2. gossips its signed envelope peer-to-peer through a crdt-merge CRDTMergeState (grow-only set,
     keyed by round/node/leaf). Gossip runs over a simulated mesh with random delay, duplicates and
     partitions that heal. Union is commutative/associative/idempotent, so delivery order does not matter;
  3. closes the round by a deterministic rule (all N contributions, or a quorum after a logical deadline),
     runs the SAME pinned acfa-rs rule LOCALLY on its own set, derives the receipt (byte-identical across
     nodes for the same set) and signs (state root, output root, receipt hash, candidate hash, leaf set);
  4. gossips that co-signature; a root is ACCEPTED when a quorum Q of distinct participants signed it
     (2Q > n + f, so two different roots cannot both reach quorum: theorem Quorum.quorum_intersection);
     a node whose signed root differs is flagged; it recomputes on the quorum-signed leaf set to recover;
  5. evaluates the candidate on its own test data, gossips a signed eval report, applies the regression
     gate itself, installs. Every honest node ends with the byte-identical model.

Modes:
  robust  every node runs ACFA multi-Krum (f=1) locally; peers see each DP-noised update.
  blind   pairwise X25519 masks; every node sums the full masked set itself (select-all band = exact mean).
          No per-update filtering. Missing/invalid/convicted participants -> deterministic re-mask attempt.
          Out-of-bound updates -> commit-and-open dispute gossiped to all peers (not zero-knowledge).
Peer trust: crdt-merge's TypedTrustScore (E4 public API) records verifiable misbehaviour; a peer whose
trust in a dimension falls to the quarantine threshold is excluded from later rounds.
"""
import base64, hashlib, json, os, shutil, time
import numpy as np
from crdt_merge.model.crdt_state import CRDTMergeState
from crdt_merge.e4.typed_trust import TypedTrustScore, QUARANTINE_THRESHOLD, TRUST_DIMENSIONS, PROBATION_TRUST
from . import acfa, attacks, data, dp, model, secagg
from .egress import Egress
from .node import Node, from_q16, to_q16, Q

SITES = ["CH", "DE", "FR", "AT", "IT"]
ADVERSARY_SITE = "IT"
ADVERSARIES = ["none", "poison", "equivocate", "forged-signature", "sign-flip-in-bound", "divergent-root"]
MSG_TYPES = {"public-keys", "gossip"}
GOSSIP_KINDS = {"robust": {"contrib", "cosig", "eval"}, "blind": {"contrib", "cosig", "eval", "opening"}}
ALLOWED = {m: MSG_TYPES | {f"gossip/{k}" for k in GOSSIP_KINDS[m]} for m in GOSSIP_KINDS}
DEFAULT_DP = {"mechanism": "DP-SGD", "sigma": 2.0, "clip": 1.0, "batch": 128, "lr": 1.2, "lr_decay": "1/sqrt(round)"}
DEFAULT_MESH = {"delay": [1, 3], "dup_p": 0.2, "deadline": 6, "cosig_timeout": 6, "max_close_attempts": 4,
                "max_ticks": 60, "partition": None}
PREFIX = {"contrib": "c", "cosig": "s", "eval": "e", "opening": "o"}
DELTA = 1e-5
EPS_CAP = 3.0
GATE_TOL = 0.02
F_BYZ = 1
BOUND_HEADROOM_Q = 1 << 21
EVIDENCE = {"equivocation": ("consistency", 1.0), "invalid-signature": ("integrity", 1.0),
            "norm-violation": ("model", 1.0), "divergent-root": ("consistency", 0.5)}


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


ROBUST_MODE_EXPLANATION = (
    "Robust mode uses ACFA multi-Krum with f = 1, run by every hospital on the same gossiped set. By definition "
    "multi-Krum keeps m = n - f - 2 contributions: 2 of 5 when all five take part, 1 of 4 once a convicted peer is "
    "quarantined. It keeps the updates closest to their neighbours, so with non-IID hospitals the same central sites "
    "tend to win and some honest sites are rarely or never selected (see the per-site counts): that is the known "
    "fairness cost of distance-based robust aggregation, not a fault, and the counts are reported rather than hidden. "
    "Averaging only two non-IID updates also moves the model towards those two sites, which is why a site's own "
    "accuracy can dip and the per-site regression gate (2-point tolerance on ~600 local test rows, standard error "
    "~1.5 points) can roll a round back. The fix in this version is a learning rate that decays as 1/sqrt(round): in "
    "the 7-round, seed-7 measurement it removed the rollbacks at rounds 5 and 7 of the no-DP runs, leaving one "
    "rollback in 28 robust rounds (no DP, no adversary, round 4, IT -3.3 points). A rollback is the gate working: "
    "nothing is installed and the next round continues from the previous model. Blind mode averages every admitted "
    "update (exact mean) and relies on norm-bound disputes instead.")


def quorum(n, f=F_BYZ):
    """Smallest Q with Q <= n, Q >= n-1 and 2Q > n + f (quorum intersection with f double-signers)."""
    return min(n, max(n - 1, (n + f) // 2 + 1))


def regression_gate(before: dict, after: dict, tol: float = GATE_TOL) -> dict:
    """Accept iff NO axis falls below before - tol, in integer basis points (theorem Gate.gate_accept_no_regression)."""
    bp = lambda v: int(round(v * 10000))
    t = bp(tol)
    deltas = {k: round(after[k] - before[k], 4) for k in before if k in after}
    failing = [k for k in deltas if bp(after[k]) + t < bp(before[k])]
    return {"passed": not failing, "tol": tol, "deltas": deltas, "failing": failing,
            "theorem": "Gate.gate_accept_no_regression"}


class _Proof:
    """Proof object for TypedTrustScore.record_evidence. A node records evidence only after it has checked the
    misbehaviour itself (signatures, roots, openings); verify() returns the result of that check."""
    def __init__(self, ok): self.ok = bool(ok)
    def verify(self): return self.ok


class Federation:
    def __init__(self, root, seed=7, *, mode="robust", adversary="poison", dp=True, leaky_node=None,
                 dp_cfg=None, eps_cap=EPS_CAP, clip_S=1.0, mesh=None, lr_decay=True):
        assert mode in GOSSIP_KINDS and adversary in ADVERSARIES + [None]
        self.root = str(root); self.seed = seed; self.mode = mode
        self.adversary = adversary or "none"; self.leaky_node = leaky_node
        self.dp_cfg = (dp_cfg or dict(DEFAULT_DP)) if dp else None
        self.eps_cap = eps_cap; self.clip_S = clip_S; self.lr_decay = bool(lr_decay)
        self.mesh = {**DEFAULT_MESH, **(mesh or {})}
        self.pub_dir = os.path.join(self.root, "published")          # artefacts for the evidence bundle
        self.verifier_dir = os.path.join(self.root, "offline-verifier")
        self.rounds, self.halted = [], None
        self.tamper_results = {}

    # ------------------------------------------------------------------ setup
    def setup(self):
        os.makedirs(self.pub_dir, exist_ok=True); os.makedirs(self.verifier_dir, exist_ok=True)
        log = os.path.join(self.root, "network-egress.log")
        if os.path.exists(log): os.remove(log)
        self.rng = np.random.default_rng(self.seed + 991)
        self.nodes = {}
        for i, s in enumerate(SITES):
            m = "honest"
            if s == ADVERSARY_SITE and self.adversary != "none": m = self.adversary
            if s == self.leaky_node: m = "leaky"
            self.nodes[s] = Node(s, self.root, self.seed * 100 + i, mode=m, dp_cfg=self.dp_cfg, clip_S=self.clip_S)
            self.nodes[s].setup()
        self.egress = Egress({s: data.SITES[s]["country"] for s in SITES}, log,
                             regimes={s: data.JURISDICTION[s] for s in SITES})
        for s, n in self.nodes.items():
            self.egress.register_scanner(s, n.scan)
        # key exchange, peer to peer (public keys only); PKI pinned out of band (threat-model.md)
        self.directory = {}
        for s, n in self.nodes.items():
            ann = n.envelope({"node_id": n.node_id, "site": s, "ed25519": n.pubkey, "x25519": n.x25519_pub})
            for p in SITES:
                if p == s: continue
                got = self.egress.send(s, p, "public-keys", ann, {"tick": 0})
                if got: self.directory[json.loads(got)["node_id"]] = json.loads(got)
        self.pki_text = "# shf consortium PKI: <node_id> <ed25519 public key hex>  (THROWAWAY demo keys)\n" + "".join(
            f"{i} {self.directory[i]['ed25519']}\n" for i in sorted(self.directory))
        for d in [self.pub_dir, self.verifier_dir] + [n.dir for n in self.nodes.values()]:
            with open(os.path.join(d, "consortium.pki"), "w") as fh: fh.write(self.pki_text)
        self.w0 = model.init(self.seed)                      # public genesis model, computed by every node
        for n in self.nodes.values():
            n.w = self.w0.copy(); n.synced = CRDTMergeState("weight_average"); n.lr_decay = self.lr_decay
            n.trust = {t: TypedTrustScore.probationary() for t in SITES if t != n.site}
            n.evidence_seen = set()
            os.makedirs(os.path.join(n.dir, "model"), exist_ok=True)
        self.w = self.w0.copy()
        np.save(os.path.join(self.pub_dir, "base-model-r0.npy"), self.w0)
        self.Xc, self.yc = data.common_benchmark(self.seed + 1)   # public benchmark, every node holds a copy
        self.eval_reports, self.evidence = [], []
        self.tick = 0
        self.link_stats = {}

    @property
    def pki_list(self):
        return [[i, self.directory[i]["ed25519"]] for i in sorted(self.directory)]

    def site_of(self, node_id):
        return next(s for s in SITES if self.nodes[s].node_id == node_id)

    def ctx_of(self, manifest) -> str:
        return hashlib.sha256(canon(manifest)).hexdigest()

    def _contrib_sig_ok(self, c):
        """A node's own check of an ACFA contribution signature (same preimage acfa-rs signs)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        th = hashlib.sha256("|".join(str(int(v)) for v in c["tensor"]).encode()).digest()
        if th.hex() != c.get("tensor_hash"): return False
        msg = (b"ACFA-CONTRIB2|" + bytes.fromhex(c["ctx"]) + bytes([0]) + int(c["f"]).to_bytes(4, "big") +
               (16).to_bytes(4, "big") + int(c["round"]).to_bytes(8, "big") + int(c["node_id"]).to_bytes(4, "big") + th)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.directory[c["node_id"]]["ed25519"])).verify(bytes.fromhex(c["sig"]), msg)
            return True
        except Exception:
            return False

    def _verify_json(self, node_id, obj, sig_hex):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk = self.directory.get(node_id, {}).get("ed25519")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
                bytes.fromhex(sig_hex), json.dumps(obj, sort_keys=True).encode()); return True
        except Exception:
            return False

    # ------------------------------------------------------------------ CRDT helpers
    @staticmethod
    def _put(n, key, meta, tensor=None):
        if key in n.synced.model_ids: return
        n.synced.add(np.asarray(tensor, dtype=np.float64) if tensor is not None else np.zeros(model.N_PARAMS), model_id=key, metadata=meta)

    @staticmethod
    def _entries(n, kind, acfa_round=None):
        out = []
        for k in sorted(n.synced.model_ids):
            if not k.startswith(PREFIX[kind] + "/"): continue
            c = n.synced.get_contribution(k); meta = dict(c.metadata)
            if acfa_round is not None and meta.get("acfa_round") != acfa_round: continue
            meta["_key"] = k
            if kind == "contrib":
                meta["c"] = dict(meta["c"], tensor=[int(v) for v in np.asarray(c.tensor).ravel()])
            out.append(meta)
        return out

    def _contribs(self, n, acfa_round, leaves=None):
        cs = [e["c"] for e in self._entries(n, "contrib", acfa_round)]
        if leaves is not None:
            cs = [c for c in cs if c["leaf"] in set(leaves)]
        return sorted(cs, key=lambda c: c["leaf"])

    # ------------------------------------------------------------------ the mesh
    def _link_up(self, a, b, rel_tick):
        p = self.mesh.get("partition")
        if not p: return True
        if not (p["from"] <= rel_tick < p["until"]): return True
        ga = next(i for i, g in enumerate(p["groups"]) if a in g)
        gb = next(i for i, g in enumerate(p["groups"]) if b in g)
        return ga == gb

    def _gossip_tick(self, rel_tick, inflight, sent, trace):
        """One logical tick: deliver due messages in random order (duplicates included), then every node
        pushes to every reachable peer the CRDT entries it has not yet sent on that link."""
        due = [m for m in inflight if m[0] <= self.tick]
        inflight[:] = [m for m in inflight if m[0] > self.tick]
        self.rng.shuffle(due)
        for _, dst, payload, _src in due:
            st = CRDTMergeState.from_dict(json.loads(payload)["state"])
            self.nodes[dst].synced = self.nodes[dst].synced.merge(st)
            self._mstats["delivered"] += 1
        senders = list(SITES); self.rng.shuffle(senders)
        for s in senders:
            n = self.nodes[s]
            peers = [p for p in SITES if p != s]; self.rng.shuffle(peers)
            for p in peers:
                if not self._link_up(s, p, rel_tick):
                    self._mstats["link_down_skips"] += 1; continue
                ks = [k for k in sorted(n.synced.model_ids) if k not in sent.setdefault((s, p), set())
                      and p in n.allowed_peers(k, SITES)]
                if not ks: continue
                d = n.synced.to_dict()
                d["contributions"] = {k: d["contributions"][k] for k in ks}
                kinds = sorted({ {"c": "contrib", "s": "cosig", "e": "eval", "o": "opening"}[k[0]] for k in ks})
                payload = n.envelope({"state": d, "kinds": kinds})
                got = self.egress.send(s, p, "gossip/" + "+".join(kinds), payload,
                                       {"tick": self.tick, "entries": len(ks)})
                sent[(s, p)].update(ks)
                ls = self.link_stats.setdefault(f"{s}->{p}", {"messages": 0, "bytes": 0, "blocked": 0})
                ls["messages"] += 1; ls["bytes"] += len(payload); ls["blocked"] += got is None
                if got is None:
                    self._mstats["blocked"] += 1; continue
                lo, hi = self.mesh["delay"]
                at = self.tick + int(self.rng.integers(lo, hi + 1))
                inflight.append((at, p, got, s)); self._mstats["sent"] += 1
                self._mstats["max_delay"] = max(self._mstats["max_delay"], at - self.tick)
                if self.rng.random() < self.mesh["dup_p"]:
                    inflight.append((at + int(self.rng.integers(1, 3)), p, got, s)); self._mstats["duplicates"] += 1
        trace.append({"tick": self.tick, "rel": rel_tick, **{s: self.nodes[s].synced.state_hash[:12] for s in SITES}})
        self.tick += 1

    # ------------------------------------------------------------------ rounds
    def run_rounds(self, n):
        out = []
        for _ in range(n):
            r = self.run_round()
            out.append(r)
            if r.get("halted") or r.get("failed"): break
        return out

    def quarantined(self):
        """Peers every honest node has quarantined (identical across honest nodes: derived from shared state)."""
        honest = [s for s, n in self.nodes.items() if n.mode == "honest"]
        views = [{t for t, sc in self.nodes[h].trust.items()
                  if any(sc.trust_for_dimension(d) <= QUARANTINE_THRESHOLD for d in TRUST_DIMENSIONS)} for h in honest]
        return sorted(set.intersection(*views)) if views else []

    def run_round(self):
        t0 = time.perf_counter()
        if self.halted:
            return {"round": len(self.rounds) + 1, "halted": True, **self.halted}
        rnd = len(self.rounds) + 1
        quar = self.quarantined()
        participants = [self.nodes[s].node_id for s in SITES if s not in quar]
        if self.dp_cfg:   # every node computes every node's projected epsilon from public parameters
            proj = {s: self.nodes[s].epsilon(DELTA, extra_steps=self.nodes[s].projected_steps()[0])
                    for s in SITES if s not in quar}
            over = {s: round(e, 3) for s, e in proj.items() if e > self.eps_cap}
            if over:
                self.halted = {"round": rnd, "reason": "privacy budget would be exceeded", "projected": over,
                               "cap": self.eps_cap}
                return {"round": rnd, "halted": True, **self.halted}
        for n in self.nodes.values():            # each round has its own grow-only set (older rounds archived)
            n.archive = getattr(n, "archive", []) + [n.synced]; n.synced = CRDTMergeState("weight_average")
        self._mstats = {"sent": 0, "delivered": 0, "duplicates": 0, "blocked": 0, "link_down_skips": 0, "max_delay": 0}
        tick_start = self.tick
        w_before = {s: n.w.copy() for s, n in self.nodes.items()}
        base_sha = model.sha256(w_before[self._ref()])
        trained, attempts, disputes, trace = {}, [], [], []
        attempt, gate_disputed = 0, False
        while True:
            attempt += 1
            res = self._attempt(rnd, attempt, participants, trained, w_before, trace, tick_start)
            attempts.append(res["summary"])
            disputes += res.get("disputes", [])
            if res.get("failed"):
                break
            if res["restart_without"]:
                participants = [p for p in participants if p not in res["restart_without"]]
                if len(participants) < 3 or attempt >= 6:
                    res["failed"] = "too few participants left after exclusions"; break
                continue
            ev = self._eval_phase(rnd, res, w_before, trace, tick_start)
            res["eval"] = ev
            g = ev["gate"]
            if self.mode == "blind" and not g["passed"] and not gate_disputed:
                gate_disputed = True
                disp = self._dispute(rnd, res, participants, trace, tick_start)
                disp["trigger"] = "regression gate failed on the blind aggregate"
                disputes.append(disp)
                attempts[-1]["restart_reason"] = "regression gate failed: commit-and-open dispute"
                if disp["violators"]:
                    participants = [p for p in participants if p not in disp["violators"]]
                    if len(participants) >= 3: continue
            break
        rr = self._finish_round(rnd, res, attempts, disputes, trace, w_before, base_sha, t0, tick_start)
        self._update_trust(rr)
        rr["trust"] = self.trust_report()
        self.rounds.append(rr)
        return rr

    # ------------------------------------------------------------------ one attempt
    def _manifest(self, rnd, attempt, participants, base_sha, f, R):
        return {"schema": "shf-round/v2-leaderless", "round": rnd, "attempt": attempt,
                "acfa_round": rnd * 100 + attempt, "mode": self.mode, "base_model_sha256": base_sha,
                "model": {"arch": "MLP 20-32-2 ReLU softmax", "n_params": model.N_PARAMS, "dtype": "float32-le"},
                "scaler": "public reference scaler (fed/data.py REF_MEAN/REF_STD)",
                "aggregation": {"engine": "acfa-rs", "rev": acfa.ACFA_REV, "rule": "krum", "f": f, "frac_bits": 16,
                                "computed_by": "every node, locally",
                                "note": "robust: multi-Krum f=1 (keeps m=n-f-2)" if self.mode == "robust"
                                else "blind: select-all band (f=n-2) = exact integer mean; NO robust filtering"},
                "close_rule": {"all_n": True, "quorum_after_deadline": quorum(len(participants)),
                               "deadline_ticks": self.mesh["deadline"], "cosign_quorum": quorum(len(participants))},
                "participants": participants, "clip_S": self.clip_S,
                "dp": self.dp_cfg, "dp_delta": DELTA, "eps_cap": self.eps_cap,
                "lr_schedule": "base_lr/sqrt(round)" if self.lr_decay else "constant",
                "secagg": {"scheme": "pairwise X25519+HKDF masks, integer, no modulus", "R": R} if R else None}

    def _attempt(self, rnd, attempt, participants, trained, w_before, trace, tick_start):
        acfa_round = rnd * 100 + attempt
        n_part = len(participants)
        f = F_BYZ if self.mode == "robust" else n_part - 2
        R = secagg.mask_range(n_part, BOUND_HEADROOM_Q) if self.mode == "blind" else None
        Qn = quorum(n_part)
        manifests = {s: self._manifest(rnd, attempt, participants, model.sha256(w_before[s]), f, R) for s in SITES}
        ctxs = {s: self.ctx_of(m) for s, m in manifests.items()}
        manifest, ctx = manifests[self._ref()], ctxs[self._ref()]
        updates, private = {}, {}
        x_dir = {i: self.directory[i]["x25519"] for i in participants}
        for s, n in self.nodes.items():
            n.restrict = {}
            if n.node_id not in participants: continue
            n.check_base(w_before[s], manifests[s])                  # pinned base hash
            if s not in trained:
                trained[s] = n.local_delta(w_before[s], rnd)
            d, raw_norm = trained[s]
            send_q, side_q = to_q16(d), None
            if n.mode == "poison": send_q = to_q16(-8.0 * d)
            elif n.mode == "sign-flip-in-bound": send_q = to_q16(-1.0 * d)
            elif n.mode == "equivocate": side_q = to_q16(-8.0 * d)
            sent_tensor, extra = send_q, {}
            if self.mode == "blind":
                peers = {j: pk for j, pk in x_dir.items() if j != n.node_id}
                sent_tensor, seeds = secagg.mask_vector(send_q, n.node_id, n._x_sk, peers, ctxs[s], R)
                r_open = os.urandom(32)
                com = secagg.commit(ctxs[s], n.node_id, send_q, r_open)
                n._opening = {"x_q": send_q, "r": r_open.hex(), "seeds": seeds, "acfa_round": acfa_round}
                extra = {"commitment": com, "commitment_sig": n.sign_json({"ctx": ctxs[s], "commitment": com})}
                if side_q is not None:
                    side_q, _ = secagg.mask_vector(side_q, n.node_id, n._x_sk, peers, ctxs[s], R)
            contrib = n.sign_contribution(sent_tensor, ctxs[s], acfa_round, f)
            if n.mode == "forged-signature":
                contrib["tensor"] = to_q16(-8.0 * d) if self.mode == "robust" else [v + 12345 for v in contrib["tensor"]]
            variants = [contrib] + ([n.sign_contribution(side_q, ctxs[s], acfa_round, f)] if side_q is not None else [])
            for vi, c in enumerate(variants):
                key = f"c/{acfa_round}/{n.node_id}/{c['leaf'][:16]}"
                meta = {"kind": "contrib", "acfa_round": acfa_round, "node_id": n.node_id,
                        "c": {k: v for k, v in c.items() if k != "tensor"}, **extra}
                meta = n.tag_outbound(meta)                         # a leaky node's bug attaches raw rows here
                self._put(n, key, meta, c["tensor"])
                if len(variants) > 1:                                # equivocation: variant i only to half the peers
                    peers_ = [p for p in SITES if p != s]
                    n.restrict[key] = set(peers_[:2]) if vi == 0 else set(peers_[2:])
            updates[s] = {"ctx": contrib["ctx"] if "ctx" in contrib else ctxs[s], "round": rnd, "sig": contrib["sig"],
                          "tensor_hash": contrib["tensor_hash"], "leaf": contrib["leaf"], "tensor": contrib["tensor"],
                          "l2_norm_sent_float": round(float(np.linalg.norm(from_q16(send_q))), 4),
                          "raw_norm_before_clip": round(raw_norm, 4)}
            private[s] = {"delta_clear": from_q16(send_q), "observed_by_peers": from_q16(contrib["tensor"])}
        # ---- gossip + leaderless close + co-signed roots
        state = {s: {"closed": False, "attempt": 0, "accepted": None, "close_tick": None, "own": None,
                     "signed": {}} for s in SITES}
        inflight, sent = [], {}
        close_attempt, last_close_tick = 1, None
        divergent_events = []
        for _ in range(self.mesh["max_ticks"]):
            rel = self.tick - tick_start
            self._gossip_tick(rel, inflight, sent, trace)
            rel = self.tick - tick_start
            for s, n in self.nodes.items():
                st = state[s]
                if st["accepted"] is not None: continue
                if not st["closed"] or st["attempt"] < close_attempt:
                    have = {c["node_id"] for c in self._contribs(n, acfa_round)} & set(participants)
                    if have == set(participants) or (rel >= self.mesh["deadline"] and len(have) >= Qn) \
                            or (st["attempt"] < close_attempt and st["attempt"] > 0):
                        self._close(n, st, acfa_round, ctxs[s], f, close_attempt, rel)
                        last_close_tick = rel if last_close_tick is None else last_close_tick
                acc = self._accepted_root(n, acfa_round, participants, Qn)
                if acc is not None:
                    st["accepted"] = acc
                    if st["own"] is None or st["own"]["state_root"] != acc["state_root"] \
                            or st["own"]["leaves"] != acc["leaves"]:
                        self._recover(n, st, acfa_round, ctxs[s], f, acc)
                        if st["own"] is not None:
                            divergent_events.append({"site": s, "own_root": st["own"]["state_root"],
                                                     "accepted_root": acc["state_root"], "recovery": st.get("recovery")})
            if all(state[s]["accepted"] is not None for s in SITES):
                break
            if last_close_tick is not None and rel - last_close_tick >= self.mesh["cosig_timeout"]:
                if close_attempt >= self.mesh["max_close_attempts"]: break
                close_attempt += 1; last_close_tick = rel           # no quorum yet: everyone re-closes
        accepted = {s: state[s]["accepted"] for s in SITES}
        honest_acc = {s: a for s, a in accepted.items() if self.nodes[s].mode == "honest"}
        if any(a is None for a in honest_acc.values()):
            return {"failed": "no quorum of co-signed roots within max_ticks: fewer than Q reachable honest signers (unhealed partition or more than f faulty peers). Safety over liveness: no model installed",
                    "summary": {"attempt": attempt, "acfa_round": acfa_round, "participants": participants,
                                "failed": True, "close_attempts": close_attempt},
                    "manifest": manifest, "ctx": ctx, "acfa_round": acfa_round, "updates": updates,
                    "_private": private, "state": state, "restart_without": None}
        ref = self._ref()
        acc = honest_acc[ref]
        cos = self._cosig_report(self.nodes[ref], acfa_round, participants, Qn, ctxs[ref], f)
        rec = dict(state[ref]["rec"])
        ids = {self.nodes[s].node_id: s for s in SITES}
        rec.update({"rule": "krum", "f": f, "n": len(rec["admitted"]),
                    "selected_sites": [ids[i] for i in rec["selected"]],
                    "dropped_sites": [ids[i] for i in rec["admitted"] if i not in rec["selected"]],
                    "convicted_sites": [ids[i] for i in rec["convicted"]]})
        present = {c["node_id"] for c in self._contribs(self.nodes[ref], acfa_round, acc["leaves"])}
        invalid = sorted((present - set(rec["admitted"]) - set(rec["convicted"])) & set(participants))
        missing = sorted(set(participants) - set(rec["admitted"]))
        summary = {"attempt": attempt, "acfa_round": acfa_round, "participants": participants,
                   "admitted": rec["admitted"], "selected": rec["selected"], "convicted": rec["convicted"],
                   "invalid_signature": invalid, "close_attempts": close_attempt,
                   "close_ticks": {s: state[s]["close_tick"] for s in SITES}}
        out = {"manifest": manifest, "manifests": manifests, "ctx": ctx, "ctxs": ctxs, "acfa_round": acfa_round,
               "f": f, "R": R, "Q": Qn, "receipt": rec, "accepted": accepted, "state": state, "cosign": cos,
               "divergent_events": divergent_events, "updates": updates, "_private": private, "summary": summary,
               "restart_without": None, "participants": participants, "invalid": invalid}
        if self.mode == "blind":
            agg = from_q16(rec["aggregate"])
            out["secagg"] = {"R": R, "hiding_tv_bound_per_update": {
                s: round(secagg.hiding_bound(to_q16(private[s]["delta_clear"]), R), 6) for s in private},
                "aggregate_l2": round(float(np.linalg.norm(agg)), 4), "bound_S": self.clip_S,
                "summed_by": sorted(x for x in SITES if state[x].get("rec") is not None)}
            bad = sorted(set(missing) | set(rec["convicted"]))
            if bad:
                summary["restart_reason"] = "participants missing/invalid/convicted: masks cannot cancel; re-mask"
                out["restart_without"] = bad
            elif float(np.linalg.norm(agg)) > self.clip_S * (1 + 1e-9):
                summary["restart_reason"] = "aggregate norm bound violated: commit-and-open dispute"
                disp = self._dispute(rnd, out, participants, trace, tick_start)
                out["disputes"] = [disp]
                out["restart_without"] = disp["violators"] or None
        return out

    def _issue(self, n, acfa_round, ctx, f, contribs, tag):
        rdir = os.path.join(n.dir, "receipts"); os.makedirs(rdir, exist_ok=True)
        rpath, xpath = os.path.join(rdir, f"r{acfa_round}-{tag}.acfa"), os.path.join(rdir, f"r{acfa_round}-{tag}.redacted.acfa")
        rec = acfa.call("issue", {"pki": self.pki_list, "ctx": ctx, "round": acfa_round, "f": f,
                                  "contributions": contribs, "out": rpath, "out_redacted": xpath})
        rec["receipt_path"], rec["redacted_path"] = rpath, xpath
        rec["receipt_sha256"] = hashlib.sha256(open(rpath, "rb").read()).hexdigest()
        return rec

    def _candidate(self, w_before, rec):
        return (w_before.astype(np.float32) + from_q16(rec["aggregate"]).astype(np.float32)).astype(np.float32)

    def _close(self, n, st, acfa_round, ctx, f, close_attempt, rel):
        contribs = self._contribs(n, acfa_round)
        rec = self._issue(n, acfa_round, ctx, f, contribs, f"a{close_attempt}")
        cand = self._candidate(n.w, rec)
        body = {"kind": "cosig", "acfa_round": acfa_round, "close_attempt": close_attempt, "ctx": ctx,
                "node_id": n.node_id, "state_root": rec["state_root"], "output_root": rec["output_root"],
                "receipt_sha256": rec["receipt_sha256"], "candidate_sha256": model.sha256(cand),
                "leaves": sorted(c["leaf"] for c in contribs)}
        if n.mode == "divergent-root":                      # byzantine: signs a root it did not compute
            body["state_root"] = hashlib.sha256(b"forged" + rec["state_root"].encode()).hexdigest()
        body["sig"] = n.sign_json({k: v for k, v in body.items() if k != "sig"})
        self._put(n, f"s/{acfa_round}/{close_attempt}/{n.node_id}/{body['state_root'][:12]}", body)
        st.update({"closed": True, "attempt": close_attempt, "close_tick": rel, "own": body, "rec": rec, "cand": cand})

    def _recover(self, n, st, acfa_round, ctx, f, acc):
        """A node whose own root differs recomputes on the quorum-signed leaf set (it must hold every leaf)."""
        contribs = self._contribs(n, acfa_round, acc["leaves"])
        if sorted(c["leaf"] for c in contribs) != sorted(acc["leaves"]):
            st["recovery"] = "missing leaves; waits for gossip"; st["accepted"] = None; return
        rec = self._issue(n, acfa_round, ctx, f, contribs, "recovered")
        st["rec"], st["cand"] = rec, self._candidate(n.w, rec)
        st["recovery"] = "recomputed on the quorum-signed leaf set: " + (
            "MATCH" if rec["state_root"] == acc["state_root"] else "STILL DIFFERENT")

    def _valid_cosigs(self, n, acfa_round, participants):
        out = []
        for e in self._entries(n, "cosig", acfa_round):
            body = {k: v for k, v in e.items() if k not in ("sig", "_key")}
            if e["node_id"] in participants and self._verify_json(e["node_id"], body, e["sig"]):
                out.append(e)
        return out

    def _accepted_root(self, n, acfa_round, participants, Qn):
        groups = {}
        for e in self._valid_cosigs(n, acfa_round, participants):
            k = (e["state_root"], e["output_root"], e["receipt_sha256"], e["candidate_sha256"], tuple(e["leaves"]))
            groups.setdefault(k, set()).add(e["node_id"])
        best = [(k, v) for k, v in groups.items() if len(v) >= Qn]
        if not best: return None
        assert len(best) == 1, "two roots reached quorum: impossible when 2Q > n + f (Quorum.quorum_intersection)"
        k, v = best[0]
        return {"state_root": k[0], "output_root": k[1], "receipt_sha256": k[2], "candidate_sha256": k[3],
                "leaves": list(k[4]), "signers": sorted(v)}

    def _cosig_report(self, n, acfa_round, participants, Qn, ctx=None, f=None):
        """Classify every co-signature against the quorum root. A signature on another root is
        STALE if that root is what ACFA gives on the leaf set the signer declared (it closed early on a
        partial set, which is normal under asynchrony; no trust penalty), and DIVERGENT if the signed
        root is not the deterministic result of the declared leaves (provable misbehaviour)."""
        cs = self._valid_cosigs(n, acfa_round, participants)
        acc = self._accepted_root(n, acfa_round, participants, Qn)
        by_root = {}
        for e in cs:
            by_root.setdefault(e["state_root"], set()).add(self.site_of(e["node_id"]))
        div, stale, memo = set(), set(), {}
        for e in cs:
            if not acc or e["state_root"] == acc["state_root"]: continue
            key = tuple(e["leaves"])
            if key == tuple(acc["leaves"]):
                expect = acc["state_root"]
            else:
                if key not in memo:
                    contribs = self._contribs(n, acfa_round, list(key))
                    memo[key] = (self._issue(n, acfa_round, ctx, f, contribs, "audit")["state_root"]
                                 if ctx is not None and sorted(c["leaf"] for c in contribs) == sorted(key) else None)
                expect = memo[key]
            (stale if expect == e["state_root"] else div).add(self.site_of(e["node_id"]))
        stale -= div
        return {"quorum": Qn, "n_participants": len(participants), "f": F_BYZ,
                "accepted_root": acc and acc["state_root"], "accepted_signers": acc and [self.site_of(i) for i in acc["signers"]],
                "signatures_by_root": {k: sorted(v) for k, v in by_root.items()},
                "divergent_signers": sorted(div), "stale_signers": sorted(stale - set(acc["signers"] if acc else [])) if acc else [],
                "cosigs": cs}

    # ------------------------------------------------------------------ eval + gate (every node)
    def _eval_phase(self, rnd, res, w_before, trace, tick_start):
        acfa_round = res["acfa_round"]; st = res["state"]
        live = [s for s in SITES if st[s]["accepted"] is not None]
        reporters = [s for s in live if self.nodes[s].node_id in res["participants"]]
        for s in live:
            n = self.nodes[s]; cand = st[s]["cand"]
            rep = {"kind": "eval", "site": s, "node_id": n.node_id, "round": rnd, "acfa_round": acfa_round,
                   "before": round(model.accuracy(w_before[s], n.Xte, n.yte), 4),
                   "after": round(model.accuracy(cand, n.Xte, n.yte), 4), "candidate_sha256": model.sha256(cand)}
            rep["sig"] = n.sign_json(rep)
            self._put(n, f"e/{acfa_round}/{n.node_id}", rep)
        inflight, sent = [], {}
        start = self.tick
        while self.tick - start < self.mesh["max_ticks"]:
            self._gossip_tick(self.tick - tick_start, inflight, sent, trace)
            if all({e["site"] for e in self._entries(self.nodes[s], "eval", acfa_round)} >= set(reporters) - set(self._silent())
                   for s in live) and self.tick - start >= 2:
                break
        gates, reports, commons = {}, {}, {}
        for s in live:
            n = self.nodes[s]
            reps = [e for e in self._entries(n, "eval", acfa_round)
                    if self._verify_json(e["node_id"], {k: v for k, v in e.items() if k not in ("sig", "_key")}, e["sig"])
                    and e["candidate_sha256"] == res["accepted"][s]["candidate_sha256"]]
            before = {e["site"]: e["before"] for e in reps}; after = {e["site"]: e["after"] for e in reps}
            before["common"] = round(model.accuracy(w_before[s], self.Xc, self.yc), 4)
            after["common"] = round(model.accuracy(st[s]["cand"], self.Xc, self.yc), 4)
            g = regression_gate(before, after)
            if len(reps) < res["Q"]:
                g["passed"] = False; g["insufficient_reports"] = len(reps)
            gates[s] = g
            reports[s] = [{k: v for k, v in e.items() if k != "_key"} for e in reps]
            commons[s] = (before["common"], after["common"])
        ref = self._ref()
        hon = [s for s in gates if self.nodes[s].mode == "honest"]
        return {"gates": gates, "gate": gates[ref], "reports": reports[ref], "common": commons[ref],
                "gate_identical_on_all_honest_nodes": len({json.dumps(gates[s], sort_keys=True) for s in hon}) == 1}

    def _ref(self):
        """Reference node for reporting: the first honest node (all honest nodes hold identical values)."""
        return next(s for s in SITES if self.nodes[s].mode == "honest")

    def _silent(self):
        """Nodes whose every outbound message so far was blocked (they are unheard, not waited for)."""
        return [s for s in SITES if self.nodes[s].mode == "leaky"]

    # ------------------------------------------------------------------ blind-mode dispute (peer to peer)
    def _dispute(self, rnd, res, participants, trace, tick_start):
        """Participants open (update, r, pair seeds) to ALL peers by gossip; every node checks every opening.
        Not zero-knowledge: peers learn the disputed attempt's (DP-noised) updates."""
        acfa_round = res["acfa_round"]
        for s, n in self.nodes.items():
            if n.node_id not in participants or getattr(n, "_opening", {}).get("acfa_round") != acfa_round: continue
            o = dict(n._opening, kind="opening", node_id=n.node_id)
            o["sig"] = n.sign_json(o)
            self._put(n, f"o/{acfa_round}/{n.node_id}", o)
        inflight, sent = [], {}
        for _ in range(self.mesh["max_ticks"]):
            self._gossip_tick(self.tick - tick_start, inflight, sent, trace)
            if not inflight and all(len(self._entries(self.nodes[s], "opening", acfa_round)) >=
                                    len([p for p in participants if self.site_of(p) not in self._silent()]) for s in SITES):
                break
        verdicts = {}
        for s, n in self.nodes.items():
            if n.mode != "honest": continue
            contribs = {e["node_id"]: e for e in self._entries(n, "contrib", acfa_round)}
            openings = {e["node_id"]: e for e in self._entries(n, "opening", acfa_round)}
            checks, violators = {}, []
            for i in participants:
                o, ce = openings.get(i), contribs.get(i)
                if o is None or ce is None:
                    checks[i] = {"opened": False}; violators.append(i); continue
                com_ok = self._verify_json(i, {"ctx": ce["c"]["ctx"], "commitment": ce["commitment"]}, ce["commitment_sig"]) \
                    and secagg.commit(ce["c"]["ctx"], i, o["x_q"], bytes.fromhex(o["r"])) == ce["commitment"]
                mask = secagg.recompute_mask(i, o["seeds"], len(o["x_q"]), res["R"])
                mask_ok = bool(np.array_equal(np.asarray(ce["c"]["tensor"]) - mask, np.asarray(o["x_q"])))
                seeds_ok = all(openings.get(int(j), {}).get("seeds", {}).get(str(i)) in (None, sd) for j, sd in o["seeds"].items())
                norm = float(np.linalg.norm(from_q16(o["x_q"])))
                ok = com_ok and mask_ok and seeds_ok and norm <= self.clip_S * (1 + 1e-6)
                checks[i] = {"opening_matches_signed_commitment": com_ok, "masked_minus_mask_equals_opening": mask_ok,
                             "pair_seeds_consistent": seeds_ok, "l2_norm": round(norm, 4),
                             "within_bound": norm <= self.clip_S * (1 + 1e-6)}
                if not ok: violators.append(i)
            verdicts[s] = {"checks": checks, "violators": sorted(violators)}
        v0 = next(iter(verdicts.values()))
        return {"round": rnd, "acfa_round": acfa_round, "checks": v0["checks"], "violators": v0["violators"],
                "violator_sites": [self.site_of(i) for i in v0["violators"]], "checked_by": sorted(verdicts),
                "identical_verdict_on_all_honest_nodes": len({json.dumps(v["violators"]) for v in verdicts.values()}) == 1}

    # ------------------------------------------------------------------ finish
    def _finish_round(self, rnd, res, attempts, disputes, trace, w_before, base_sha, t0, tick_start):
        failed = res.get("failed")
        st = res.get("state", {})
        node_roots, verify_runs, installed, receipt_sha, installed_on = {}, {}, {}, {}, []
        gate = res.get("eval", {}).get("gate") if not failed else {"passed": False, "failing": [], "deltas": {},
                                                                     "tol": GATE_TOL, "aborted": failed}
        if failed and "eval" not in res:
            gate = {"passed": False, "failing": [], "deltas": {}, "tol": GATE_TOL, "aborted": failed}
        rec = res.get("receipt")
        if not failed:
            for s, n in self.nodes.items():
                x = st[s]
                if x.get("accepted") is None: continue
                node_roots[s] = acfa.call("root", {"pki": self.pki_list, "round": res["acfa_round"],
                                                  "contributions": [c for c in self._contribs(n, res["acfa_round"], x["accepted"]["leaves"])
                                                                    if self._contrib_sig_ok(c)]})["state_root"]
                verify_runs[s] = acfa.verify(x["rec"]["receipt_path"], os.path.join(n.dir, "consortium.pki"),
                                             res["ctxs"][s], res["f"], node_roots[s])
                receipt_sha[s] = x["rec"]["receipt_sha256"]
            gates = res["eval"]["gates"]
            for s, n in self.nodes.items():
                if s in gates and gates[s]["passed"] and verify_runs.get(s, {}).get("exit_code") == 0:
                    installed_on.append(s)
                    n.w = st[s]["cand"].copy()
                    np.save(os.path.join(n.dir, "model", f"installed-r{rnd}.npy"), n.w)
            installed = {s: model.sha256(n.w) for s, n in self.nodes.items() if st[s].get("accepted") is not None}
        gate["rolled_back"] = not gate["passed"]
        honest = [s for s in SITES if self.nodes[s].mode == "honest"]
        self.w = self.nodes[honest[0]].w.copy()
        np.save(os.path.join(self.pub_dir, f"model-r{rnd}.npy"), self.w)
        rdir = os.path.join(self.pub_dir, f"round-{rnd}"); os.makedirs(rdir, exist_ok=True)
        if not failed:
            shutil.copy(st[self._ref()]["rec"]["receipt_path"], os.path.join(rdir, "receipt.acfa"))
            shutil.copy(st[self._ref()]["rec"]["redacted_path"], os.path.join(rdir, "receipt.redacted.acfa"))
        with open(os.path.join(rdir, "manifest.json"), "w") as fh:
            fh.write(json.dumps(res["manifest"], indent=1, sort_keys=True))
        if not failed:
            self.eval_reports += res["eval"]["reports"]
            res["_contribs"] = self._contribs(self.nodes[self._ref()], res["acfa_round"], res["accepted"][self._ref()]["leaves"])
        rr = {"round": rnd, "mode": self.mode, "manifest": res["manifest"], "ctx": res["ctx"],
              "ctx_identical_on_all_nodes": len(set(res.get("ctxs", {"x": 1}).values())) == 1,
              "acfa_round": res["acfa_round"], "attempts": attempts, "disputes": disputes,
              "blocked_nodes": sorted({e["src"] for e in self.egress.entries if e["dlp"] != "pass"}),
              "updates": res["updates"], "receipt": rec, "failed": failed,
              "receipt_path": os.path.join(rdir, "receipt.acfa"), "redacted_path": os.path.join(rdir, "receipt.redacted.acfa"),
              "node_state_roots": node_roots, "receipt_sha256_per_node": receipt_sha,
              "verify_exit_codes": {s: v["exit_code"] for s, v in verify_runs.items()}, "verify_runs": verify_runs,
              "installed_hashes": installed, "installed_on": installed_on, "candidate_sha256": model.sha256(st[self._ref()]["cand"]) if not failed else None,
              "model_sha256_after": model.sha256(self.w), "base_model_sha256": base_sha,
              "models_after": {s: model.sha256(n.w) for s, n in self.nodes.items()},
              "eval": {},
              "gate": gate, "gate_identical_on_all_honest_nodes": res.get("eval", {}).get("gate_identical_on_all_honest_nodes"),
              "cosign": {k: v for k, v in res.get("cosign", {}).items() if k != "cosigs"},
              "cosigs": res.get("cosign", {}).get("cosigs", []), "divergent_events": res.get("divergent_events", []),
              "privacy": {s: n.epsilon(DELTA) for s, n in self.nodes.items()},
              "secagg": res.get("secagg"),
              "mesh": {**self._mstats, "ticks": self.tick - tick_start, "partition": self.mesh.get("partition"),
                       "converged_tick": next((t["rel"] for t in trace if len({t[s] for s in SITES if s not in self._silent()}) == 1
                                               and t["rel"] >= 1), None),
                       "hash_trace": trace},
              "round_seconds": round(time.perf_counter() - t0, 3),
              "_contribs": res.get("_contribs", []),
              "_private": res["_private"], "_w_before": w_before[self._ref()]}
        if not failed:
            ev = {e["site"]: (e["before"], e["after"]) for e in res["eval"]["reports"]}
            rr["eval"] = {"before": {s: b for s, (b, a) in ev.items()} | {"common": res["eval"]["common"][0]},
                          "after": {s: a for s, (b, a) in ev.items()} | {"common": res["eval"]["common"][1]}}
        return rr

    # ------------------------------------------------------------------ peer trust (crdt-merge E4 TypedTrustScore)
    def _update_trust(self, rr):
        found = []
        rec = rr.get("receipt") or {}
        for a in rr["attempts"]:
            for i in a.get("convicted", []):
                found.append(("equivocation", self.site_of(i), f"two signed contributions, acfa_round {a['acfa_round']}"))
            for i in a.get("invalid_signature", []):
                found.append(("invalid-signature", self.site_of(i), f"contribution signature invalid, acfa_round {a['acfa_round']}"))
        for d in rr["disputes"]:
            for s in d["violator_sites"]:
                found.append(("norm-violation", s, f"dispute acfa_round {d['acfa_round']}"))
        for s in rr["cosign"].get("divergent_signers", []) or []:
            found.append(("divergent-root", s, f"signed a root other than the quorum root, round {rr['round']}"))
        for kind, target, detail in found:
            eid = hashlib.sha256(f"{kind}|{target}|{detail}".encode()).hexdigest()[:16]
            item = {"id": eid, "round": rr["round"], "kind": kind, "target": target, "detail": detail,
                    "dimension": EVIDENCE[kind][0], "amount": EVIDENCE[kind][1]}
            if eid not in {e["id"] for e in self.evidence}: self.evidence.append(item)
            for s, n in self.nodes.items():
                if n.mode != "honest" or s == target or eid in n.evidence_seen: continue
                n.trust[target] = n.trust[target].record_evidence(s, item["dimension"], item["amount"], _Proof(True))
                n.evidence_seen.add(eid)

    def trust_report(self):
        out = {}
        for s, n in self.nodes.items():
            if n.mode != "honest": continue
            out[s] = {t: {"overall": round(sc.overall_trust(), 4),
                          "dimensions_with_evidence": {d: round(sc.trust_for_dimension(d), 4) for d in sorted(
                              {e["dimension"] for e in self.evidence if e["target"] == t and e["id"] in n.evidence_seen})},
                          "quarantined": any(sc.trust_for_dimension(d) <= QUARANTINE_THRESHOLD for d in TRUST_DIMENSIONS)}
                      for t, sc in n.trust.items()}
        return {"engine": "crdt-merge TypedTrustScore (E4 public API: record_evidence, merge, trust_for_dimension)",
                "quarantine_threshold": QUARANTINE_THRESHOLD, "probation_trust": PROBATION_TRUST, "views": out, "evidence": list(self.evidence),
                "quarantined": self.quarantined()}

    def selection_counts(self):
        cnt = {s: {"selected": 0, "admitted": 0} for s in SITES}
        for r in self.rounds:
            rec = r.get("receipt") or {}
            for s in rec.get("selected_sites", []): cnt[s]["selected"] += 1
            for i in rec.get("admitted", []): cnt[self.site_of(i)]["admitted"] += 1
        return cnt

    # ------------------------------------------------------------------ evidence
    def build_bundle(self, path, attacks=None, shadows=None):
        from .bundle import build_bundle
        return build_bundle(self, path, attacks, shadows)

    def canary_scan(self):
        """Offline scan of EVERY peer-to-peer payload byte against EVERY node's canaries & PII markers, per link."""
        pats = {s: n.patterns() for s, n in self.nodes.items()}
        hits, per_link = [], {}
        for e, p in zip(self.egress.entries, self.egress.payloads):
            txt = p.decode("utf-8", "replace")
            L = per_link.setdefault(e["link"], {"messages": 0, "bytes": 0, "hits": 0, "delivered_hits": 0})
            L["messages"] += 1; L["bytes"] += len(p)
            for s, ps in pats.items():
                for pat in ps:
                    if pat in txt:
                        h = {"seq": e["seq"], "src": e["src"], "dst": e["dst"], "type": e["type"], "pattern_owner": s,
                             "pattern_sha256": hashlib.sha256(pat.encode()).hexdigest(), "delivered": e["dlp"] == "pass"}
                        hits.append(h); L["hits"] += 1; L["delivered_hits"] += h["delivered"]
        foreign = [h for h in hits if h["delivered"]]
        return {"payloads_scanned": len(self.egress.payloads), "bytes_scanned": sum(map(len, self.egress.payloads)),
                "hits": len(hits), "hits_delivered": sum(h["delivered"] for h in hits), "hit_list": hits,
                "per_link": per_link, "raw_data_received_by_any_peer": bool(foreign)}

    def verify_independent(self, round_index=-1):
        """An OFFLINE third party (not a network participant) re-verifies a node's receipt."""
        r = self.rounds[round_index]
        rpath = os.path.join(self.verifier_dir, f"receipt-r{r['round']}.acfa")
        shutil.copy(r["receipt_path"], rpath)
        exp = r["node_state_roots"][self._ref()]
        return acfa.verify(rpath, os.path.join(self.verifier_dir, "consortium.pki"), self.ctx_of(r["manifest"]),
                           r["manifest"]["aggregation"]["f"], exp)

    def check_installed_model(self, site, round_index=-1, path=None):
        r = self.rounds[round_index]; n = self.nodes[site]
        path = path or os.path.join(n.dir, "model", f"installed-r{r['round']}.npy")
        agg = acfa.call("resolve", {"pki": self.pki_list, "ctx": r["ctx"], "round": r["acfa_round"],
                                    "f": r["manifest"]["aggregation"]["f"], "receipt_path": r["receipt_path"]})["aggregate"]
        expected = (r["_w_before"].astype(np.float32) + from_q16(agg).astype(np.float32)).astype(np.float32)
        actual = np.load(path)
        return {"expected_sha256": model.sha256(expected), "artifact_sha256": model.sha256(actual),
                "match": model.sha256(expected) == model.sha256(actual)}

    def tamper(self, kind):
        r = next(x for x in reversed(self.rounds) if not x.get("failed") and x["gate"]["passed"])
        tdir = os.path.join(self.verifier_dir, "tamper"); os.makedirs(tdir, exist_ok=True)
        ctx = r["ctx"]; f = r["manifest"]["aggregation"]["f"]; exp = r["node_state_roots"][self._ref()]
        if kind == "receipt_byte":
            b = bytearray(open(r["receipt_path"], "rb").read()); off = len(b) // 2; b[off] ^= 0x01
            p = os.path.join(tdir, "receipt-flipped.acfa"); open(p, "wb").write(b)
            v = acfa.verify(p, os.path.join(self.verifier_dir, "consortium.pki"), ctx, f, exp)
            res = {"kind": kind, "what": f"flipped 1 bit at byte {off} of the receipt", "exit_code": v["exit_code"],
                   "detected": v["exit_code"] != 0, "verifier_output": (v["stdout"] + v["stderr"]).strip()[-600:]}
        elif kind == "model_swap":
            n = self.nodes[self._ref()]
            good = os.path.join(n.dir, "model", f"installed-r{r['round']}.npy")
            swapped = np.load(good).copy(); swapped[0] += np.float32(1e-3)
            p = os.path.join(tdir, "swapped-model.npy"); np.save(p, swapped)
            c = self.check_installed_model(self._ref(), self.rounds.index(r), path=p)
            res = {"kind": kind, "what": f"replaced {self._ref()}'s installed model artefact (one weight +1e-3)",
                   "detected": not c["match"], **c}
        elif kind == "wrong_key":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            fake = Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            lines = [f"2 {fake}\n" if l.startswith("2 ") else l for l in self.pki_text.splitlines(True)]
            p = os.path.join(tdir, "wrong-key.pki"); open(p, "w").write("".join(lines))
            v = acfa.verify(r["receipt_path"], p, ctx, f, exp)
            res = {"kind": kind, "what": "verifier given a PKI where DE's key is replaced by an attacker's key",
                   "exit_code": v["exit_code"], "detected": v["exit_code"] != 0,
                   "verifier_output": (v["stdout"] + v["stderr"]).strip()[-600:]}
        else:
            raise ValueError(kind)
        self.tamper_results[kind] = res
        return res

    def evaluation(self):
        honest = [s for s, n in self.nodes.items() if n.mode == "honest"]
        def accs(w):
            d = {s: round(model.accuracy(w, self.nodes[s].Xte, self.nodes[s].yte), 4) for s in SITES}
            d["common"] = round(model.accuracy(w, self.Xc, self.yc), 4)
            d["mean_honest_sites"] = round(float(np.mean([d[s] for s in honest])), 4)
            return d
        b, a = accs(self.w0), accs(self.w)
        return {"metric": "accuracy, 5-year CV event (synthetic)", "before": b, "after": a,
                "common": {"before": b["common"], "after": a["common"]},
                "rounds": [{"round": r["round"], "gate": r["gate"], "eval": r["eval"]} for r in self.rounds],
                "dp": self.dp_cfg is not None, "mode": self.mode,
                "selection_counts": self.selection_counts(),
                "regression_gate": {"rule": f"accept iff every site and the common set stay >= before - {GATE_TOL}",
                                    "applied_by": "every node, on the gossiped signed eval reports",
                                    "theorem": "Gate.gate_accept_no_regression"}}

    def privacy_budget(self):
        nodes = {}
        for s, n in self.nodes.items():
            if not self.dp_cfg:
                nodes[s] = {"dp": False}; continue
            q = self.dp_cfg["batch"] / len(n.ytr); cum, per = 0, []
            for st in n.steps_log:
                cum += st["steps"]
                per.append({"round": st["round"], "steps": st["steps"], "q": round(q, 6),
                            "epsilon_round_alone": round(dp.epsilon_for(q, self.dp_cfg["sigma"], st["steps"], DELTA), 4),
                            "epsilon_cumulative": round(dp.epsilon_for(q, self.dp_cfg["sigma"], cum, DELTA), 4)})
            nodes[s] = {"dp": True, "n_records": int(len(n.ytr)), "sampling_rate_q": round(q, 6), "per_round": per,
                        "epsilon_cumulative": per[-1]["epsilon_cumulative"] if per else 0.0}
        return {"mechanism": "DP-SGD (per-record clipping + Gaussian noise, Poisson sampling) per node, "
                             "then update-level L2 clip (post-processing)",
                "privacy_unit": "one patient record at one hospital", "accountant": "RDP of the subsampled Gaussian "
                "(Mironov et al. 2019), integer orders, Balle et al. 2020 conversion; cross-checked against opacus",
                "observers_covered": "every other hospital (all peers receive the DP-noised update) and the public",
                "params": self.dp_cfg, "delta": DELTA, "epsilon_budget": self.eps_cap,
                "budget_rule": "a round is refused if any node's projected cumulative epsilon would exceed the cap",
                "halted": self.halted, "nodes": nodes,
                "not_covered": "hospital-level (whole-dataset) privacy; repeated records (group privacy)"}

    def _contribs_of_dir(self, r):
        """The contribution set the quorum co-signed for this round (identical on every honest node)."""
        return r["_contribs"]

    def adversarial_report(self):
        rows = []
        for r in self.rounds:
            if r.get("failed"):
                rows.append({"round": r["round"], "failed": r["failed"]}); continue
            rows.append({"round": r["round"], "mode": self.mode, "attempts": r["attempts"], "disputes": r["disputes"],
                         "blocked_nodes": r["blocked_nodes"], "rule": f"krum f={r['manifest']['aggregation']['f']}",
                         "admitted": r["receipt"]["admitted"], "selected_sites": r["receipt"]["selected_sites"],
                         "dropped_sites": r["receipt"]["dropped_sites"], "convicted_sites": r["receipt"]["convicted_sites"],
                         "population_bound_met": r["receipt"]["population_bound_met"],
                         "cosign": r["cosign"], "divergent_events": r["divergent_events"],
                         "update_norms": {s: u["l2_norm_sent_float"] for s, u in r["updates"].items()},
                         "gate": r["gate"]})
        return {"adversary": {"site": ADVERSARY_SITE, "behaviour": self.adversary}, "leaky_node": self.leaky_node,
                "rounds": rows, "tamper_tests": self.tamper_results, "trust": self.trust_report(),
                "selection_counts": self.selection_counts(),
                "honest_limits": [
                    "multi-Krum keeps only m = n - f - 2 updates (2 of 5 with f=1): honest hospitals are dropped in "
                    "rotation by design of the rule, not because they misbehaved (see selection_counts)",
                    "robust rules are distance based: a within-norm attacker is not filtered",
                    "blind mode does NO per-update filtering: an in-bound sign-flip passes the norm check and is only "
                    "caught if it makes the regression gate fail, then by commit-and-open",
                    "commit-and-open reveals the disputed attempt's updates to every peer (not zero-knowledge)",
                    "liveness needs eventual delivery: a partition that never heals stalls the round (no model is "
                    "installed), it never splits the model (quorum intersection)"]}

    # ------------------------------------------------------------------ privacy attacks
    def _mi_sets(self, sites, k=600):
        Xm, ym, Xn, yn = [], [], [], []
        for s in sites:
            n = self.nodes[s]
            Xm.append(n.Xtr[data.N_CANARIES:data.N_CANARIES + k]); ym.append(n.ytr[data.N_CANARIES:data.N_CANARIES + k])
            Xn.append(n.Xte[:k]); yn.append(n.yte[:k])
        return np.concatenate(Xm), np.concatenate(ym), np.concatenate(Xn), np.concatenate(yn)

    def _mi_one(self, target="AT"):
        honest = [s for s, n in self.nodes.items() if n.mode == "honest"]
        Xm, ym, Xn, yn = self._mi_sets(honest)
        shared = attacks.mia_shared_model(self.w, Xm, ym, Xn, yn)
        r0 = self.rounds[0]
        if target not in r0["_private"] or self.nodes[target].mode != "honest":
            target = next(s for s in honest if s in r0["_private"])
        n = self.nodes[target]
        obs = r0["_private"][target]["observed_by_peers"]
        k = min(len(n.yte), len(n.ytr) - data.N_CANARIES)
        upd = attacks.mia_update(obs, r0["_w_before"], n.Xtr[data.N_CANARIES:data.N_CANARIES + k],
                                 n.ytr[data.N_CANARIES:data.N_CANARIES + k], n.Xte[:k], n.yte[:k])
        upd["target"] = f"{target} round-1 update as received by every peer ({self.mode} mode)"
        return {"shared_model": shared, "single_update": upd}

    def membership_inference(self, baseline=None, blind=None):
        eps = max([v for v in (n.epsilon(DELTA) for n in self.nodes.values()) if v is not None] or [float("inf")])
        out = {("dp" if self.dp_cfg else "no_dp"): self._mi_one()}
        if baseline is not None:
            out["dp" if baseline.dp_cfg else "no_dp"] = baseline._mi_one()
        if blind is not None:
            out["blind_no_dp"] = blind._mi_one()
        out["epsilon"] = round(eps, 4) if np.isfinite(eps) else None
        out["theoretical_max_advantage"] = round((np.exp(eps) - 1 + 2 * DELTA) / (np.exp(eps) + 1), 4) \
            if np.isfinite(eps) else 1.0
        out["interpretation"] = ("AUC 0.5 = attacker no better than a coin. The epsilon bound caps the advantage of "
                                 "ANY membership attack; the measured AUCs are for the specific attacks run here.")
        return out

    def inversion_attacks(self, target="CH"):
        n = self.nodes[target]; w = self.w0
        rng = np.random.default_rng(self.seed)
        x1, y1 = n.Xtr[data.N_CANARIES:data.N_CANARIES + 1], n.ytr[data.N_CANARIES:data.N_CANARIES + 1]
        g = model.per_example_grads(w, x1, y1)[0]
        single_clear = -0.1 * g
        gn = g / max(1.0, np.linalg.norm(g) / DEFAULT_DP["clip"])
        single_dp = -0.1 * (gn + rng.normal(0, DEFAULT_DP["sigma"] * DEFAULT_DP["clip"], g.shape))
        Rr = secagg.mask_range(5, BOUND_HEADROOM_Q)
        mask = secagg.prg_mask(os.urandom(32), len(g), Rr) - secagg.prg_mask(os.urandom(32), len(g), Rr)
        single_masked = from_q16(np.asarray(to_q16(single_clear)) + mask)
        r0 = self.rounds[0]["_private"][target]
        res = {
            "worst_case_single_record_clear": attacks.inversion_report(single_clear, n.Xtr, x1[0]),
            "worst_case_single_record_dp": attacks.inversion_report(single_dp, n.Xtr, x1[0]),
            "worst_case_single_record_masked": attacks.inversion_report(single_masked, n.Xtr, x1[0]),
            "intercepted_round1_update": attacks.inversion_report(r0["observed_by_peers"], n.Xtr),
        }
        for k, v in res.items():
            v["attacker_output_raw_units"] = [round(float(a), 2) for a in
                                             (np.array(v["reconstruction_std_units"]) * data.REF_STD + data.REF_MEAN)]
        res["features"] = data.FEATURES
        res["method"] = "analytic first-layer inversion x = dW1[:,j]/db1[j] (exact for one record, no noise)"
        return res

    def exposure_attack(self):
        rng = np.random.default_rng(self.seed + 5)
        Xs = np.concatenate([n.canary_Z for n in self.nodes.values() if n.mode == "honest"])
        ys = np.concatenate([n.canary_y for n in self.nodes.values() if n.mode == "honest"])
        return attacks.exposure(self.w, Xs, ys, rng, spread=data.CANARY_SPREAD)


# ---------------------------------------------------------------------- privacy attacks + shadows
def _shadow(fed, **over):
    import tempfile
    kw = dict(seed=fed.seed, mode=fed.mode, adversary=fed.adversary, dp=fed.dp_cfg is not None,
              dp_cfg=fed.dp_cfg, eps_cap=1e9, clip_S=fed.clip_S)
    kw.update(over)
    if kw["dp"] is False: kw["dp_cfg"] = None
    s = Federation(tempfile.mkdtemp(prefix="shadow-"), **kw)
    s.setup(); s.run_rounds(max(1, len(fed.rounds)))
    return s


def privacy_attacks(fed, shadows=None):
    """Every attack against the live federation and against unprotected shadow federations
    (same seed, same rounds), so a failure can be attributed to the protection."""
    sh = shadows or {}
    if "robust_nodp" not in sh: sh["robust_nodp"] = _shadow(fed, mode="robust", dp=False)
    if "blind_nodp" not in sh: sh["blind_nodp"] = _shadow(fed, mode="blind", dp=False)
    if "robust_dp" not in sh: sh["robust_dp"] = fed if (fed.mode == "robust" and fed.dp_cfg) else _shadow(fed, mode="robust", dp=True, dp_cfg=None)
    if "blind_dp" not in sh: sh["blind_dp"] = fed if (fed.mode == "blind" and fed.dp_cfg) else _shadow(fed, mode="blind", dp=True, dp_cfg=None)
    eps = max(n.epsilon(DELTA) or 0 for n in sh["robust_dp"].nodes.values())
    mi = {k: v._mi_one() for k, v in sh.items()}
    n = fed.nodes["AT"]; rng = np.random.default_rng(fed.seed)
    R = secagg.mask_range(5, BOUND_HEADROOM_Q)
    mf = lambda u: from_q16(np.asarray(to_q16(u)) + secagg.prg_mask(rng.bytes(32), len(u), R)
                            - secagg.prg_mask(rng.bytes(32), len(u), R))
    worst = attacks.mia_worst_case(fed.w0, n.Xtr[data.N_CANARIES:], n.ytr[data.N_CANARIES:], n.Xte, n.yte, rng,
                                   mask_fn=mf, sigma=DEFAULT_DP["sigma"], clip=DEFAULT_DP["clip"])
    worst["epsilon_of_one_unsampled_step"] = round(dp.epsilon_for(1.0, DEFAULT_DP["sigma"], 1, DELTA), 3)
    mia = {"federations": mi, "worst_case_tiny_batch": worst, "epsilon_live": round(eps, 4),
           "theoretical_max_advantage_at_epsilon": round((np.exp(eps) - 1 + 2 * DELTA) / (np.exp(eps) + 1), 4),
           "interpretation": "AUC 0.5 = coin flip. In this federation even the unprotected model barely leaks "
                             "(large cohorts, tiny model); the worst-case tiny-batch row shows the attack works "
                             "on an unprotected update and that DP and masking remove it."}
    inv = fed.inversion_attacks()
    for name in ("robust_nodp", "blind_nodp"):
        r0 = sh[name].rounds[0]["_private"]["CH"]
        inv[f"intercepted_round1_update_{name}"] = attacks.inversion_report(r0["observed_by_peers"], sh[name].nodes["CH"].Xtr)
    expo = {k: v.exposure_attack() for k, v in sh.items()}
    expo["interpretation"] = ("~1-2 bits = chance; 9.97 = fully exposed. This 738-parameter model shows no "
                              "measurable memorisation of single canary records WITH OR WITHOUT DP, so this test "
                              "does not by itself show DP is causal (the MIA worst case and inversion do). "
                              "DP still bounds exposure for any model: P(rank 1) <= e^eps/(n+1) + delta.")
    return {"membership_inference": mia, "gradient_inversion": inv, "canary_exposure": expo,
            "accuracy": {k: v.evaluation()["after"]["common"] for k, v in sh.items()}}, sh

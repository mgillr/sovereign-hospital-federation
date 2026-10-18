# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Pairwise-mask secure aggregation (Bonawitz et al. 2017 style, single-mask variant).

* X25519 key agreement per pair; HKDF-SHA256 derives a per-round pair seed bound to ctx.
* Masks are integers in [-R, R). Node i adds +m_ij for j > i and -m_ij for j < i, so the masks cancel
  EXACTLY in the integer sum (theorem `masks_cancel` in proofs/). No modular reduction is used, so
  ACFA's integer kernel computes the exact mean of the hidden updates from the masked vectors alone.
* Hiding is STATISTICAL, not perfect: for an update x and at least one mask unknown to the observer,
  TV(masked(x), masked(0)) <= ||x||_1 / (2R)  (adding independent noise cannot increase TV, and a
  uniform on [-R, R) shifted by t has TV |t|/(2R)). `hiding_bound` computes it per update.
* R is the largest value keeping every masked coordinate inside Q16.16's integer range.
* Dropouts: handled by RE-MASKING. If a participant's masked update has not reached a node by the close
  deadline, every node independently moves to the next attempt number (new ctx) over the surviving set,
  which all honest nodes derive from the same gossiped CRDT state; survivors mask afresh only with each
  other and the first attempt's masked vectors are discarded. (Bonawitz instead secret-shares seeds so
  survivors can unmask without a second upload; re-masking costs one more gossip round.) If the
  survivors disagree about who dropped (a partition), the co-signature quorum decides; without a
  quorum nothing is installed.
"""
import hashlib
import numpy as np
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

Q16_MAX = (1 << 31) - 1


def mask_range(n_participants: int, bound_q: int) -> int:
    """Largest R with (n-1)*R + bound_q <= 2^31 - 1."""
    return (Q16_MAX - bound_q) // max(1, n_participants - 1)


def new_x25519():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return sk, pk


def pair_seed(sk: X25519PrivateKey, peer_pk_hex: str, ctx_hex: str, i: int, j: int) -> bytes:
    shared = sk.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pk_hex)))
    a, b = sorted((i, j))
    info = b"shf-secagg-pair|" + bytes.fromhex(ctx_hex) + a.to_bytes(4, "big") + b.to_bytes(4, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def prg_mask(seed: bytes, d: int, R: int) -> np.ndarray:
    raw = hashlib.shake_256(b"shf-mask|" + seed).digest(8 * d)
    u = np.frombuffer(raw, dtype=">u8").astype(object)          # exact big ints
    return np.array([int(v % (2 * R)) - R for v in u], dtype=np.int64)   # modulo bias <= 2R/2^64


def mask_vector(x_q, node_id, sk, peers, ctx_hex, R):
    """peers: {node_id: x25519_pub_hex} for the OTHER participants of this attempt."""
    total = np.zeros(len(x_q), dtype=np.int64)
    seeds = {}
    for j, pk in sorted(peers.items()):
        s = pair_seed(sk, pk, ctx_hex, node_id, j)
        seeds[j] = s.hex()
        m = prg_mask(s, len(x_q), R)
        total += m if node_id < j else -m
    masked = np.asarray(x_q, dtype=np.int64) + total
    assert np.all(np.abs(masked) <= Q16_MAX)
    return [int(v) for v in masked], seeds


def recompute_mask(node_id, seeds_hex: dict, d, R):
    total = np.zeros(d, dtype=np.int64)
    for j, s in seeds_hex.items():
        m = prg_mask(bytes.fromhex(s), d, R)
        total += m if node_id < int(j) else -m
    return total


def hiding_bound(x_q, R) -> float:
    return float(np.sum(np.abs(np.asarray(x_q, dtype=np.float64))) / (2 * R))


def commit(ctx_hex, node_id, x_q, r: bytes) -> str:
    enc = "|".join(str(int(v)) for v in x_q).encode()
    return hashlib.sha256(b"shf-commit|" + bytes.fromhex(ctx_hex) + node_id.to_bytes(4, "big") +
                          hashlib.sha256(enc).digest() + r).hexdigest()

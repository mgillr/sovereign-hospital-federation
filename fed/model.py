# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""738-parameter MLP (20 -> 32 -> 2) in numpy. Canonical bytes: W1, b1, W2, b2 as float32 LE."""
import hashlib
import numpy as np

D_IN, H, D_OUT = 20, 32, 2
SHAPES = [(D_IN, H), (H,), (H, D_OUT), (D_OUT,)]
N_PARAMS = sum(int(np.prod(s)) for s in SHAPES)  # 738
assert N_PARAMS == 738


def init(seed: int) -> np.ndarray:
    r = np.random.default_rng(seed)
    w1 = r.normal(0, np.sqrt(2 / D_IN), (D_IN, H))
    w2 = r.normal(0, np.sqrt(1 / H), (H, D_OUT))
    return np.concatenate([w1.ravel(), np.zeros(H), w2.ravel(), np.zeros(D_OUT)]).astype(np.float32)


def unpack(w):
    out, i = [], 0
    for s in SHAPES:
        n = int(np.prod(s)); out.append(np.asarray(w[i:i + n], np.float64).reshape(s)); i += n
    return out


def canonical_bytes(w) -> bytes:
    return np.asarray(w, dtype="<f4").tobytes()


def sha256(w) -> str:
    return hashlib.sha256(canonical_bytes(w)).hexdigest()


def forward(w, X):
    W1, b1, W2, b2 = unpack(w)
    h = np.maximum(X @ W1 + b1, 0)
    z = h @ W2 + b2
    z = z - z.max(1, keepdims=True)
    p = np.exp(z); p /= p.sum(1, keepdims=True)
    return h, p


def predict_proba(w, X):
    return forward(w, X)[1][:, 1]


def losses(w, X, y):
    p = forward(w, X)[1]
    return -np.log(np.clip(p[np.arange(len(y)), y], 1e-12, 1))


def accuracy(w, X, y) -> float:
    return float((forward(w, X)[1].argmax(1) == y).mean())


def per_example_grads(w, X, y):
    """B x 738 matrix of per-example cross-entropy gradients (needed for DP-SGD clipping)."""
    W1, b1, W2, b2 = unpack(w)
    pre = X @ W1 + b1
    h = np.maximum(pre, 0)
    z = h @ W2 + b2
    z = z - z.max(1, keepdims=True)
    p = np.exp(z); p /= p.sum(1, keepdims=True)
    d = p.copy(); d[np.arange(len(y)), y] -= 1          # dL/dz, B x 2
    gW2 = h[:, :, None] * d[:, None, :]                  # B x 32 x 2
    dh = (d @ W2.T) * (pre > 0)                          # B x 32
    gW1 = X[:, :, None] * dh[:, None, :]                 # B x 20 x 32
    B = len(y)
    return np.concatenate([gW1.reshape(B, -1), dh, gW2.reshape(B, -1), d], axis=1)

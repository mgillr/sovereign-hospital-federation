# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Client-side differential privacy: DP-SGD (per-record clipping + Gaussian noise, Poisson sampling)
and a hand-written RDP accountant for the subsampled Gaussian mechanism (Mironov et al. 2019),
matched against opacus in the test-suite. Privacy unit: ONE PATIENT RECORD at one hospital."""
import math
import numpy as np
from . import model

ORDERS = list(range(2, 64)) + [80, 96, 128, 192, 256]  # integer orders: exact log-A series


def _log_add(a, b):
    if a == -np.inf: return b
    if b == -np.inf: return a
    m = max(a, b); return math.log1p(math.exp(min(a, b) - m)) + m


def _log_a_int(q, sigma, alpha):
    log_a = -np.inf
    for i in range(alpha + 1):
        c = math.log(math.comb(alpha, i)) + i * math.log(q) + (alpha - i) * math.log(1 - q)
        log_a = _log_add(log_a, c + (i * i - i) / (2 * sigma ** 2))
    return log_a


def rdp(q, sigma, steps, orders=ORDERS):
    out = []
    for a in orders:
        if q == 0: out.append(0.0); continue
        if q == 1.0: out.append(a / (2 * sigma ** 2) * steps); continue
        la = _log_a_int(q, sigma, int(a))
        out.append(la / (a - 1) * steps)
    return np.array(out)


def epsilon_for(q, sigma, steps, delta, orders=ORDERS):
    """(eps, delta) from RDP with the conversion of Balle et al. 2020 (same as opacus)."""
    r = rdp(q, sigma, steps, orders)
    a = np.array(orders, float)
    eps = r - (np.log(delta) + np.log(a)) / (a - 1) + np.log((a - 1) / a)
    eps = np.where(np.isnan(eps), np.inf, eps)
    return float(np.min(eps))


def dp_sgd_local(w0, X, y, *, epochs, batch, lr, clip, sigma, rng):
    """Returns (delta_w, steps, q). Poisson sampling with rate q = batch/N; noise std sigma*clip
    added to the SUM of clipped per-record gradients; divided by the expected batch size."""
    w = np.asarray(w0, np.float64).copy()
    N = len(y); q = batch / N; steps = int(round(epochs / q))
    for _ in range(steps):
        mask = rng.random(N) < q
        g_sum = np.zeros_like(w)
        if mask.any():
            G = model.per_example_grads(w, X[mask], y[mask])
            norms = np.linalg.norm(G, axis=1, keepdims=True)
            G = G / np.maximum(1.0, norms / clip)
            g_sum = G.sum(0)
        g = (g_sum + rng.normal(0, sigma * clip, size=w.shape)) / (q * N)
        w -= lr * g
    return (w - w0).astype(np.float64), steps, q


def sgd_local(w0, X, y, *, epochs, batch, lr, rng):
    """Non-private baseline with the same schedule (no clipping, no noise)."""
    w = np.asarray(w0, np.float64).copy(); N = len(y); q = batch / N; steps = int(round(epochs / q))
    for _ in range(steps):
        idx = rng.choice(N, size=batch, replace=False)
        w -= lr * model.per_example_grads(w, X[idx], y[idx]).mean(0)
    return (w - w0).astype(np.float64), steps, q

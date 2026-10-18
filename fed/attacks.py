# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Privacy attacks used as evidence. Each is run against protected AND unprotected variants so the
protection is shown to be the cause of failure."""
import numpy as np
from . import model


def auc(pos, neg):
    """P(score_member > score_nonmember), ties count 1/2 (Mann-Whitney)."""
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    allv = np.concatenate([pos, neg]); order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv)); ranks[order] = np.arange(1, len(allv) + 1)
    # average ranks for ties
    _, inv, cnt = np.unique(allv, return_inverse=True, return_counts=True)
    sums = np.zeros(len(cnt)); np.add.at(sums, inv, ranks); ranks = (sums / cnt)[inv]
    return float((ranks[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def advantage(pos, neg):
    thr = np.unique(np.concatenate([pos, neg]))
    best = 0.0
    for t in thr[:: max(1, len(thr) // 400)]:
        best = max(best, float(np.mean(np.asarray(pos) >= t) - np.mean(np.asarray(neg) >= t)))
    return best


def mia_shared_model(w, Xm, ym, Xn, yn):
    """Loss-threshold attack (Yeom et al. 2018): lower loss => member."""
    sm, sn = -model.losses(w, Xm, ym), -model.losses(w, Xn, yn)
    return {"attack": "loss-threshold on shared model", "auc": round(auc(sm, sn), 4),
            "advantage": round(advantage(sm, sn), 4), "n_members": len(ym), "n_nonmembers": len(yn)}


def mia_update(delta, w_base, Xm, ym, Xn, yn):
    """Gradient-alignment attack on an intercepted update: members' gradients align with -delta."""
    d = np.asarray(delta, np.float64)
    def s(X, y):
        G = model.per_example_grads(w_base, X, y)
        return -(G @ d) / (np.linalg.norm(G, axis=1) * (np.linalg.norm(d) + 1e-12) + 1e-12)
    sm, sn = s(Xm, ym), s(Xn, yn)
    return {"attack": "gradient-alignment on intercepted update", "auc": round(auc(sm, sn), 4),
            "advantage": round(advantage(sm, sn), 4), "n_members": len(ym), "n_nonmembers": len(yn)}


def invert(delta):
    """Analytic gradient inversion for a first dense layer (Phong et al. 2017; Geiping et al. 2020):
    dL/dW1[:, j] = x * dL/db1[j], so x = dW1[:, j] / db1[j]. Exact for a single-record gradient."""
    W1, b1, _, _ = model.unpack(np.asarray(delta, np.float64))
    j = int(np.argmax(np.abs(b1)))
    if abs(b1[j]) < 1e-15:
        return np.zeros(W1.shape[0])
    return W1[:, j] / b1[j]


def inversion_report(delta, X_private, true_record=None, threshold=0.25):
    xh = invert(delta)
    dists = np.linalg.norm(X_private - xh, axis=1) / np.sqrt(X_private.shape[1])
    out = {"reconstruction_std_units": [round(float(v), 4) for v in xh],
           "nearest_private_record_rmse": round(float(dists.min()), 4),
           "success_threshold_rmse": threshold}
    if true_record is not None:
        out["true_record_std_units"] = [round(float(v), 4) for v in true_record]
        out["rmse_to_true_record"] = round(float(np.linalg.norm(xh - true_record) / np.sqrt(len(xh))), 6)
        out["success"] = bool(out["rmse_to_true_record"] < threshold)
    else:
        out["success"] = bool(dists.min() < threshold)
    return out


def margin(w, X, y):
    W1, b1, W2, b2 = model.unpack(np.asarray(w, np.float64))
    z = np.maximum(X @ W1 + b1, 0) @ W2 + b2
    return z[np.arange(len(y)), y] - z[np.arange(len(y)), 1 - y]


def exposure(w, canaries_X, canaries_y, rng, n_candidates=1000, spread=3.0):
    """Carlini et al. 2019 exposure adapted to tabular canaries: rank each planted outlier record by
    model loss among n_candidates fresh outliers from the same distribution with the same label.
    exposure = log2(n+1) - log2(rank). ~1 bit = no memorisation; log2(n+1) ~ 10 bits = fully exposed."""
    out = []
    for x, y in zip(canaries_X, canaries_y):
        C = rng.normal(0, spread, size=(n_candidates, len(x)))
        # rank by logit margin for the canary label (no softmax saturation, so no artificial ties)
        lc = -margin(w, x[None, :], np.array([y]))[0]
        lo = -margin(w, C, np.full(n_candidates, y))
        rank = 1 + int(np.sum(lo < lc)) + int(np.sum(lo == lc)) // 2
        out.append(np.log2(n_candidates + 1) - np.log2(rank))
    return {"metric": "exposure (bits)", "mean": round(float(np.mean(out)), 3), "max": round(float(np.max(out)), 3),
            "max_possible": round(float(np.log2(n_candidates + 1)), 3), "n_canaries": len(out)}


def mia_worst_case(w, X_pool, y_pool, X_out, y_out, rng, *, batch=4, trials=100, lr=0.1, clip=1.0, sigma=2.0,
                   mask_fn=None):
    """Worst case for update-level membership inference: one local step on a tiny batch.
    Returns AUCs for the update in the clear, with DP (clip + Gaussian), and masked (secure aggregation)."""
    sc = {"clear": ([], []), "dp": ([], []), "masked": ([], [])}
    for _ in range(trials):
        idx = rng.choice(len(y_pool), batch, replace=False); jdx = rng.choice(len(y_out), batch, replace=False)
        G = model.per_example_grads(w, X_pool[idx], y_pool[idx])
        clear = -lr * G.mean(0)
        Gc = G / np.maximum(1.0, np.linalg.norm(G, axis=1, keepdims=True) / clip)
        dpu = -lr * (Gc.sum(0) + rng.normal(0, sigma * clip, G.shape[1])) / batch
        masked = mask_fn(clear) if mask_fn else clear
        Gm, Gn = G, model.per_example_grads(w, X_out[jdx], y_out[jdx])
        for k, u in (("clear", clear), ("dp", dpu), ("masked", masked)):
            f = lambda GG: -(GG @ u) / (np.linalg.norm(GG, axis=1) * (np.linalg.norm(u) + 1e-12) + 1e-12)
            sc[k][0].extend(f(Gm)); sc[k][1].extend(f(Gn))
    return {k: {"auc": round(auc(*v), 4), "advantage": round(advantage(*v), 4)} for k, v in sc.items()} | {
        "setting": f"one SGD step on {batch} records, {trials} trials, gradient-alignment attack"}

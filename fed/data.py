# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
"""Synthetic patient tables. Every value is generated; no real patient is represented.
Each site gets a different population, its own held-out split and planted CANARY rows whose
identifiers must never appear in anything that leaves the node."""
import csv, hashlib, os, secrets
import numpy as np

FEATURES = ["age", "sex", "bmi", "sbp", "dbp", "heart_rate", "glucose", "hba1c", "chol_total", "ldl",
            "hdl", "triglycerides", "creatinine", "egfr", "crp", "smoker", "diabetes_hx", "hypertension_hx",
            "prior_mi", "statin"]
# Public reference scaler, published in the model manifest so no site has to share statistics.
REF_MEAN = np.array([60, .5, 27, 135, 82, 74, 105, 5.9, 205, 125, 52, 150, 1.0, 80, 3, .25, .15, .35, .08, .3])
REF_STD = np.array([12, .5, 4.5, 18, 10, 11, 25, 0.9, 38, 32, 14, 70, .3, 18, 3, .43, .36, .48, .27, .46])
JURISDICTION = {"CH": "CH nFADP", "DE": "EU GDPR (DE BDSG)", "FR": "EU GDPR (FR Loi Informatique et Libertés)",
                "AT": "EU GDPR (AT DSG)", "IT": "EU GDPR (IT Codice privacy)"}
COORDS = {"CH": (46.95, 7.44), "DE": (50.73, 7.10), "FR": (45.76, 4.84), "AT": (48.21, 16.37), "IT": (45.46, 9.19)}
# Site populations: (age shift, bmi shift, smoker rate, diabetes rate, n_train, n_test)
SITES = {
    "CH": dict(node_id=1, country="Switzerland", age=4, bmi=-1.0, smoke=.20, diab=.10, n=2400),
    "DE": dict(node_id=2, country="Germany", age=1, bmi=1.5, smoke=.25, diab=.16, n=2400),
    "FR": dict(node_id=3, country="France", age=-1, bmi=-0.5, smoke=.33, diab=.12, n=2400),
    "AT": dict(node_id=4, country="Austria", age=2, bmi=0.8, smoke=.24, diab=.14, n=1200),
    "IT": dict(node_id=5, country="Italy", age=3, bmi=0.2, smoke=.22, diab=.13, n=2000),
}
N_CANARIES = 10
CANARY_SPREAD = 3.0
_TRUE_W = np.array([.9, .3, .35, .5, .1, .15, .3, .45, .2, .4, -.45, .15, .2, -.3, .25, .6, .5, .35, .7, -.25])


def sample(site, n, rng):
    p = SITES[site]
    age = rng.normal(60 + p["age"], 12, n).clip(25, 95)
    sex = rng.integers(0, 2, n)
    bmi = rng.normal(27 + p["bmi"], 4.5, n).clip(16, 50)
    smoker = (rng.random(n) < p["smoke"]).astype(float)
    diab = (rng.random(n) < p["diab"]).astype(float)
    sbp = rng.normal(130 + 0.4 * (age - 60) + 0.8 * (bmi - 27), 15, n)
    dbp = rng.normal(80 + 0.3 * (bmi - 27), 9, n)
    hr = rng.normal(74 + 3 * smoker, 10, n)
    glucose = rng.normal(98 + 45 * diab + 1.2 * (bmi - 27), 15, n)
    hba1c = rng.normal(5.6 + 1.6 * diab, .5, n)
    chol = rng.normal(205, 36, n); ldl = rng.normal(0.62 * chol, 15, n)
    hdl = rng.normal(55 - 6 * smoker - .6 * (bmi - 27), 12, n)
    trig = rng.lognormal(np.log(140) + .02 * (bmi - 27), .4, n)
    creat = rng.normal(1.0 + .006 * (age - 60), .25, n).clip(.4, 4)
    egfr = (140 - age) * 0.9 / creat.clip(.5)
    crp = rng.lognormal(np.log(2.5) + .3 * smoker, .7, n)
    htn = ((sbp > 140) | (rng.random(n) < .1)).astype(float)
    prior = (rng.random(n) < .05 + .002 * (age - 60).clip(0)).astype(float)
    statin = ((ldl > 140) & (rng.random(n) < .6)).astype(float)
    X = np.stack([age, sex, bmi, sbp, dbp, hr, glucose, hba1c, chol, ldl, hdl, trig, creat, egfr, crp,
                  smoker, diab, htn, prior, statin], 1)
    Z = (X - REF_MEAN) / REF_STD
    logit = Z @ _TRUE_W + 0.6 * Z[:, 0] * Z[:, 15] + 0.5 * np.maximum(Z[:, 6], 0) ** 2 - 1.1
    y = (rng.random(n) < 1 / (1 + np.exp(-logit))).astype(int)
    return X, y


def standardize(X):
    return ((X - REF_MEAN) / REF_STD).astype(np.float64)


def write_site(site, data_dir, seed):
    """Writes patients_train.csv / patients_test.csv with PII-like columns and canary rows.
    Returns the list of canary strings (kept inside the node; only their hashes are published)."""
    os.makedirs(data_dir, exist_ok=True)
    rng = np.random.default_rng(seed)
    p = SITES[site]
    canaries = [f"CANARY-{site}-{secrets.token_hex(6)}" for _ in range(N_CANARIES)]
    crng = np.random.default_rng([seed, 999])
    canary_Z = crng.normal(0, CANARY_SPREAD, size=(N_CANARIES, len(FEATURES)))
    canary_y = crng.integers(0, 2, N_CANARIES)
    out = {}
    for split, n in (("train", p["n"]), ("test", 600)):
        X, y = sample(site, n, rng)
        if split == "train":
            X[:N_CANARIES] = canary_Z * REF_STD + REF_MEAN; y[:N_CANARIES] = canary_y
        path = os.path.join(data_dir, f"patients_{split}.csv")
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["patient_id", "full_name", "date_of_birth"] + FEATURES + ["cv_event_5y"])
            for i in range(n):
                pid = f"{site}-{split[:2].upper()}-{i:06d}"
                name = f"Synthetic Patient {site}{i:06d}"
                if split == "train" and i < len(canaries):
                    pid = canaries[i]; name = f"Canary Person {canaries[i]}"
                w.writerow([pid, name, f"19{40 + i % 50}-0{1 + i % 9}-1{i % 9}"] +
                           [f"{v:.4f}" for v in X[i]] + [int(y[i])])
        out[split] = path
    return canaries, out, canary_Z, canary_y


def load(path):
    with open(path) as fh:
        r = csv.reader(fh); header = next(r); rows = list(r)
    ids = [row[0] for row in rows]
    X = np.array([[float(v) for v in row[3:3 + len(FEATURES)]] for row in rows])
    y = np.array([int(row[-1]) for row in rows])
    return ids, standardize(X), y


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 16), b""): h.update(b)
    return h.hexdigest()


def common_benchmark(seed, n_per_site=300):
    """Public synthetic benchmark (no site's records): a fresh draw from every site's population."""
    rng = np.random.default_rng(seed)
    Xs, ys = zip(*[sample(s, n_per_site, rng) for s in SITES])
    return standardize(np.concatenate(Xs)), np.concatenate(ys)

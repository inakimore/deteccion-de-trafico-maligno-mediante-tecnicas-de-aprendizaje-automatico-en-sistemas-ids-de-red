#!/usr/bin/env python3
"""Estado del arte vs nuestro pipeline: ¿mejora el ensemble a lo que tenemos? (TFG)

POR QUE ESTE EXPERIMENTO
------------------------
El estado del arte (ver `Machine Learning en NIDS.pdf` y el README) sostiene dos
afirmaciones concretas y COMPROBABLES sobre nuestros datos:

  (A) "La supremacia del Ensemble Learning": Random Forest, XGBoost y LightGBM
      dominan sistematicamente la deteccion sobre caracteristicas de flujo, con
      precisiones cercanas al 99,9% intra-dataset, y XGBoost obtiene la mayor
      tasa de acierto (0.9367) al exponerse a flujos cruzados de CSE-CIC-IDS2018.

  (B) El "aprendizaje por atajos" (shortcut learning) de Engelen et al.
      (WTMC2021): si no se eliminan IPs y puertos efimeros, el clasificador
      memoriza la topologia del laboratorio -las IPs del atacante y la victima-
      y obtiene 99,99% en el laboratorio "fracasando por completo al generalizar
      en redes externas".

Este script contrasta ambas contra nuestro pipeline, en nuestros dias y con
nuestro protocolo. Nuestro clasificador de referencia es el MLP de
`hybrid_compare.make_pipeline()`, que es lo que usan todas las evaluaciones del
trabajo.

MODOS
-----
  --day A            dentro del dia: CV 5-Fold, MLP vs RF vs XGBoost por vista.
  --train-day A --test-day B   entre dias: entrena en A y evalua en B, que es
                     donde el trabajo ya demostro (HALLAZGO 14) que la accuracy
                     con umbral fijo engana; por eso se reporta TAMBIEN el AUC.

La vista `meta+FUGA` reproduce deliberadamente el error que denuncia Engelen:
anade el puerto de origen efimero y los octetos de las IPs. Sirve para medir el
atajo, no para usarlo.

Uso:
    python scripts/zeek/sota_baselines.py --day Friday-02-03-2018 --service http
    python scripts/zeek/sota_baselines.py --train-day Friday-16-02-2018 \\
        --test-day Tuesday-20-02-2018 --service http
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import build_burst_features  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


def ip_octetos(arr) -> np.ndarray:
    """Los 4 octetos de cada IP como enteros. ESTO ES LA FUGA: identifica al host."""
    out = np.zeros((len(arr), 4), dtype=np.float32)
    for i, s in enumerate(arr.astype(str)):
        partes = s.split(".")
        if len(partes) == 4:
            try:
                out[i] = [int(x) for x in partes]
            except ValueError:
                pass
    return out


def construir_vistas(d, sel, burst):
    """Las cuatro vistas que se comparan."""
    meta = build_meta_features(d, sel)
    payload = np.hstack([d["X_hist"][sel],
                         (d["entropy"][sel] / 8.0).reshape(-1, 1)]).astype(np.float32)
    meta_raf = np.hstack([meta, burst[sel]]).astype(np.float32)
    # La vista con FUGA: puerto de origen efimero + octetos de ambas IPs.
    fuga = np.hstack([
        meta,
        d["orig_p"][sel].astype(np.float32).reshape(-1, 1),
        ip_octetos(d["orig_h"][sel]),
        ip_octetos(d["resp_h"][sel]),
    ]).astype(np.float32)
    return {"payload-hist": payload, "metadatos": meta,
            "meta+rafaga": meta_raf, "meta+FUGA (IPs/puertos)": fuga}


def modelos():
    """Nuestro MLP frente a los dos ensembles que el estado del arte declara superiores."""
    from sklearn.ensemble import RandomForestClassifier
    from xgboost import XGBClassifier
    return {
        "MLP (nuestro)": make_pipeline(),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1, n_jobs=-1,
            tree_method="hist", eval_metric="logloss", random_state=RANDOM_STATE),
    }


def subconjunto(d, port, service, cap, rng):
    from imblearn.under_sampling import RandomUnderSampler
    y_raw = d["y"].astype(str)
    svc = service_selection(d, port=port, service=service)
    etiquetas = sorted(set(y_raw[svc & (y_raw != "Benign")]))
    if not etiquetas:
        sys.exit(f"[ERROR] Sin ataques en {selection_label(port, service)}")
    y_bin = np.where(np.isin(y_raw, etiquetas), 1, np.where(y_raw == "Benign", 0, -1))
    mask = svc & (y_bin >= 0)
    idx = np.nonzero(mask)[0]
    sel_l, _ = RandomUnderSampler(random_state=RANDOM_STATE).fit_resample(
        np.arange(len(idx)).reshape(-1, 1), y_bin[idx])
    sel = idx[sel_l.ravel()]
    y = y_bin[sel]
    if cap > 0:
        keep = np.concatenate([
            (lambda c: rng.choice(c, cap, replace=False) if len(c) > cap else c)(
                np.nonzero(y == k)[0]) for k in (0, 1)])
        keep.sort(); sel, y = sel[keep], y[keep]
    return sel, y, etiquetas


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", default=None)
    ap.add_argument("--train-day", default=None)
    ap.add_argument("--test-day", default=None)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default=None)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.metrics import f1_score, roc_auc_score, recall_score

    rng = np.random.default_rng(RANDOM_STATE)
    MODELS_DIR.mkdir(exist_ok=True)

    # ------------------------------------------------------ dentro del dia --
    if args.day:
        d = load_dataset(args.day)
        print(f"== Estado del arte vs nuestro pipeline: {args.day} ==")
        print(f"   {selection_label(args.port, args.service)}\n")
        burst = build_burst_features(d)
        sel, y, etiquetas = subconjunto(d, args.port, args.service, args.cap, rng)
        print(f"Ataques: {etiquetas}")
        print(f"Balance -> ataque {int(y.sum())} / benigno {int((y == 0).sum())}\n")
        vistas = construir_vistas(d, sel, burst)

        cv = StratifiedKFold(n_splits=args.folds, shuffle=True,
                             random_state=RANDOM_STATE)
        tabla = {}
        for nv, X in vistas.items():
            tabla[nv] = {}
            for nm, clf in modelos().items():
                yp = cross_val_predict(clf, X, y, cv=cv, n_jobs=1)
                tabla[nv][nm] = float(f1_score(y, yp, average="macro"))
            fila = "  ".join(f"{nm} {v:.4f}" for nm, v in tabla[nv].items())
            print(f"{nv:26s} {fila}")

        out = MODELS_DIR / f"phase3_sota_{args.day}.json"
        out.write_text(json.dumps({"dia": args.day, "macro_f1": tabla},
                                  indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nResumen -> {out}")
        return

    # -------------------------------------------------------- entre dias ----
    if not (args.train_day and args.test_day):
        sys.exit("[ERROR] Usa --day, o bien --train-day y --test-day")

    d_tr, d_te = load_dataset(args.train_day), load_dataset(args.test_day)
    print(f"== Transferencia entre dias: {args.train_day} -> {args.test_day} ==\n")
    b_tr, b_te = build_burst_features(d_tr), build_burst_features(d_te)
    s_tr, y_tr, _ = subconjunto(d_tr, args.port, args.service, args.cap, rng)
    s_te, y_te, _ = subconjunto(d_te, args.port, args.service, args.cap, rng)
    v_tr = construir_vistas(d_tr, s_tr, b_tr)
    v_te = construir_vistas(d_te, s_te, b_te)

    tabla = {}
    for nv in v_tr:
        tabla[nv] = {}
        for nm, clf in modelos().items():
            clf.fit(v_tr[nv], y_tr)
            yp = clf.predict(v_te[nv])
            f1 = float(f1_score(y_te, yp, average="macro"))
            rec = float(recall_score(y_te, yp, pos_label=1, zero_division=0))
            try:
                s = clf.predict_proba(v_te[nv])[:, 1]
                auc = float(roc_auc_score(y_te, s))
            except Exception:
                auc = float("nan")
            tabla[nv][nm] = {"macro_f1": f1, "recall_atk": rec, "auc_roc": auc}
        fila = "  ".join(f"{nm} F1 {m['macro_f1']:.4f}/AUC {m['auc_roc']:.4f}"
                         for nm, m in tabla[nv].items())
        print(f"{nv:26s} {fila}")

    out = MODELS_DIR / (f"phase3_sota_cruzado_{args.train_day}__{args.test_day}.json")
    out.write_text(json.dumps({"train": args.train_day, "test": args.test_day,
                               "resultados": tabla}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

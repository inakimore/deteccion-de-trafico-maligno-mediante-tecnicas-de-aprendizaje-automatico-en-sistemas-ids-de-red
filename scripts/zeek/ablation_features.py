#!/usr/bin/env python3
"""Ablacion: ¿que caracteristica lleva realmente la senal? (TFG, Fase 3)

POR QUE ESTE EXPERIMENTO
------------------------
El trabajo afirma dos cosas sobre sus caracteristicas conductuales que hasta
ahora NO se habian comprobado por separado:

  (1) Que la rafaga (conexiones por ventana y origen) es lo que resuelve el
      regimen volumetrico concentrado.
  (2) Que dentro de las seis caracteristicas de inter-arribo, `cv_local` -el
      coeficiente de variacion, ~0 en un metronomo- es "LA feature del
      beaconing". Eso se escribio como interpretacion, no como medida.

Una ablacion lo decide: se quita un grupo (o una sola caracteristica) y se mira
cuanto cae el resultado. Si al quitar `cv_local` no pasa nada, la afirmacion (2)
era una historia bonita y hay que corregirla.

Se reportan dos ablaciones:
  - POR GRUPOS: metadatos / +rafaga / +inter-arribo / solo inter-arribo.
  - UNA A UNA dentro del inter-arribo: se elimina cada caracteristica y se mide
    la caida (leave-one-out).

Uso:
    python scripts/zeek/ablation_features.py --day Friday-02-03-2018 --service http
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
from interarrival_eval import build_interarrival_features, N_FEATS  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

NOMBRES_INTER = ["dt_prev", "dt_next", "media_local", "cv_local",
                 "regularidad", "frac_cerca_mediana"]


def cv_f1(X, y, folds, seed):
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    return float(np.mean(cross_val_score(make_pipeline(), X, y, cv=cv,
                                         scoring="f1_macro", n_jobs=1)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default=None)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    from imblearn.under_sampling import RandomUnderSampler
    rng = np.random.default_rng(RANDOM_STATE)
    MODELS_DIR.mkdir(exist_ok=True)

    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    svc = service_selection(d, port=args.port, service=args.service)
    etiquetas = sorted(set(y_raw[svc & (y_raw != "Benign")]))
    y_bin = np.where(np.isin(y_raw, etiquetas), 1, np.where(y_raw == "Benign", 0, -1))
    idx = np.nonzero(svc & (y_bin >= 0))[0]
    sel_l, _ = RandomUnderSampler(random_state=RANDOM_STATE).fit_resample(
        np.arange(len(idx)).reshape(-1, 1), y_bin[idx])
    sel = idx[sel_l.ravel()]
    y = y_bin[sel]
    if args.cap > 0:
        keep = np.concatenate([
            (lambda c: rng.choice(c, args.cap, replace=False) if len(c) > args.cap else c)(
                np.nonzero(y == k)[0]) for k in (0, 1)])
        keep.sort(); sel, y = sel[keep], y[keep]

    print(f"== Ablacion: {args.day} ({selection_label(args.port, args.service)}) ==")
    print(f"   ataques {etiquetas} | {int(y.sum())} / {int((y == 0).sum())}\n")
    print("Calculando rafaga e inter-arribo sobre todo el dataset...")
    meta = build_meta_features(d, sel).astype(np.float32)
    burst = build_burst_features(d)[sel].astype(np.float32)
    inter = build_interarrival_features(d)[sel].astype(np.float32)

    grupos = {
        "metadatos": meta,
        "metadatos + rafaga": np.hstack([meta, burst]),
        "metadatos + inter-arribo": np.hstack([meta, inter]),
        "metadatos + rafaga + inter": np.hstack([meta, burst, inter]),
        "inter-arribo SOLO": inter,
        "rafaga SOLA": burst,
    }
    print("\n=== Ablacion POR GRUPOS (macro-F1, CV out-of-fold) ===")
    por_grupo = {}
    for nombre, X in grupos.items():
        por_grupo[nombre] = cv_f1(X, y, args.folds, RANDOM_STATE)
        print(f"  {nombre:28s} {por_grupo[nombre]:.4f}   ({X.shape[1]} caract.)")

    print("\n=== Ablacion UNA A UNA dentro del inter-arribo (leave-one-out) ===")
    completo = cv_f1(inter, y, args.folds, RANDOM_STATE)
    print(f"  {'las 6 juntas':28s} {completo:.4f}")
    loo = {}
    for i, nom in enumerate(NOMBRES_INTER):
        Xi = np.delete(inter, i, axis=1)
        f = cv_f1(Xi, y, args.folds, RANDOM_STATE)
        loo[nom] = {"sin_ella": f, "caida": completo - f}
        marca = "  <-- imprescindible" if completo - f > 0.02 else ""
        print(f"  sin {nom:24s} {f:.4f}   caida {completo - f:+.4f}{marca}")

    print("\n=== Cada caracteristica de inter-arribo POR SI SOLA ===")
    sola = {}
    for i, nom in enumerate(NOMBRES_INTER):
        f = cv_f1(inter[:, [i]], y, args.folds, RANDOM_STATE)
        sola[nom] = f
        print(f"  solo {nom:23s} {f:.4f}")

    out = MODELS_DIR / f"phase3_ablacion_{args.day}.json"
    out.write_text(json.dumps({"dia": args.day, "por_grupo": por_grupo,
                               "inter_completo": completo,
                               "leave_one_out": loo, "cada_una_sola": sola},
                              indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

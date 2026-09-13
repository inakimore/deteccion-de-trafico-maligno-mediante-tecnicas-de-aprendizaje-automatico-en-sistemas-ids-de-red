#!/usr/bin/env python3
"""¿Cuantas muestras del dia nuevo hacen falta para recalibrar? (TFG, Eje D)

POR QUE ESTE EXPERIMENTO
------------------------
`cross_calibration.py` demostro que el colapso del byte-CNN entre dias
(HALLAZGO 14) es de CALIBRACION y no de representacion: AUC >= 0.9724 en los
seis pares, y con el umbral adecuado el F1 sube de 0.0000 a >= 0.9849.

Pero aquel "umbral adecuado" es un ORACULO: se elige conociendo las etiquetas
del dia de test, asi que es una cota superior, no un metodo. Un IDS desplegado
no tiene esas etiquetas.

Este script sustituye el oraculo por un metodo REAL y responde a la pregunta
operativa: **¿cuantos flujos etiquetados del dominio nuevo hacen falta para
arreglar la calibracion?** Se usa Platt scaling -la correccion estandar, y la
que aplica el trabajo independiente de Cross-Dataset Transformer-IDS (2026),
que documenta el mismo fenomeno-, ajustado sobre una muestra PEQUENA del dia de
test y evaluado sobre el RESTO, que el calibrador no ha visto.

    p_calibrada = sigmoide(A * logit(p_cruda) + B)

Se anaden ademas las dos metricas de calibracion que el trabajo no reportaba y
la literatura exige:

    ECE (Expected Calibration Error): |confianza - acierto| promediado por
        bins de confianza. Mide si un "80% de probabilidad" ocurre el 80% de
        las veces. Un modelo puede tener AUC perfecto y ECE pesimo.
    Brier: error cuadratico medio de la probabilidad. Penaliza la confianza
        equivocada mas que un simple acierto/fallo.

Uso:
    python scripts/zeek/cross_recalibration.py --train-day Friday-16-02-2018 \\
        --test-day Tuesday-20-02-2018 --service http --service-port 80
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cross_dataset_eval import (RANDOM_STATE, balance_indices,  # noqa: E402
                                service_subset, view_seq)
from hybrid_compare import load_dataset  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"

# Cuantos flujos ETIQUETADOS del dia nuevo se le dan al calibrador. Es la
# variable que importa: en despliegue, cada etiqueta cuesta trabajo de analista.
TAMANOS = [25, 50, 100, 250, 500, 1000]
N_BINS_ECE = 15


def ece(y, p, n_bins=N_BINS_ECE) -> float:
    """Expected Calibration Error: |acierto - confianza| ponderado por bin."""
    p = np.clip(p, 1e-7, 1 - 1e-7)
    conf = np.maximum(p, 1 - p)             # confianza en la clase predicha
    pred = (p >= 0.5).astype(int)
    acierto = (pred == y).astype(float)
    bordes = np.linspace(0.5, 1.0, n_bins + 1)
    total = 0.0
    for i in range(n_bins):
        m = (conf > bordes[i]) & (conf <= bordes[i + 1])
        if m.sum():
            total += m.mean() * abs(acierto[m].mean() - conf[m].mean())
    return float(total)


def brier(y, p) -> float:
    return float(np.mean((p - y) ** 2))


def metricas(y, p):
    from sklearn.metrics import f1_score, roc_auc_score
    pred = (p >= 0.5).astype(int)
    return {
        "f1": float(f1_score(y, pred, average="macro")),
        "recall_atk": float(((pred == 1) & (y == 1)).sum() / max((y == 1).sum(), 1)),
        "auc": float(roc_auc_score(y, p)) if len(set(y)) > 1 else float("nan"),
        "ece": ece(y, p),
        "brier": brier(y, p),
    }


def platt(p_cal, y_cal, p_aplicar):
    """Ajusta sigmoide(A*logit(p)+B) sobre (p_cal, y_cal) y la aplica."""
    from sklearn.linear_model import LogisticRegression
    lg = lambda q: np.log(np.clip(q, 1e-7, 1 - 1e-7) / (1 - np.clip(q, 1e-7, 1 - 1e-7)))
    modelo = LogisticRegression(C=1e6, solver="lbfgs")
    modelo.fit(lg(p_cal).reshape(-1, 1), y_cal)
    return modelo.predict_proba(lg(p_aplicar).reshape(-1, 1))[:, 1]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-day", required=True)
    ap.add_argument("--test-day", required=True)
    ap.add_argument("--service", default=None)
    ap.add_argument("--service-port", type=int, required=True)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=8)
    args = ap.parse_args()

    rng = np.random.default_rng(RANDOM_STATE)
    d_tr, d_te = load_dataset(args.train_day), load_dataset(args.test_day)
    itr, ytr_b = service_subset(d_tr, args.service_port, args.service)
    ite, yte_b = service_subset(d_te, args.service_port, args.service)
    sel_tr, y_tr = balance_indices(itr, ytr_b, args.cap, rng)
    sel_te, y_te = balance_indices(ite, yte_b, args.cap, rng)

    print(f"== Recalibracion real: {args.train_day} -> {args.test_day} ==")
    print(f"   train {len(sel_tr)} flujos | test {len(sel_te)} flujos\n")

    from dl_models import ByteCNN, set_seed, train_torch, predict_proba_torch
    set_seed(RANDOM_STATE)
    modelo = ByteCNN(n_classes=2)
    train_torch(modelo, view_seq(d_tr, sel_tr), y_tr, epochs=args.epochs)
    p_cruda = predict_proba_torch(modelo, view_seq(d_te, sel_te))[:, 1]

    filas = {}
    for n in TAMANOS:
        if n * 2 >= len(y_te):
            continue
        # Muestra de calibracion BALANCEADA, y evaluacion sobre el RESTO:
        # el calibrador nunca ve los flujos con los que se le mide.
        idx_a = np.nonzero(y_te == 1)[0]
        idx_b = np.nonzero(y_te == 0)[0]
        cal = np.concatenate([rng.choice(idx_a, n // 2, replace=False),
                              rng.choice(idx_b, n // 2, replace=False)])
        resto = np.setdiff1d(np.arange(len(y_te)), cal)

        antes = metricas(y_te[resto], p_cruda[resto])
        p_cal = platt(p_cruda[cal], y_te[cal], p_cruda[resto])
        despues = metricas(y_te[resto], p_cal)
        filas[n] = {"antes": antes, "despues": despues}

        print(f"  n={n:>5} etiquetas  F1 {antes['f1']:.4f} -> {despues['f1']:.4f}   "
              f"recall {antes['recall_atk']:.4f} -> {despues['recall_atk']:.4f}   "
              f"ECE {antes['ece']:.4f} -> {despues['ece']:.4f}   "
              f"Brier {antes['brier']:.4f} -> {despues['brier']:.4f}")

    base = metricas(y_te, p_cruda)
    print(f"\n  sin recalibrar (todo el test): F1 {base['f1']:.4f}  "
          f"AUC {base['auc']:.4f}  ECE {base['ece']:.4f}  Brier {base['brier']:.4f}")

    MODELS_DIR.mkdir(exist_ok=True)
    out = MODELS_DIR / (f"phase3_recalibracion_{args.train_day}__{args.test_day}"
                        f"_p{args.service_port}.json")
    out.write_text(json.dumps({"train": args.train_day, "test": args.test_day,
                               "sin_recalibrar": base, "por_tamano": filas},
                              indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

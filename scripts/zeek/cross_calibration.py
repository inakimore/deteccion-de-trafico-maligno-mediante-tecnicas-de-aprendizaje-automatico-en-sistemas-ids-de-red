#!/usr/bin/env python3
"""¿El byte-CNN no transfiere, o transfiere DESCALIBRADO? (TFG, Eje D)

POR QUE ESTE EXPERIMENTO
------------------------
El HALLAZGO 14 (cross_dataset_eval.py entre dias del mismo regimen) mostro que
el byte-CNN colapsa a accuracy 0.5000 con recall de ataque 0.0000 en cuatro de
los seis pares: no se equivoca, DEGENERA y predice una sola clase.

Eso admite dos lecturas MUY distintas, y la diferencia importa para la memoria:

  (a) NO TRANSFIERE LA REPRESENTACION. El modelo no distingue ataque de benigno
      en el dia nuevo. Su puntuacion no separa las clases -> AUC ~ 0.5. No hay
      nada que rescatar.

  (b) TRANSFIERE, PERO DESCALIBRADO. El modelo SI ordena bien los ejemplos (AUC
      alto), pero el umbral aprendido en el dia de origen cae fuera del rango de
      puntuaciones del dia nuevo, asi que todo queda del mismo lado. Aqui el
      problema es de CALIBRACION, y se arregla con re-ajustar el umbral.

La accuracy con umbral fijo NO distingue (a) de (b). El AUC si: mide la calidad
del ORDEN, sin depender del umbral. Este script calcula ambos y, ademas, el
mejor F1 alcanzable con un umbral oraculo (el que se elegiria conociendo el dia
de test), que es la cota superior de lo que daria recalibrar.

Uso:
    python scripts/zeek/cross_calibration.py --train-day Friday-16-02-2018 \\
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
                                service_subset, view_payload_hist, view_seq)
from hybrid_compare import load_dataset, make_pipeline  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"


def curva(y, s):
    """AUC-PR, AUC-ROC y el mejor F1 con umbral oraculo."""
    from sklearn.metrics import (average_precision_score, roc_auc_score,
                                 precision_recall_curve, f1_score)
    ap = float(average_precision_score(y, s))
    roc = float(roc_auc_score(y, s))
    prec, rec, thr = precision_recall_curve(y, s)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-12, None)
    i = int(np.nanargmax(f1))
    thr_opt = float(thr[min(i, len(thr) - 1)]) if len(thr) else 0.5
    # F1 con el umbral por defecto de 0.5, para ver cuanto se pierde por umbral
    f1_05 = float(f1_score(y, (s >= 0.5).astype(int), zero_division=0))
    return {"auc_pr": ap, "auc_roc": roc, "f1_oraculo": float(f1[i]),
            "umbral_oraculo": thr_opt, "f1_umbral_05": f1_05,
            "recall_umbral_05": float(((s >= 0.5) & (y == 1)).sum() / max((y == 1).sum(), 1)),
            "s_media_atk": float(s[y == 1].mean()), "s_media_ben": float(s[y == 0].mean())}


def main() -> None:
    ap_ = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap_.add_argument("--train-day", required=True)
    ap_.add_argument("--test-day", required=True)
    ap_.add_argument("--service", default=None)
    ap_.add_argument("--service-port", type=int, required=True)
    ap_.add_argument("--cap", type=int, default=4000)
    ap_.add_argument("--epochs", type=int, default=8)
    args = ap_.parse_args()

    rng = np.random.default_rng(RANDOM_STATE)
    d_tr = load_dataset(args.train_day)
    d_te = load_dataset(args.test_day)
    itr, ytr_b = service_subset(d_tr, args.service_port, args.service)
    ite, yte_b = service_subset(d_te, args.service_port, args.service)
    sel_tr, y_tr = balance_indices(itr, ytr_b, args.cap, rng)
    sel_te, y_te = balance_indices(ite, yte_b, args.cap, rng)

    print(f"== Calibracion cruzada: {args.train_day} -> {args.test_day} ==")
    print(f"   train {len(sel_tr)} flujos | test {len(sel_te)} flujos\n")

    filas = {}

    # --- byte-CNN ---------------------------------------------------------
    from dl_models import ByteCNN, set_seed, train_torch, predict_proba_torch
    set_seed(RANDOM_STATE)
    modelo = ByteCNN(n_classes=2)
    train_torch(modelo, view_seq(d_tr, sel_tr), y_tr, epochs=args.epochs)
    s_cnn = predict_proba_torch(modelo, view_seq(d_te, sel_te))[:, 1]
    filas["byte-CNN"] = curva(y_te, s_cnn)

    # --- payload-hist (MLP), como control ---------------------------------
    clf = make_pipeline().fit(view_payload_hist(d_tr, sel_tr), y_tr)
    s_mlp = clf.predict_proba(view_payload_hist(d_te, sel_te))[:, 1]
    filas["payload-hist"] = curva(y_te, s_mlp)

    for nombre, m in filas.items():
        print(f"== {nombre} ==")
        print(f"   AUC-PR {m['auc_pr']:.4f} | AUC-ROC {m['auc_roc']:.4f}")
        print(f"   F1 con umbral 0.5 {m['f1_umbral_05']:.4f} (recall "
              f"{m['recall_umbral_05']:.4f})  ->  F1 con umbral ORACULO "
              f"{m['f1_oraculo']:.4f} (umbral {m['umbral_oraculo']:.4g})")
        print(f"   puntuacion media: ataque {m['s_media_atk']:.4f} | "
              f"benigno {m['s_media_ben']:.4f}\n")

    # veredicto automatico para el byte-CNN
    m = filas["byte-CNN"]
    if m["auc_roc"] >= 0.85 and m["recall_umbral_05"] < 0.10:
        veredicto = ("DESCALIBRADO: el orden es bueno (AUC alto) pero el umbral "
                     "heredado del dia de origen deja todo del mismo lado. "
                     "Recalibrar rescataria el modelo.")
    elif m["auc_roc"] < 0.65:
        veredicto = ("LA REPRESENTACION NO TRANSFIERE: la puntuacion apenas ordena "
                     "mejor que el azar, asi que no hay umbral que lo rescate.")
    else:
        veredicto = ("INTERMEDIO: hay algo de senal en el orden, pero lejos de lo "
                     "que daria dentro del dia.")
    print(f"VEREDICTO (byte-CNN): {veredicto}")

    MODELS_DIR.mkdir(exist_ok=True)
    out = MODELS_DIR / (f"phase3_calibracion_{args.train_day}__{args.test_day}"
                        f"_p{args.service_port}.json")
    out.write_text(json.dumps(
        {"train": args.train_day, "test": args.test_day, "vistas": filas,
         "veredicto_byte_cnn": veredicto}, indent=2, ensure_ascii=False),
        encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

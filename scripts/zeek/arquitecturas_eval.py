#!/usr/bin/env python3
"""¿Aporta la ATENCION algo sobre lo que ya teniamos? (TFG, Fase 3)

POR QUE ESTE EXPERIMENTO
------------------------
El estado del arte sintetizado en el README hace dos propuestas arquitectonicas
que este trabajo NO habia probado, y son justo las dos que un tribunal de IA
preguntaria:

  (1) Para el payload, los Transformers (ET-BERT, DeBERTav2) por encima del CNN.
  (2) Para la fusion, la ATENCION CRUZADA (CPS-IDS) por encima de concatenar los
      embeddings de las dos ramas, que es lo que hace nuestro Eje B.

Aqui se comparan a igualdad de datos, de particion y de presupuesto de
parametros (30k-72k), que es la unica forma de saber si la ganancia viene de la
ARQUITECTURA y no de haber entrenado un modelo mas grande.

    --modo secuencia : ByteCNN (nuestro) vs ByteLSTM (nuestro) vs ByteTransformer
    --modo fusion    : concat ingenua vs fusion tardia (nuestro Eje B) vs
                       atencion cruzada

Con --day mide dentro del dia (CV out-of-fold). Con --train-day/--test-day mide
la transferencia entre dias, que es donde este trabajo ha demostrado que se
deciden las cosas (HALLAZGO 14), y reporta AUC ademas de F1 porque el umbral
fijo engana.

Uso:
    python scripts/zeek/arquitecturas_eval.py --day Thursday-22-02-2018 \\
        --service http --modo secuencia
    python scripts/zeek/arquitecturas_eval.py --train-day Friday-16-02-2018 \\
        --test-day Tuesday-20-02-2018 --service http --modo fusion
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, load_dataset, build_meta_features,
)
from dl_models import (ByteCNN, ByteLSTM, ByteTransformer,  # noqa: E402
                       CrossAttentionNet, set_seed)
from train_dl_hybrid import HybridNet  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset


def entrenar(modelo, tensores, y, *, epochs: int, batch: int = 64, lr: float = 1e-3):
    """Bucle de entrenamiento comun a todas las arquitecturas."""
    opt = torch.optim.Adam(modelo.parameters(), lr=lr)
    lossf = nn.CrossEntropyLoss()
    ds = TensorDataset(*tensores, torch.tensor(y, dtype=torch.long))
    dl = DataLoader(ds, batch_size=batch, shuffle=True)
    modelo.train()
    for _ in range(epochs):
        for lote in dl:
            *xs, yb = lote
            opt.zero_grad()
            loss = lossf(modelo(*xs), yb)
            loss.backward()
            opt.step()
    return modelo


def probabilidades(modelo, tensores, batch: int = 256):
    modelo.eval()
    out = []
    with torch.no_grad():
        ds = TensorDataset(*tensores)
        for lote in DataLoader(ds, batch_size=batch):
            out.append(torch.softmax(modelo(*lote), dim=1)[:, 1].numpy())
    return np.concatenate(out)


def metricas(y, p):
    from sklearn.metrics import f1_score, roc_auc_score
    pred = (p >= 0.5).astype(int)
    return {"f1": float(f1_score(y, pred, average="macro")),
            "recall_atk": float(((pred == 1) & (y == 1)).sum() / max((y == 1).sum(), 1)),
            "auc": float(roc_auc_score(y, p)) if len(set(y)) > 1 else float("nan")}


def subconjunto(d, port, service, cap, rng):
    from imblearn.under_sampling import RandomUnderSampler
    y_raw = d["y"].astype(str)
    svc = service_selection(d, port=port, service=service)
    etiquetas = sorted(set(y_raw[svc & (y_raw != "Benign")]))
    if not etiquetas:
        sys.exit(f"[ERROR] Sin ataques en {selection_label(port, service)}")
    y_bin = np.where(np.isin(y_raw, etiquetas), 1, np.where(y_raw == "Benign", 0, -1))
    idx = np.nonzero(svc & (y_bin >= 0))[0]
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


def tensores_de(d, sel):
    xs = torch.tensor(d["X_seq"][sel].astype(np.int64))
    xm = torch.tensor(build_meta_features(d, sel).astype(np.float32))
    return xs, xm


def fabricas(modo: str, n_meta: int):
    """Modelos a comparar, con su etiqueta de PROCEDENCIA para la memoria."""
    if modo == "secuencia":
        return {
            "byte-CNN (este TFG)": (lambda: ByteCNN(2), ("seq",)),
            "byte-LSTM (este TFG)": (lambda: ByteLSTM(2), ("seq",)),
            "byte-Transformer (SOTA)": (lambda: ByteTransformer(2), ("seq",)),
        }
    return {
        "fusion tardia (este TFG)": (lambda: HybridNet(2, n_meta=n_meta), ("seq", "meta")),
        "atencion cruzada (SOTA)": (lambda: CrossAttentionNet(2, n_meta=n_meta), ("seq", "meta")),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", default=None)
    ap.add_argument("--train-day", default=None)
    ap.add_argument("--test-day", default=None)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default=None)
    ap.add_argument("--modo", choices=["secuencia", "fusion"], default="secuencia")
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    rng = np.random.default_rng(RANDOM_STATE)
    MODELS_DIR.mkdir(exist_ok=True)
    tabla = {}

    if args.day:
        from sklearn.model_selection import StratifiedKFold
        d = load_dataset(args.day)
        sel, y, etiquetas = subconjunto(d, args.port, args.service, args.cap, rng)
        xs, xm = tensores_de(d, sel)
        print(f"== Arquitecturas ({args.modo}) dentro del dia: {args.day} ==")
        print(f"   {selection_label(args.port, args.service)} | ataques {etiquetas}")
        print(f"   {int(y.sum())} ataque / {int((y == 0).sum())} benigno\n")

        cv = StratifiedKFold(n_splits=args.folds, shuffle=True,
                             random_state=RANDOM_STATE)
        for nombre, (fab, vistas) in fabricas(args.modo, xm.shape[1]).items():
            t0 = time.time()
            p_oof = np.zeros(len(y))
            for tr, te in cv.split(np.zeros(len(y)), y):
                set_seed(RANDOM_STATE)
                ent = [xs[tr]] if vistas == ("seq",) else [xs[tr], xm[tr]]
                tes = [xs[te]] if vistas == ("seq",) else [xs[te], xm[te]]
                m = entrenar(fab(), ent, y[tr], epochs=args.epochs)
                p_oof[te] = probabilidades(m, tes)
            mm = metricas(y, p_oof)
            mm["segundos"] = round(time.time() - t0, 1)
            mm["parametros"] = sum(p.numel() for p in fab().parameters())
            tabla[nombre] = mm
            print(f"{nombre:26s} F1 {mm['f1']:.4f}  AUC {mm['auc']:.4f}  "
                  f"({mm['parametros']:,} par., {mm['segundos']:.0f}s)")
        out = MODELS_DIR / f"phase3_arquitecturas_{args.modo}_{args.day}.json"
    else:
        if not (args.train_day and args.test_day):
            sys.exit("[ERROR] Usa --day, o --train-day y --test-day")
        d_tr, d_te = load_dataset(args.train_day), load_dataset(args.test_day)
        s_tr, y_tr, _ = subconjunto(d_tr, args.port, args.service, args.cap, rng)
        s_te, y_te, _ = subconjunto(d_te, args.port, args.service, args.cap, rng)
        xs_tr, xm_tr = tensores_de(d_tr, s_tr)
        xs_te, xm_te = tensores_de(d_te, s_te)
        print(f"== Arquitecturas ({args.modo}): {args.train_day} -> {args.test_day} ==\n")
        for nombre, (fab, vistas) in fabricas(args.modo, xm_tr.shape[1]).items():
            set_seed(RANDOM_STATE)
            ent = [xs_tr] if vistas == ("seq",) else [xs_tr, xm_tr]
            tes = [xs_te] if vistas == ("seq",) else [xs_te, xm_te]
            m = entrenar(fab(), ent, y_tr, epochs=args.epochs)
            mm = metricas(y_te, probabilidades(m, tes))
            tabla[nombre] = mm
            print(f"{nombre:26s} F1 {mm['f1']:.4f}  AUC {mm['auc']:.4f}  "
                  f"recall {mm['recall_atk']:.4f}")
        out = MODELS_DIR / (f"phase3_arquitecturas_{args.modo}_"
                            f"{args.train_day}__{args.test_day}.json")

    out.write_text(json.dumps(tabla, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

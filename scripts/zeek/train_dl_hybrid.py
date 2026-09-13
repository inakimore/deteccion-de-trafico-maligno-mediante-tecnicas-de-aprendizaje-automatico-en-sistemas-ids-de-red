#!/usr/bin/env python3
"""FASE 3 - Eje B: HIBRIDO DE DOS RAMAS con fusion tardia (payload + metadatos).

El 16-jun se vio que concatenar a lo bruto las 257 features de payload con los 4
escalares de metadatos DILUYE la metadata (el MLP no aisla los pocos escalares
utiles). Aqui se hace la fusion BIEN: una red de dos ramas que aprende un embedding
por vista y las funde al final (late fusion):

  - Rama payload  : embedding de bytes + CNN 1D multi-kernel  -> vector de payload.
  - Rama metadatos: MLP sobre las features de flujo           -> vector de conducta.
  - Fusion        : se concatenan los DOS EMBEDDINGS APRENDIDOS (no las features
                    crudas) y una capa final decide.

La tesis del TFG es que un unico modelo hibrido debe ser ROBUSTO en los dos
regimenes (payload en claro y trafico cifrado). Se compara el hibrido de dos ramas
contra:
  - solo-payload (byte-CNN)         -> gana en claro, ciego al cifrado.
  - solo-metadatos (MLP conductual) -> gana en cifrado por la ráfaga.
  - fusion INGENUA (early concat)   -> el problema que este script corrige.

Evaluacion out-of-fold (5-Fold Stratified). El escalado de los metadatos se ajusta
DENTRO de cada fold (solo con el train) para no filtrar informacion.

Salida: models/phase2_dlhybrid_<dia>_<task>.md + consola.

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/train_dl_hybrid.py --day Thursday-22-02-2018 --port 80 --task multitype
    conda run -n tfg_ia python scripts/zeek/train_dl_hybrid.py --day Thursday-22-02-2018 --port 80 --task binary
    conda run -n tfg_ia python scripts/zeek/train_dl_hybrid.py --day Wednesday-14-02-2018 --port 22 --task binary
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)
from dl_models import ByteCNN, set_seed, VOCAB  # noqa: E402
from train_dl_payload import report, eval_sklearn  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

EPOCHS = 40


class HybridNet(nn.Module):
    """Dos ramas (payload-CNN + metadatos-MLP) con fusion tardia de embeddings."""

    def __init__(self, n_classes: int, n_meta: int, emb: int = 24,
                 kernels=(3, 5, 7), n_filters: int = 64, meta_hidden: int = 32,
                 dropout: float = 0.3):
        super().__init__()
        self.embed = nn.Embedding(VOCAB, emb)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, n_filters, k, padding=k // 2) for k in kernels])
        pay_dim = n_filters * len(kernels)
        self.meta = nn.Sequential(
            nn.Linear(n_meta, meta_hidden), nn.ReLU(),
            nn.Linear(meta_hidden, meta_hidden), nn.ReLU())
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(pay_dim + meta_hidden, n_classes)

    def forward(self, x_seq, x_meta):
        e = self.embed(x_seq).transpose(1, 2)
        pf = torch.cat([F.relu(c(e)).max(dim=2).values for c in self.convs], dim=1)
        mf = self.meta(x_meta)
        return self.fc(self.drop(torch.cat([pf, mf], dim=1)))


def oof_hybrid(X_seq, X_meta, y_enc, n_classes, folds, seed):
    """Out-of-fold del hibrido; escala los metadatos dentro de cada fold."""
    from sklearn.model_selection import StratifiedKFold
    from sklearn.preprocessing import StandardScaler

    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    y_pred = np.zeros(len(y_enc), dtype=int)
    for tr, va in skf.split(X_seq, y_enc):
        set_seed(seed)
        sc = StandardScaler().fit(X_meta[tr])
        m_tr = sc.transform(X_meta[tr]).astype(np.float32)
        m_va = sc.transform(X_meta[va]).astype(np.float32)
        model = HybridNet(n_classes, X_meta.shape[1])
        ds = TensorDataset(torch.as_tensor(X_seq[tr], dtype=torch.long),
                           torch.as_tensor(m_tr, dtype=torch.float32),
                           torch.as_tensor(y_enc[tr], dtype=torch.long))
        dl = DataLoader(ds, batch_size=64, shuffle=True)
        opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
        lossf = nn.CrossEntropyLoss()
        model.train()
        for _ in range(EPOCHS):
            for sb, mb, yb in dl:
                opt.zero_grad()
                lossf(model(sb, mb), yb).backward()
                opt.step()
        model.eval()
        with torch.no_grad():
            logits = model(torch.as_tensor(X_seq[va], dtype=torch.long),
                           torch.as_tensor(m_va, dtype=torch.float32))
        y_pred[va] = logits.argmax(1).numpy()
    return y_pred


def write_summary(day, task, rows, counts, classes, out_dir):
    counts_str = ", ".join(f"{c} `{lab}`" for lab, c in counts.items())
    lines = [
        f"# Fase 3 (Eje B) - Hibrido de dos ramas: fusion tardia payload+metadatos ({day}, {task})",
        "",
        f"Flujos: {counts_str} (total {sum(counts.values())}). Clases: `{list(classes)}`.",
        "Evaluacion out-of-fold (5-Fold Stratified).",
        "",
        "La red de DOS RAMAS (CNN de payload + MLP de metadatos, fusion tardia de",
        "embeddings) frente a las vistas sueltas y a la fusion INGENUA (early concat de",
        "features crudas). La tesis: el hibrido debe ser robusto en ambos regimenes.",
        "",
        "| Modelo | Accuracy | Macro-F1 |",
        "|--------|----------|----------|",
    ]
    for r in rows:
        lines.append(f"| {r['name']} | {r['acc']:.4f} | {r['macro_f1']:.4f} |")
    lines.append("")
    for r in rows:
        lines += [
            f"## {r['name']}", "",
            f"- **Accuracy:** {r['acc']:.4f} | **Macro-F1:** {r['macro_f1']:.4f}", "",
            "```", r["report"].rstrip(), "",
            f"Matriz de confusion labels={list(classes)}:",
            np.array2string(r["cm"]), "```", "",
        ]
    out = out_dir / f"phase2_dlhybrid_{day}_{task}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--day", default="Thursday-22-02-2018")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--service", default=None,
                   help="Selecciona el servicio por CONTENIDO (http, ssh...) en vez "
                        "de por puerto. Correccion del tutor: el puerto depende de "
                        "la configuracion de cada red.")
    p.add_argument("--task", choices=["binary", "multitype"], default="multitype")
    p.add_argument("--folds", type=int, default=CV_FOLDS)
    p.add_argument("--cap", type=int, default=0,
                   help="Max flujos por clase (0=sin limite); subsampleo por clase "
                        "para dias masivos (DoS) tratable en CPU/RAM.")
    args = p.parse_args()

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    set_seed()
    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))

    # Memoria: no materializamos vistas completas (DoS = millones de flujos -> OOM).
    # Se calcula `sel` con arrays ligeros y las vistas se construyen solo para sel.
    if args.task == "binary":
        y = np.where(np.isin(y_raw, attack_labels), "Attack", y_raw)
        mask = svc_sel & ((y == "Attack") | (y == "Benign"))
        y_svc = y[mask]
        idx_all = np.nonzero(mask)[0]
        rus = RandomUnderSampler(random_state=RANDOM_STATE)
        sel_local, y_bal = rus.fit_resample(np.arange(len(y_svc)).reshape(-1, 1), y_svc)
        sel = idx_all[sel_local.ravel()]
        le = LabelEncoder().fit(y_svc)
        y_enc = le.transform(y_bal)
    else:
        mask = svc_sel & np.isin(y_raw, attack_labels)
        sel = np.nonzero(mask)[0]
        y_bal = y_raw[sel]
        le = LabelEncoder().fit(y_bal)
        y_enc = le.transform(y_bal)

    if args.cap and args.cap > 0:
        rng = np.random.default_rng(RANDOM_STATE)
        keep = []
        for c in np.unique(y_enc):
            ci = np.nonzero(y_enc == c)[0]
            if len(ci) > args.cap:
                ci = rng.choice(ci, size=args.cap, replace=False)
            keep.append(ci)
        keep = np.sort(np.concatenate(keep))
        sel, y_bal, y_enc = sel[keep], y_bal[keep], y_enc[keep]
        print(f"[cap={args.cap}] subsampleado a {len(sel)} flujos por clase")

    classes = list(le.classes_)
    labs, cnts = np.unique(y_bal, return_counts=True)
    counts = dict(zip(labs.tolist(), cnts.tolist()))
    print(f"Tarea {args.task} puerto {args.port}: {len(sel)} flujos -> {counts}\n")

    # Vistas solo para sel (carga transitoria por array; pico de RAM acotado).
    X_seq = d["X_seq"][sel].astype(np.int64)
    X_meta = build_meta_features(d, sel)
    n_classes = len(classes)
    rows = []

    print("Entrenando HIBRIDO de dos ramas (CNN payload + MLP metadatos)...")
    yp = oof_hybrid(X_seq, X_meta, y_enc, n_classes, args.folds, RANDOM_STATE)
    rows.append(report("hibrido 2-ramas (torch)", y_enc, yp, classes))

    print("Entrenando fusion INGENUA (early concat seq+meta, MLP sklearn)...")
    X_naive = np.hstack([X_seq.astype(np.float32), X_meta]).astype(np.float32)
    rows.append(report("fusion ingenua (concat)", y_enc,
                       eval_sklearn("naive", X_naive, y_enc, args.folds, RANDOM_STATE), classes))

    from dl_models import oof_predict_torch
    print("Entrenando solo-payload (byte-CNN)...")
    yp, _ = oof_predict_torch("cnn", X_seq, y_enc, n_classes,
                              epochs=EPOCHS, folds=args.folds, seed=RANDOM_STATE)
    rows.append(report("solo-payload (byte-CNN)", y_enc, yp, classes))

    print("Entrenando solo-metadatos (MLP sklearn)...")
    rows.append(report("solo-metadatos (MLP)", y_enc,
                       eval_sklearn("meta", X_meta, y_enc, args.folds, RANDOM_STATE), classes))

    write_summary(args.day, args.task, rows, counts, classes, MODELS_DIR)
    print("\nListo.")


if __name__ == "__main__":
    main()

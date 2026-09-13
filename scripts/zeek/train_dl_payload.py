#!/usr/bin/env python3
"""FASE 3 - Eje A: deep learning sobre la SECUENCIA de bytes del payload.

Compara, EN LA MISMA PARTICION (mismos folds), modelos profundos sobre la secuencia
de bytes contra los baselines shallow de la Fase 2, para medir cuanto aporta la IA
"de verdad" frente al MLP sobre histograma/secuencia plana:

  - byte-CNN   (torch) : embedding de bytes + conv 1D multi-kernel (Deep Packet).
  - byte-LSTM  (torch) : embedding de bytes + BiLSTM.
  - mlp-seq    (sklearn): MLP sobre la secuencia como vector plano (baseline Fase 2).
  - mlp-hist   (sklearn): MLP sobre histograma de bytes + entropia (vista Fase 2).
  - metadatos  (sklearn): MLP sobre features de flujo (referencia conductual).

Dos tareas:
  --task binary    : ataque vs benigno SOBRE EL SERVICIO ATACADO (puerto), balanceado
                     1:1 (caso dificil honesto, comparable a honest_by_service*.py).
  --task multitype : distinguir el TIPO de ataque (solo flujos de ataque del puerto),
                     out-of-fold sobre el desbalanceo natural (comparable a
                     multitype_web.py).

Evaluacion: predicciones out-of-fold (5-Fold Stratified, sin fuga) -> accuracy y
macro-F1 sobre todos los flujos, classification_report y matriz de confusion.

Salida: models/phase2_dl_<dia>_<task>.md + impresion por consola.

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/train_dl_payload.py --day Thursday-22-02-2018 --port 80 --task binary
    conda run -n tfg_ia python scripts/zeek/train_dl_payload.py --day Thursday-22-02-2018 --port 80 --task multitype
    conda run -n tfg_ia python scripts/zeek/train_dl_payload.py --day Wednesday-14-02-2018 --port 22 --task binary
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)
from dl_models import oof_predict_torch, set_seed  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

CNN_EPOCHS = 40
LSTM_EPOCHS = 25


def eval_sklearn(name, X, y_enc, folds, seed):
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    return cross_val_predict(make_pipeline(), X, y_enc, cv=skf, n_jobs=-1)


def report(name, y_true, y_pred, classes):
    from sklearn.metrics import classification_report, confusion_matrix, f1_score, accuracy_score
    ids = np.arange(len(classes))
    acc = accuracy_score(y_true, y_pred)
    macro = f1_score(y_true, y_pred, labels=ids, average="macro", zero_division=0)
    rep = classification_report(y_true, y_pred, labels=ids, target_names=classes,
                                digits=4, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=ids)
    print(f"\n== {name} == acc {acc:.4f} | macro-F1 {macro:.4f}")
    print(rep)
    print(cm)
    return {"name": name, "acc": acc, "macro_f1": macro, "report": rep, "cm": cm}


def write_summary(day, task, rows, counts, classes, out_dir):
    counts_str = ", ".join(f"{c} `{lab}`" for lab, c in counts.items())
    title_task = "ataque vs benigno por servicio" if task == "binary" else "tipo de ataque (multiclase)"
    lines = [
        f"# Fase 3 (Eje A) - Deep learning sobre bytes: {title_task} ({day})",
        "",
        f"Tarea `{task}`. Flujos: {counts_str} (total {sum(counts.values())}).",
        f"Clases: `{list(classes)}`. Evaluacion out-of-fold (5-Fold Stratified).",
        "",
        "Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a",
        "los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y",
        "metadatos de flujo), todos en la MISMA particion.",
        "",
        "| Vista / Modelo | Accuracy | Macro-F1 |",
        "|----------------|----------|----------|",
    ]
    for r in rows:
        lines.append(f"| {r['name']} | {r['acc']:.4f} | {r['macro_f1']:.4f} |")
    lines.append("")
    for r in rows:
        lines += [
            f"## {r['name']}", "",
            f"- **Accuracy:** {r['acc']:.4f} | **Macro-F1:** {r['macro_f1']:.4f}", "",
            "```", r["report"].rstrip(), "",
            f"Matriz de confusion (filas=real, cols=pred) labels={list(classes)}:",
            np.array2string(r["cm"]), "```", "",
        ]
    out = out_dir / f"phase2_dl_{day}_{task}.md"
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
    p.add_argument("--task", choices=["binary", "multitype"], default="binary")
    p.add_argument("--folds", type=int, default=CV_FOLDS)
    p.add_argument("--cap", type=int, default=0,
                   help="Max flujos por clase (0=sin limite). Para dias muy grandes "
                        "(DoS, millones de flujos) subsamplea por clase y hace el "
                        "entrenamiento DL tratable en CPU sin cambiar el resultado "
                        "(la senal ya satura con unos miles de muestras).")
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
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en el puerto {args.port} de {args.day}")
    print(f"Ataques en el servicio: {attack_labels}")

    # NOTA de memoria: NO materializamos las vistas completas (en dias masivos como
    # el DoS son millones de flujos y castear X_seq a int64 son ~8 GB -> OOM con 16
    # GB de RAM). Calculamos primero `sel` (indices) con arrays ligeros (y, resp_p)
    # y solo despues construimos las vistas para el subconjunto seleccionado.
    if args.task == "binary":
        # Colapsa ataques -> "Attack"; ataque vs benigno del servicio, balance 1:1.
        y = np.where(np.isin(y_raw, attack_labels), "Attack", y_raw)
        mask = svc_sel & ((y == "Attack") | (y == "Benign"))
        y_svc = y[mask]
        idx_all = np.nonzero(mask)[0]
        rus = RandomUnderSampler(random_state=RANDOM_STATE)
        sel_local, y_bal = rus.fit_resample(np.arange(len(y_svc)).reshape(-1, 1), y_svc)
        sel = idx_all[sel_local.ravel()]
        le = LabelEncoder().fit(y_svc)
        y_enc = le.transform(y_bal)
    else:  # multitype
        mask = svc_sel & np.isin(y_raw, attack_labels)
        sel = np.nonzero(mask)[0]
        y_bal = y_raw[sel]
        le = LabelEncoder().fit(y_bal)
        y_enc = le.transform(y_bal)

    # Cap por clase (dias masivos como el DoS): subsampleo reproducible manteniendo
    # sel/y_bal/y_enc alineados. No aplica a dias pequenos (web/SSH) con cap=0.
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
    print(f"Tarea {args.task}: {len(sel)} flujos -> {counts}\nClases: {classes}\n")

    # Vistas SOLO para las filas seleccionadas (cada d[...] carga el array del npz
    # de forma transitoria y se subsetea; el pico de RAM es un array a la vez).
    X_seq = d["X_seq"][sel].astype(np.int64)
    ent_sel = entropy[sel]
    X_hist = np.hstack([d["X_hist"][sel], (ent_sel / 8.0).reshape(-1, 1)]).astype(np.float32)
    X_meta = build_meta_features(d, sel)
    n_classes = len(classes)
    rows = []

    print("Entrenando byte-CNN (torch)...")
    yp, _ = oof_predict_torch("cnn", X_seq, y_enc, n_classes,
                              epochs=CNN_EPOCHS, folds=args.folds, seed=RANDOM_STATE)
    rows.append(report("byte-CNN (torch)", y_enc, yp, classes))

    print("Entrenando byte-LSTM (torch)...")
    yp, _ = oof_predict_torch("lstm", X_seq, y_enc, n_classes,
                              epochs=LSTM_EPOCHS, folds=args.folds, seed=RANDOM_STATE)
    rows.append(report("byte-LSTM (torch)", y_enc, yp, classes))

    for nm, Xv in [("mlp-seq (sklearn)", X_seq.astype(np.float32)),
                   ("mlp-hist (sklearn)", X_hist),
                   ("metadatos (sklearn)", X_meta)]:
        print(f"Entrenando {nm}...")
        yp = eval_sklearn(nm, Xv, y_enc, args.folds, RANDOM_STATE)
        rows.append(report(nm, y_enc, yp, classes))

    write_summary(args.day, args.task, rows, counts, classes, MODELS_DIR)
    print("\nListo.")


if __name__ == "__main__":
    main()

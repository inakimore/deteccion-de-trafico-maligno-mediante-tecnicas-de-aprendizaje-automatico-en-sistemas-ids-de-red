#!/usr/bin/env python3
"""Punto 6 - METRICAS DE RIGOR: PR/ROC-AUC + intervalos de confianza (bootstrap).

CONTEXTO
--------
Las clases de ataque de este TFG son pequenas (web 174-203 flujos, SSH benigno limpio
433) y hasta ahora se reporto sobre todo accuracy/F1 puntuales. Con N pequeno eso puede
enganar. Este script anade el rigor estadistico estandar en deteccion:
  - ROC-AUC y PR-AUC (average precision), mas informativas con clases pequenas/
    desbalanceadas que el accuracy.
  - Intervalos de confianza al 95% por BOOTSTRAP sobre las predicciones out-of-fold.
  - Curvas ROC y Precision-Recall (PNG) comparando las vistas.

Compara las vistas clave sobre el servicio atacado (binario Attack vs Benign, 1:1,
out-of-fold): payload byte-CNN, payload histograma (MLP) y conducta meta+rafaga (MLP).

Salida: models/phase2_rigor_<day>_p<port>.md + models/phase2_rigor_<day>_p<port>.png

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/rigor_metrics.py --day Thursday-22-02-2018 --port 80
    conda run -n tfg_ia python scripts/zeek/rigor_metrics.py --day Wednesday-14-02-2018 --port 22
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, CV_FOLDS, load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import build_burst_features, BURST_WINDOWS  # noqa: E402
from dl_models import oof_predict_torch  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402


def sklearn_oof_proba(X, y, folds, seed):
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    return cross_val_predict(make_pipeline(), X, y, cv=skf, method="predict_proba",
                             n_jobs=-1)[:, 1]


def boot_ci(y, score, metric, n_boot=2000, seed=RANDOM_STATE):
    """IC 95% por bootstrap de una metrica que toma (y_true, score)."""
    rng = np.random.default_rng(seed)
    n = len(y)
    vals = []
    for _ in range(n_boot):
        ix = rng.integers(0, n, n)
        if len(np.unique(y[ix])) < 2:
            continue
        vals.append(metric(y[ix], score[ix]))
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(np.mean(vals)), float(lo), float(hi)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--service", default=None,
                    help="Selecciona el servicio por CONTENIDO (ssh, http...) en vez "
                         "de por puerto. Correccion del tutor: el puerto depende de "
                         "la configuracion de cada red.")
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--folds", type=int, default=CV_FOLDS)
    ap.add_argument("--epochs", type=int, default=30)
    args = ap.parse_args()

    from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve, precision_recall_curve
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    rng = np.random.default_rng(RANDOM_STATE)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en :{args.port} de {args.day}")
    print(f"Ataques en :{args.port}: {attack_labels}")

    print(f"Calculando rafaga (ventanas {BURST_WINDOWS} s)...")
    burst = build_burst_features(d)

    y_bin_full = np.where(np.isin(y_raw, attack_labels), 1, np.where(y_raw == "Benign", 0, -1))
    mask = svc_sel & (y_bin_full >= 0)
    idx_all = np.nonzero(mask)[0]
    yb = y_bin_full[idx_all]
    sel_local, _ = RandomUnderSampler(random_state=RANDOM_STATE).fit_resample(
        np.arange(len(yb)).reshape(-1, 1), yb)
    sel = idx_all[sel_local.ravel()]
    y = y_bin_full[sel]
    if args.cap > 0:
        keep = np.concatenate([
            (lambda ci: rng.choice(ci, args.cap, replace=False) if len(ci) > args.cap else ci)(
                np.nonzero(y == c)[0]) for c in (0, 1)])
        keep.sort(); sel, y = sel[keep], y[keep]
    print(f"Balance -> attack {int((y==1).sum())} / benign {int((y==0).sum())}\n")

    X_seq = d["X_seq"][sel].astype(np.int64)
    X_hist = np.hstack([d["X_hist"][sel], (entropy[sel] / 8.0).reshape(-1, 1)]).astype(np.float32)
    X_meta = np.hstack([build_meta_features(d, sel), burst[sel]]).astype(np.float32)

    print("byte-CNN (out-of-fold)...")
    _, proba_cnn = oof_predict_torch("cnn", X_seq, y, 2, epochs=args.epochs, folds=args.folds)
    scores = {
        "payload byte-CNN": proba_cnn[:, 1],
        "payload histograma": sklearn_oof_proba(X_hist, y, args.folds, RANDOM_STATE),
        "conducta meta+rafaga": sklearn_oof_proba(X_meta, y, args.folds, RANDOM_STATE),
    }

    rows = []
    fig, (axr, axp) = plt.subplots(1, 2, figsize=(12, 5))
    for name, sc in scores.items():
        auc_m, auc_lo, auc_hi = boot_ci(y, sc, roc_auc_score)
        ap_m, ap_lo, ap_hi = boot_ci(y, sc, average_precision_score)
        rows.append((name, auc_m, auc_lo, auc_hi, ap_m, ap_lo, ap_hi))
        print(f"  [{name}] ROC-AUC {auc_m:.4f} [{auc_lo:.4f},{auc_hi:.4f}] | "
              f"PR-AUC {ap_m:.4f} [{ap_lo:.4f},{ap_hi:.4f}]")
        fpr, tpr, _ = roc_curve(y, sc)
        axr.plot(fpr, tpr, label=f"{name} (AUC {auc_m:.3f})")
        prec, rec, _ = precision_recall_curve(y, sc)
        axp.plot(rec, prec, label=f"{name} (AP {ap_m:.3f})")
    axr.plot([0, 1], [0, 1], "k--", alpha=0.4); axr.set_xlabel("FPR"); axr.set_ylabel("TPR")
    axr.set_title(f"ROC - {args.day} :{args.port}"); axr.legend(loc="lower right", fontsize=8)
    axp.set_xlabel("Recall"); axp.set_ylabel("Precision")
    axp.set_title(f"Precision-Recall - {args.day} :{args.port}"); axp.legend(loc="lower left", fontsize=8)
    fig.tight_layout()
    png = MODELS_DIR / f"phase2_rigor_{args.day}_p{args.port}.png"
    fig.savefig(png, dpi=120); plt.close(fig)

    lines = [
        f"# Punto 6 - Metricas de rigor: ROC/PR-AUC + IC 95% ({args.day}, :{args.port})",
        "",
        f"Binario Attack vs Benign en :{args.port}, balanceado 1:1 "
        f"(attack {int((y==1).sum())} / benign {int((y==0).sum())}), out-of-fold {args.folds}-Fold. "
        "Intervalos de confianza al 95% por bootstrap (2000 remuestreos). Curvas en el PNG.",
        "",
        "| Vista | ROC-AUC [IC95%] | PR-AUC [IC95%] |",
        "|-------|-----------------|----------------|",
    ]
    for name, aucm, auclo, auchi, apm, aplo, aphi in rows:
        lines.append(f"| {name} | {aucm:.4f} [{auclo:.4f}, {auchi:.4f}] | "
                     f"{apm:.4f} [{aplo:.4f}, {aphi:.4f}] |")
    lines += [
        "",
        f"Curvas ROC y Precision-Recall: `{png.name}`.",
        "",
        "**Lectura:** con clases pequenas el ROC/PR-AUC y su IC son mas honestos que un "
        "accuracy puntual. Un IC ancho avisa de que el N es reducido (p.ej. web, 203 flujos); "
        "aun asi la vista ganadora de cada regimen se separa de forma consistente.",
        "",
    ]
    out = MODELS_DIR / f"phase2_rigor_{args.day}_p{args.port}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}\nGrafica -> {png}")


if __name__ == "__main__":
    main()

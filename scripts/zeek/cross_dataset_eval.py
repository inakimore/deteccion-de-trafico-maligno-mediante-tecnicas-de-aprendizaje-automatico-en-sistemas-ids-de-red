#!/usr/bin/env python3
"""Generalizacion CRUZADA entre datasets: entrenar en A, testear en B (TFG).

POR QUE ESTE EXPERIMENTO
------------------------
Las evaluaciones honestas por servicio (honest_by_service*.py) miden cada vista
DENTRO de un mismo dataset (train y test del mismo dia). Un acierto muy alto ahi
—sobre todo los 1.0— puede estar inflado por dos motivos: N pequeno y, sobre todo,
que el modelo MEMORICE la huella del laboratorio/herramienta concreta (el banner
`paramiko` del SSH, la app DVWA del web) en vez de aprender la firma del ataque.

La prueba decisiva es entrenar en un dataset y testear en OTRO distinto con el
ataque analogo. Si el modelo sigue detectando -> la senal es real y generaliza.
Si se hunde -> estaba memorizando. Esto responde directamente a la objecion del
"100% sospechoso".

Analogos entre CSE-CIC-IDS2018 y CIC-IDS2017 (mismos tres regimenes):
    SSH cifrado : 2018 Wednesday-14-02  <->  2017 Tuesday-04-07   (:22)
    Web claro   : 2018 Thursday-22-02   <->  2017 Thursday-06-07  (:80)
    DoS volum.  : 2018 Friday-16-02     <->  2017 Wednesday-05-07 (:80)

QUE MIDE
--------
Sobre el servicio atacado (--service-port) y con un problema binario Attack vs
Benign, entrena en A (balanceado 1:1) y evalua en B (balanceado 1:1, de modo que
0.5 = azar). Compara tres vistas para ver CUAL generaliza entre datasets:
    - payload-hist : histograma de bytes + entropia         (MLP)
    - metadatos    : escalares de flujo (n_pkts, bytes...)   (MLP)
    - byte-cnn     : CNN 1D sobre la secuencia de bytes      (PyTorch, la clave)

Salida: models/phase2_crossdataset_<A>__<B>_p<port>.md + consola.

Ejemplos:
    # Web en claro: entrenar en 2018, testear en 2017 (y al reves con --swap-report)
    conda run -n tfg_ia python scripts/zeek/cross_dataset_eval.py \
        --train-day Thursday-22-02-2018 --test-day Thursday-06-07-2017 \
        --service-port 80 --cap 4000

    # SSH cifrado
    conda run -n tfg_ia python scripts/zeek/cross_dataset_eval.py \
        --train-day Wednesday-14-02-2018 --test-day Tuesday-04-07-2017 \
        --service-port 22 --cap 4000
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

# Reutiliza las utilidades ya validadas de la Fase 2/3 (mismo directorio).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import load_dataset, build_meta_features, make_pipeline  # noqa: E402
from service_id import service_selection  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"

RANDOM_STATE = 42
CLASSES = ["Benign", "Attack"]      # 0 = Benign, 1 = Attack (fijo en ambos datasets)


def service_subset(d, port: int, service: str | None = None):
    """Indices (globales) de los flujos del servicio y su etiqueta binaria.

    Attack = cualquier etiqueta != Benign; Benign en caso contrario. Si se indica
    `service`, el subconjunto se define por el servicio identificado por CONTENIDO
    (correccion del tutor: el puerto depende de la configuracion de cada red); si
    no, se cae al filtro historico `resp_p == port`, igual que en
    honest_by_service*.py / hybrid_compare.py.
    """
    y = d["y"].astype(str)
    idx = np.nonzero(service_selection(d, port=port, service=service))[0]
    if idx.size == 0:
        return idx, np.array([], dtype=int)
    y_bin = (y[idx] != "Benign").astype(int)   # 1 = Attack, 0 = Benign
    return idx, y_bin


def balance_indices(idx, y_bin, cap: int, rng):
    """Submuestrea 1:1 Attack/Benign (y como mucho `cap` por clase si cap>0)."""
    atk = idx[y_bin == 1]
    ben = idx[y_bin == 0]
    n = min(len(atk), len(ben))
    if cap > 0:
        n = min(n, cap)
    if n == 0:
        return np.array([], dtype=int), np.array([], dtype=int)
    sel_atk = rng.choice(atk, n, replace=False)
    sel_ben = rng.choice(ben, n, replace=False)
    sel = np.concatenate([sel_atk, sel_ben])
    y = np.concatenate([np.ones(n, dtype=int), np.zeros(n, dtype=int)])
    order = rng.permutation(len(sel))
    return sel[order], y[order]


def view_payload_hist(d, sel):
    hist = d["X_hist"][sel]
    ent = (d["entropy"][sel] / 8.0).reshape(-1, 1)
    return np.hstack([hist, ent]).astype(np.float32)


def view_seq(d, sel):
    return d["X_seq"][sel].astype(np.int64)


def metrics(y_true, y_pred):
    from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
    return {
        "acc": accuracy_score(y_true, y_pred),
        "macro_f1": f1_score(y_true, y_pred, average="macro"),
        "atk_recall": recall_score(y_true, y_pred, pos_label=1, zero_division=0),
        "atk_prec": precision_score(y_true, y_pred, pos_label=1, zero_division=0),
    }


def eval_mlp(Xtr, ytr, Xte, yte):
    clf = make_pipeline().fit(Xtr, ytr)
    return metrics(yte, clf.predict(Xte))


def eval_cnn(Xtr, ytr, Xte, yte, epochs: int):
    from dl_models import ByteCNN, set_seed, train_torch, predict_torch
    set_seed(RANDOM_STATE)
    model = ByteCNN(n_classes=2)
    train_torch(model, Xtr, ytr, epochs=epochs)
    return metrics(yte, predict_torch(model, Xte))


def fmt(m):
    return (f"acc {m['acc']:.4f} | macroF1 {m['macro_f1']:.4f} | "
            f"recall_atk {m['atk_recall']:.4f} | prec_atk {m['atk_prec']:.4f}")


def write_summary(train_day, test_day, port, rows, n_tr, n_te, out_dir):
    lines = [
        f"# Generalizacion cruzada entre datasets: train {train_day} -> test {test_day} (:{port})",
        "",
        "Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema",
        "binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos",
        "(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a",
        "cual solo memorizaba la huella del laboratorio/herramienta.",
        "",
        f"- Train ({train_day}): {n_tr} flujos balanceados (1:1).",
        f"- Test  ({test_day}): {n_te} flujos balanceados (1:1).",
        "",
        "| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |",
        "|-------|----------|----------|---------------|------------------|",
    ]
    for name, m in rows:
        lines.append(f"| {name} | {m['acc']:.4f} | {m['macro_f1']:.4f} | "
                     f"{m['atk_recall']:.4f} | {m['atk_prec']:.4f} |")
    lines += [
        "",
        "**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura",
        "la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la",
        "huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta",
        "o la app vulnerable). Es la prueba directa contra el \"100% sospechoso\".",
        "",
    ]
    out = out_dir / f"phase2_crossdataset_{train_day}__{test_day}_p{port}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train-day", required=True, help="Dia/dataset de ENTRENAMIENTO")
    ap.add_argument("--test-day", required=True, help="Dia/dataset de TEST (otro dataset)")
    ap.add_argument("--service", default=None,
                    help="Servicio identificado por CONTENIDO (ssh, http...). Via "
                         "preferente tras la correccion del tutor sobre los puertos.")
    ap.add_argument("--service-port", type=int, required=True,
                    help="Puerto del servicio atacado (22 SSH, 80 web/DoS)")
    ap.add_argument("--cap", type=int, default=4000,
                    help="Maximo de flujos por clase (0 = sin limite; controla RAM/CPU)")
    ap.add_argument("--epochs", type=int, default=8, help="Epocas del byte-CNN")
    ap.add_argument("--views", default="payload,meta,cnn",
                    help="Vistas a evaluar, separadas por comas (payload,meta,cnn)")
    args = ap.parse_args()

    MODELS_DIR.mkdir(exist_ok=True)
    want = {v.strip() for v in args.views.split(",") if v.strip()}
    rng = np.random.default_rng(RANDOM_STATE)

    print(f"== Generalizacion cruzada :{args.service_port} ==")
    print(f"   train: {args.train_day}")
    print(f"   test : {args.test_day}\n")

    d_tr = load_dataset(args.train_day)
    d_te = load_dataset(args.test_day)

    itr, ytr_bin = service_subset(d_tr, args.service_port, args.service)
    ite, yte_bin = service_subset(d_te, args.service_port, args.service)
    if itr.size == 0 or ytr_bin.sum() == 0:
        sys.exit(f"[ERROR] {args.train_day}: sin flujos de ataque en :{args.service_port}. "
                 "Verifica la ground-truth (find_attacker.py) y reconstruye el dataset.")
    if ite.size == 0 or yte_bin.sum() == 0:
        sys.exit(f"[ERROR] {args.test_day}: sin flujos de ataque en :{args.service_port}. "
                 "Verifica la ground-truth (find_attacker.py) y reconstruye el dataset.")

    sel_tr, y_tr = balance_indices(itr, ytr_bin, args.cap, rng)
    sel_te, y_te = balance_indices(ite, yte_bin, args.cap, rng)
    print(f"Train balanceado: {len(sel_tr)} flujos "
          f"(atk {int(y_tr.sum())} / ben {int((y_tr == 0).sum())})")
    print(f"Test  balanceado: {len(sel_te)} flujos "
          f"(atk {int(y_te.sum())} / ben {int((y_te == 0).sum())})\n")

    rows = []
    if "payload" in want:
        print("== payload-hist (MLP) ==")
        m = eval_mlp(view_payload_hist(d_tr, sel_tr), y_tr,
                     view_payload_hist(d_te, sel_te), y_te)
        print("  " + fmt(m)); rows.append(("payload-hist", m))
    if "meta" in want:
        print("== metadatos (MLP) ==")
        m = eval_mlp(build_meta_features(d_tr, sel_tr), y_tr,
                     build_meta_features(d_te, sel_te), y_te)
        print("  " + fmt(m)); rows.append(("metadatos", m))
    if "cnn" in want:
        print("== byte-CNN (PyTorch) ==")
        m = eval_cnn(view_seq(d_tr, sel_tr), y_tr,
                     view_seq(d_te, sel_te), y_te, args.epochs)
        print("  " + fmt(m)); rows.append(("byte-cnn", m))

    write_summary(args.train_day, args.test_day, args.service_port,
                  rows, len(sel_tr), len(sel_te), MODELS_DIR)
    print("Listo.")


if __name__ == "__main__":
    main()

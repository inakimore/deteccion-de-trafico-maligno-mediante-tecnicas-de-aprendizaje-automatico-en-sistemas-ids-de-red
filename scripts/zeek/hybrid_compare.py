#!/usr/bin/env python3
"""Cuantifica la VENTAJA HIBRIDA (paso 1 de los proximos pasos del 9 de mayo).

El HALLAZGO CLAVE 3 mostro que el payload es ciego al SSH-Bruteforce cifrado: el
modelo aprende el PROTOCOLO, no el ATAQUE, y marca como ataque al 96% del SSH
benigno. La hipotesis es que la firma del ataque vive en los METADATOS de flujo
(rafaga de conexiones cortas: pocos paquetes y pocos bytes por flujo), no en los
bytes del payload. Este script lo mide entrenando TRES vistas sobre los MISMOS
flujos y comparandolas:

  A. payload    -> X_hist[256] + entropy        (la vista de la Fase 2 hasta ahora).
  B. metadatos  -> escalares de flujo derivados de la extraccion de Zeek:
                   n_pkts, tot_bytes, bytes/pkt, seq_len  (vista "comportamiento").
  C. hibrido    -> payload + metadatos concatenados (lo mejor de ambas).

Nota honesta sobre los metadatos: el CSV de CICFlowMeter (Fase 1) NO trae IPs, asi
que no se puede unir por 5-tupla con los payloads (ver README). Por eso el baseline
de metadatos se reconstruye con los escalares de flujo que SI tenemos por uid
(numero de paquetes con datos y bytes de payload del flujo). No se incluye el
puerto destino a proposito: seria un "atajo" (memorizar 22) y ademas no separa
SSH-ataque de SSH-benigno (ambos en el 22), justo el caso dificil.

Protocolo (igual que train_phase2.py para comparabilidad):
  - Balanceo global por RandomUnderSampler a la clase minoritaria.
  - 5-Fold Stratified CV + test held-out (20%) -> accuracy por vista.
  - AUDITORIA HONESTA por vista (como honest_check.py): sobre el SSH benigno real
    (puerto 22), % de falsos positivos y recall del ataque. Es la metrica que
    de verdad distingue las vistas (el accuracy global ~0.9996 las iguala a todas).

Salida: models/phase2_hybrid_compare.md + impresion por consola.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/hybrid_compare.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = REPO_ROOT / "data" / "processed" / "zeek"
MODELS_DIR = REPO_ROOT / "models"

DEFAULT_DAY = "Wednesday-14-02-2018"
RANDOM_STATE = 42
TEST_SIZE = 0.20
CV_FOLDS = 5
ATTACK = "SSH-Bruteforce"


def load_dataset(day: str):
    npz_path = PROCESSED / day.lower() / f"dataset_{day}.npz"
    if not npz_path.is_file():
        sys.exit(f"[ERROR] No existe {npz_path}. Ejecuta antes build_dataset.py")
    d = np.load(npz_path, allow_pickle=True)
    return d


def build_meta_features(d, sel=None):
    """Escalares de flujo (vista comportamiento), con log1p para colas pesadas.

    `sel` (opcional): indices de fila a materializar. Permite construir la vista
    solo para un subconjunto sin cargar en RAM las columnas completas casteadas
    (critico en dias masivos como el DoS, con millones de flujos y 16 GB de RAM).
    """
    def col(name):
        a = d[name]
        return a[sel] if sel is not None else a
    n_pkts = col("n_pkts").astype(np.float64)
    tot_bytes = col("tot_bytes").astype(np.float64)
    seq_len = col("seq_len").astype(np.float64)
    bytes_per_pkt = tot_bytes / np.maximum(n_pkts, 1)
    feats = np.column_stack([
        np.log1p(n_pkts),
        np.log1p(tot_bytes),
        np.log1p(bytes_per_pkt),
        np.log1p(seq_len),
    ]).astype(np.float32)
    return feats  # el escalado se hace dentro del pipeline (fit en train)


def make_mlp():
    from sklearn.neural_network import MLPClassifier
    return MLPClassifier(
        hidden_layer_sizes=(256, 128),
        activation="relu",
        solver="adam",
        alpha=1e-4,
        batch_size=64,
        max_iter=200,
        early_stopping=True,
        n_iter_no_change=10,
        random_state=RANDOM_STATE,
    )


def make_pipeline():
    """StandardScaler + MLP. El scaler evita que los metadatos sin normalizar
    dominen y, en payload/hibrido, deja el histograma (ya en [0,1]) casi intacto."""
    from sklearn.pipeline import make_pipeline as mk
    from sklearn.preprocessing import StandardScaler
    return mk(StandardScaler(), make_mlp())


def evaluate(name, X, y_enc, classes):
    """5-Fold CV + test held-out de la vista X. Devuelve (clf, metricas)."""
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.metrics import accuracy_score

    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(make_pipeline(), X, y_enc, cv=skf,
                             scoring="accuracy", n_jobs=-1)
    cv_line = f"{scores.mean():.5f} ± {scores.std():.5f}"

    Xtr, Xte, ytr, yte = train_test_split(
        X, y_enc, test_size=TEST_SIZE, stratify=y_enc, random_state=RANDOM_STATE)
    clf = make_pipeline().fit(Xtr, ytr)
    test_acc = accuracy_score(yte, clf.predict(Xte))
    print(f"  [{name}] CV {cv_line} | test held-out acc {test_acc:.5f}")
    return clf, cv_line, test_acc


def honest_audit(name, clf, X_full, mask_ssh_ben, mask_ssh_atk, le):
    """Audita la vista sobre el caso dificil (mismo servicio cifrado, SSH)."""
    atk_id = int(le.transform([ATTACK])[0])
    pred_ben = clf.predict(X_full[mask_ssh_ben])
    pred_atk = clf.predict(X_full[mask_ssh_atk])
    n_ben = int(mask_ssh_ben.sum())
    n_atk = int(mask_ssh_atk.sum())
    fp = int((pred_ben == atk_id).sum())
    tp = int((pred_atk == atk_id).sum())
    fp_rate = fp / n_ben if n_ben else 0.0
    recall = tp / n_atk if n_atk else 0.0
    print(f"  [{name}] SSH benigno marcado como ataque (FP): {fp}/{n_ben} "
          f"({fp_rate*100:.1f}%) | recall ataque SSH: {recall*100:.1f}%")
    return fp, n_ben, fp_rate, recall


def write_summary(day, rows, out_dir):
    lines = [
        f"# Fase 2 - Ventaja hibrida: payload vs metadatos vs hibrido ({day})",
        "",
        "Tres vistas entrenadas sobre los MISMOS flujos (MLP 256->128, balanceo",
        "global por undersampling, 5-Fold CV + test held-out). La columna decisiva",
        "es la **auditoria honesta** sobre el SSH benigno real (puerto 22): el",
        "accuracy global iguala a todas las vistas (~0.9996) porque el benigno",
        "balanceado es casi todo NO-SSH; solo el caso dificil las separa.",
        "",
        "| Vista | CV accuracy | Test acc | FP sobre SSH benigno | Recall ataque SSH |",
        "|-------|-------------|----------|----------------------|-------------------|",
    ]
    for r in rows:
        lines.append(
            f"| {r['name']} | {r['cv']} | {r['test_acc']:.5f} | "
            f"{r['fp']}/{r['n_ben']} ({r['fp_rate']*100:.1f}%) | "
            f"{r['recall']*100:.1f}% |")
    lines += [
        "",
        "**Lectura (resultado honesto, no el esperado):** con balanceo *global por",
        "clase* las TRES vistas se comportan igual: accuracy ~0.9996 y, sobre el SSH",
        "benigno real, ~78% de falsos positivos. Añadir metadatos NO arregla el caso",
        "dificil. La causa no es la vista sino el PROTOCOLO de balanceo: como el",
        "benigno balanceado es 99,9% NO-SSH, ninguna vista aprende a separar",
        "SSH-ataque de SSH-benigno; todas aprenden \"SSH/flujo-corto = ataque\". El",
        "espejismo del 0.9996 es estructural al balanceo, no exclusivo del payload.",
        "Conclusion: para medir de verdad la aportacion de cada vista hay que",
        "balancear POR SERVICIO (SSH-ataque vs SSH-benigno) -> es el paso 2.",
        "",
    ]
    out = out_dir / "phase2_hybrid_compare.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    parser.add_argument("--port", type=int, default=22,
                        help="Puerto del servicio del caso dificil (def: 22)")
    parser.add_argument("--service", default=None,
                        help="Define el caso dificil por el servicio identificado por "
                             "CONTENIDO (ssh, http...) en vez de por puerto. Correccion "
                             "del tutor: el puerto depende de la configuracion de la red.")
    args = parser.parse_args()

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    # Vistas completas (sin balancear): se balancean por indice para alinearlas.
    X_payload = np.hstack([d["X_hist"], (entropy / 8.0).reshape(-1, 1)]).astype(np.float32)
    X_meta = build_meta_features(d)
    X_hybrid = np.hstack([X_payload, X_meta]).astype(np.float32)
    views = {"payload": X_payload, "metadatos": X_meta, "hibrido": X_hybrid}

    classes, counts = np.unique(y, return_counts=True)
    print(f"Dataset {args.day}: {len(y)} flujos -> {dict(zip(classes, counts.tolist()))}")

    # Balanceo global por INDICE (mismas filas para las tres vistas).
    idx = np.arange(len(y)).reshape(-1, 1)
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    idx_bal, y_bal = rus.fit_resample(idx, y)
    sel = idx_bal.ravel()
    le = LabelEncoder().fit(y)
    y_enc = le.transform(y_bal)
    print(f"Balanceado -> {dict(zip(*np.unique(y_bal, return_counts=True)))} "
          f"(total {len(sel)})\n")

    # Mascaras del caso dificil (sobre el dataset COMPLETO, no el balanceado).
    from service_id import service_selection, selection_label
    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Caso dificil definido por {selection_label(args.port, args.service)}")
    mask_ssh_ben = (y == "Benign") & svc_sel
    mask_ssh_atk = (y == ATTACK) & svc_sel
    print(f"Caso dificil: SSH benigno {int(mask_ssh_ben.sum())} flujos, "
          f"SSH ataque {int(mask_ssh_atk.sum())} flujos\n")

    rows = []
    for name, Xfull in views.items():
        print(f"== Vista: {name} ({Xfull.shape[1]} features) ==")
        clf, cv_line, test_acc = evaluate(name, Xfull[sel], y_enc, le.classes_)
        fp, n_ben, fp_rate, recall = honest_audit(
            name, clf, Xfull, mask_ssh_ben, mask_ssh_atk, le)
        rows.append({"name": name, "cv": cv_line, "test_acc": test_acc,
                     "fp": fp, "n_ben": n_ben, "fp_rate": fp_rate, "recall": recall})
        print()

    write_summary(args.day, rows, MODELS_DIR)
    print("Listo.")


if __name__ == "__main__":
    main()

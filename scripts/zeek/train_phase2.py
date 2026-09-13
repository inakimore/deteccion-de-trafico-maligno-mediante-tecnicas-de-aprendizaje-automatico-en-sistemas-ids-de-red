#!/usr/bin/env python3
"""Entrena el primer modelo de Deep Learning de la Fase 2 (payload).

Implementa el paso 2 del 7 de mayo: *balancear clases y entrenar el primer modelo
de Deep Learning (histograma+entropia y secuencial)* sobre el dataset etiquetado
que produce build_dataset.py (dataset_<dia>.npz).

Se entrenan DOS redes neuronales (MLPClassifier de scikit-learn) sobre las dos
representaciones definidas el 28 de abril:

  A. Histograma+entropia  -> X_hist[256] + entropy  (vista "estadistica" del flujo).
  B. Secuencial           -> X_seq[256] bytes / 255  (vista "byte a byte").

Nota honesta: el entorno tfg_ia no tiene TensorFlow/PyTorch, asi que el modelo
secuencial es un MLP denso sobre los 256 bytes, NO un CNN/RNN. Sirve como baseline
neuronal; el modelo secuencial "de verdad" (convolucional/recurrente) queda para
cuando se incorpore un framework de DL. Aun asi, ambos MLP son redes neuronales
multicapa entrenadas por backprop.

Balanceo: como en la Fase 1, se usa RandomUnderSampler (imbalanced-learn) para
igualar todas las clases a la minoritaria. Evita que el modelo se aproveche del
desbalanceo (la victima SSH domina el dataset del 14-02).

Evaluacion: 5-Fold Stratified CV sobre el conjunto balanceado + un test held-out
(20%) con classification_report y matriz de confusion. Se guardan los modelos
(joblib), las matrices de confusion (PNG) y un resumen en Markdown.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/train_phase2.py
    conda run -n tfg_ia python scripts/zeek/train_phase2.py --day Wednesday-14-02-2018
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


def load_dataset(day: str):
    """Carga X_hist, X_seq, entropy, y del dataset_<dia>.npz."""
    npz_path = PROCESSED / day.lower() / f"dataset_{day}.npz"
    if not npz_path.is_file():
        sys.exit(f"[ERROR] No existe {npz_path}. Ejecuta antes build_dataset.py")
    d = np.load(npz_path, allow_pickle=True)
    return d["X_hist"], d["X_seq"], d["entropy"], d["y"].astype(str)


def build_views(X_hist, X_seq, entropy):
    """Construye las matrices de features de cada vista.

    A) histograma+entropia: 256 columnas del histograma (ya normalizado a suma=1)
       + 1 columna de entropia escalada a [0,1] dividiendo por 8 (max bits/byte).
    B) secuencial: 256 bytes escalados a [0,1] dividiendo por 255.
    """
    X_a = np.hstack([X_hist, (entropy / 8.0).reshape(-1, 1)]).astype(np.float32)
    X_b = (X_seq.astype(np.float32) / 255.0)
    return X_a, X_b


def evaluate(name, X, y, out_dir):
    """CV estratificada + test held-out de un MLP sobre la vista X."""
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.neural_network import MLPClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler
    import joblib

    print(f"\n{'='*70}\n  Modelo: {name}\n{'='*70}")

    # 1) Balanceo por undersampling a la clase minoritaria.
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    Xb, yb = rus.fit_resample(X, y)
    # MLPClassifier con early_stopping falla con etiquetas string (hace isnan
    # sobre las predicciones); se codifican a enteros y se mapean de vuelta.
    le = LabelEncoder().fit(yb)
    yb_enc = le.transform(yb)
    classes = le.classes_
    counts = np.bincount(yb_enc)
    print(f"Balanceado -> {dict(zip(classes, counts))}  (total {len(yb)})")

    def make_mlp():
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

    # 2) 5-Fold Stratified CV (solo si hay >=2 clases y muestras suficientes).
    cv_line = "CV no aplicable (1 sola clase)"
    if len(classes) >= 2:
        skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
        scores = cross_val_score(make_mlp(), Xb, yb_enc, cv=skf, scoring="accuracy", n_jobs=-1)
        cv_line = f"{scores.mean():.5f} ± {scores.std():.5f}  (folds: {np.round(scores,4)})"
    print(f"5-Fold CV accuracy: {cv_line}")

    # 3) Test held-out 80/20.
    Xtr, Xte, ytr, yte = train_test_split(
        Xb, yb_enc, test_size=TEST_SIZE, stratify=yb_enc, random_state=RANDOM_STATE)
    clf = make_mlp().fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    label_ids = np.arange(len(classes))
    report = classification_report(yte, ypred, labels=label_ids,
                                   target_names=classes, digits=4, zero_division=0)
    cm = confusion_matrix(yte, ypred, labels=label_ids)
    print("\nTest held-out (20%):")
    print(report)
    print("Matriz de confusion (filas=real, cols=pred):")
    print(f"labels: {list(classes)}")
    print(cm)

    # 4) Guardar modelo y matriz de confusion.
    slug = name.lower().replace(" ", "_").replace("+", "").replace("__", "_")
    model_path = out_dir / f"phase2_mlp_{slug}.joblib"
    joblib.dump({"model": clf, "classes": classes, "view": name}, model_path)

    png_path = None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import ConfusionMatrixDisplay
        fig, ax = plt.subplots(figsize=(5, 4))
        ConfusionMatrixDisplay(cm, display_labels=classes).plot(ax=ax, cmap="Blues",
                                                                colorbar=False)
        ax.set_title(f"Fase 2 - {name}")
        fig.tight_layout()
        png_path = out_dir / f"phase2_cm_{slug}.png"
        fig.savefig(png_path, dpi=120)
        plt.close(fig)
    except Exception as e:  # noqa: BLE001
        print(f"[aviso] no se pudo guardar la matriz de confusion: {e}")

    return {
        "name": name,
        "n_balanced": int(len(yb)),
        "classes": [str(c) for c in classes],
        "cv": cv_line,
        "report": report,
        "cm": cm,
        "model_path": model_path,
        "png_path": png_path,
    }


def write_summary(results, day, out_dir):
    """Vuelca un resumen en Markdown en models/phase2_results.md."""
    lines = [
        f"# Fase 2 - Primer modelo de Deep Learning ({day})",
        "",
        "Redes neuronales (MLPClassifier) entrenadas sobre el dataset de payload",
        "etiquetado, con balanceo por undersampling a la clase minoritaria.",
        "",
        "> Nota: el entorno `tfg_ia` no tiene TensorFlow/PyTorch; el modelo",
        "> \"secuencial\" es un MLP denso sobre los 256 bytes (no un CNN/RNN). Ambos",
        "> son redes neuronales multicapa entrenadas por backprop.",
        "",
    ]
    for r in results:
        lines += [
            f"## {r['name']}",
            "",
            f"- Clases balanceadas: `{r['classes']}` ({r['n_balanced']} muestras).",
            f"- **5-Fold CV accuracy:** {r['cv']}",
            "",
            "Test held-out (20%):",
            "",
            "```",
            r["report"].rstrip(),
            "",
            "Matriz de confusion (filas=real, cols=pred):",
            f"labels: {r['classes']}",
            np.array2string(r["cm"]),
            "```",
            "",
        ]
        if r["png_path"] is not None:
            rel = r["png_path"].relative_to(REPO_ROOT).as_posix()
            lines += [f"![matriz de confusion {r['name']}]({rel})", ""]
    out = out_dir / "phase2_results.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    args = parser.parse_args()

    MODELS_DIR.mkdir(exist_ok=True)
    X_hist, X_seq, entropy, y = load_dataset(args.day)
    classes, counts = np.unique(y, return_counts=True)
    print(f"Dataset {args.day}: {len(y)} flujos")
    print(f"Distribucion original -> {dict(zip(classes, counts.tolist()))}")
    if len(classes) < 2:
        print("\n[aviso] El dataset tiene una sola clase con payload; el modelo no")
        print("        puede discriminar. Procesa mas capturas (run_zeek_payload.py)")
        print("        para incorporar mas trafico benigno antes de sacar conclusiones.")

    X_a, X_b = build_views(X_hist, X_seq, entropy)
    results = [
        evaluate("histograma+entropia", X_a, y, MODELS_DIR),
        evaluate("secuencial", X_b, y, MODELS_DIR),
    ]
    write_summary(results, args.day, MODELS_DIR)
    print("\nListo. Modelos y resultados en", MODELS_DIR)


if __name__ == "__main__":
    main()

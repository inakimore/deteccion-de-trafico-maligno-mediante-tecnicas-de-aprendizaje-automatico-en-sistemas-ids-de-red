#!/usr/bin/env python3
"""Evaluacion honesta POR SERVICIO para el dia de Web Attacks (payload EN CLARO).

Es el ESPEJO de honest_by_service.py (SSH). Alli el ataque viajaba cifrado y el
payload era ciego (CV ~0.57, azar): la firma vivia en la conducta/metadata. Aqui
el ataque web viaja en HTTP SIN CIFRAR contra la app DVWA (172.31.69.28:80), asi
que el contenido malicioso esta LITERALMENTE en los bytes (POST /login.php,
<script>, union select). Hipotesis a contrastar: en este regimen el **payload
gana** con holgura, invirtiendo el resultado del SSH.

Metodo (identico al del SSH para comparabilidad):
  - Se restringe al servicio atacado (puerto 80, HTTP).
  - Las 3 etiquetas de ataque del dia (Brute Force -Web, Brute Force -XSS, SQL
    Injection) se COLAPSAN en una unica clase `Web-Attack` frente a `Benign`.
  - Balanceo 1:1 Web-Attack vs Benign-HTTP (mismo servicio) por indice para alinear
    las tres vistas (payload, metadatos, hibrido).
  - 5-Fold Stratified CV + test held-out (20%), tres MLP (256->128).

Salida: models/phase2_by_service_web.md + impresion por consola.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/honest_by_service_web.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_id import service_selection, selection_label  # noqa: E402
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, TEST_SIZE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)

DEFAULT_DAY = "Thursday-22-02-2018"
PORT = 80  # servicio atacado (HTTP)
ATTACK_LABELS = ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]
ATTACK = "Web-Attack"  # etiqueta colapsada


def evaluate(name, X, y_enc, classes):
    """5-Fold CV + test held-out con classification_report y matriz de confusion."""
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.metrics import classification_report, confusion_matrix

    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(make_pipeline(), X, y_enc, cv=skf,
                             scoring="accuracy", n_jobs=-1)
    cv_line = f"{scores.mean():.4f} ± {scores.std():.4f}"

    Xtr, Xte, ytr, yte = train_test_split(
        X, y_enc, test_size=TEST_SIZE, stratify=y_enc, random_state=RANDOM_STATE)
    clf = make_pipeline().fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    ids = np.arange(len(classes))
    report = classification_report(yte, ypred, labels=ids, target_names=classes,
                                   digits=4, zero_division=0)
    cm = confusion_matrix(yte, ypred, labels=ids)
    print(f"\n== Vista: {name} ({X.shape[1]} features) ==")
    print(f"5-Fold CV accuracy: {cv_line}")
    print("Test held-out (20%):")
    print(report)
    print(f"Matriz de confusion (filas=real, cols=pred) labels={list(classes)}:")
    print(cm)
    return {"name": name, "cv": cv_line, "report": report, "cm": cm}


def write_summary(day, rows, n_atk, n_ben, classes, out_dir):
    lines = [
        f"# Fase 2 - Evaluacion honesta por servicio: Web-ataque vs HTTP-benigno ({day})",
        "",
        f"Espejo del SSH. Conjunto balanceado 1:1 sobre el servicio atacado (puerto",
        f"{PORT}, HTTP): {n_atk} `{ATTACK}` (colapsa {ATTACK_LABELS}) vs {n_ben} "
        f"`Benign`, ambos HTTP en claro. A diferencia del SSH cifrado, aqui el ataque",
        "esta en los bytes, asi que se espera que el payload gane.",
        "",
        f"Clases: `{list(classes)}`. Tres MLP (256->128), 5-Fold CV + test held-out.",
        "",
    ]
    for r in rows:
        lines += [
            f"## {r['name']}",
            "",
            f"- **5-Fold CV accuracy:** {r['cv']}",
            "",
            "```",
            r["report"].rstrip(),
            "",
            f"Matriz de confusion (filas=real, cols=pred) labels={list(classes)}:",
            np.array2string(r["cm"]),
            "```",
            "",
        ]
    out = out_dir / "phase2_by_service_web.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    parser.add_argument("--port", type=int, default=PORT,
                        help=f"Puerto del servicio atacado (def: {PORT}, HTTP)")
    parser.add_argument("--service", default=None,
                        help="Selecciona el servicio por CONTENIDO (http, ssh...) en "
                             "vez de por puerto. Correccion del tutor: el puerto "
                             "depende de la configuracion de cada red.")
    args = parser.parse_args()

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    # Colapsa las 3 etiquetas de ataque en una sola clase.
    y = np.where(np.isin(y_raw, ATTACK_LABELS), ATTACK, y_raw)
    present = {lab: int((y_raw == lab).sum()) for lab in ATTACK_LABELS}
    print(f"Etiquetas de ataque presentes: {present}")

    # Caso: solo trafico del servicio atacado (HTTP), ataque vs benigno.
    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    mask = svc_sel & ((y == ATTACK) | (y == "Benign"))
    n_total = int(mask.sum())
    y_svc = y[mask]
    n_atk = int((y_svc == ATTACK).sum())
    n_ben = int((y_svc == "Benign").sum())
    print(f"Servicio puerto {args.port}: {n_total} flujos -> "
          f"{ATTACK} {n_atk}, Benign {n_ben}")
    if n_atk == 0 or n_ben == 0:
        sys.exit("[ERROR] El caso necesita ambas clases en el servicio.")

    # Vistas completas restringidas al servicio.
    X_payload = np.hstack([d["X_hist"], (entropy / 8.0).reshape(-1, 1)]).astype(np.float32)[mask]
    X_meta = build_meta_features(d)[mask]
    X_hybrid = np.hstack([X_payload, X_meta]).astype(np.float32)
    views = {"payload": X_payload, "metadatos": X_meta, "hibrido": X_hybrid}

    # Balanceo 1:1 por INDICE para alinear las tres vistas.
    idx = np.arange(n_total).reshape(-1, 1)
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    idx_bal, y_bal = rus.fit_resample(idx, y_svc)
    sel = idx_bal.ravel()
    le = LabelEncoder().fit(y_svc)
    y_enc = le.transform(y_bal)
    print(f"Balanceado 1:1 -> {dict(zip(*np.unique(y_bal, return_counts=True)))} "
          f"(total {len(sel)})")

    rows = [evaluate(name, Xv[sel], y_enc, le.classes_) for name, Xv in views.items()]
    write_summary(args.day, rows, int((y_bal == ATTACK).sum()),
                  int((y_bal == "Benign").sum()), list(le.classes_), MODELS_DIR)
    print("\nListo.")


if __name__ == "__main__":
    main()

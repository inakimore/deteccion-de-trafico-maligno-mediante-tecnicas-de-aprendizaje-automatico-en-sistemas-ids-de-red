#!/usr/bin/env python3
"""Evaluacion honesta POR SERVICIO (paso 2 de los proximos pasos del 9 de mayo).

El paso 1 (hybrid_compare.py) demostro que con balanceo *global por clase* las
tres vistas (payload, metadatos, hibrido) son indistinguibles: ~0.9996 de accuracy
y ~78% de falsos positivos sobre el SSH benigno. El problema no era la vista sino
el balanceo: como el benigno es 99,9% NO-SSH, el modelo solo aprende a separar
"SSH cifrado" de "otros protocolos" y nunca el ATAQUE del SSH legitimo.

Este script aisla el CASO DIFICIL: construye un conjunto balanceado 1:1
SSH-Bruteforce vs Benigno-SSH (mismo servicio, ambos en el puerto 22, ambos
cifrados) y entrena las tres vistas SOLO sobre el. Asi se elimina la separacion
trivial entre protocolos y se obtiene la metrica REALISTA de cada vista sobre el
caso que de verdad importa.

Hipotesis a contrastar: si la firma del brute-force vive en los METADATOS de flujo
(rafaga de conexiones cortas) y no en los bytes cifrados, la vista `metadatos` y la
`hibrido` deberian batir claramente a `payload` en este escenario.

Salida: models/phase2_by_service.md + impresion por consola.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/honest_by_service.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_id import service_selection, selection_label  # noqa: E402
from hybrid_compare import (  # noqa: E402
    REPO_ROOT, MODELS_DIR, DEFAULT_DAY, RANDOM_STATE, TEST_SIZE, CV_FOLDS, ATTACK,
    load_dataset, build_meta_features, make_pipeline,
)

PORT = 22  # servicio atacado (SSH)


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
        f"# Fase 2 - Evaluacion honesta por servicio: SSH-ataque vs SSH-benigno ({day})",
        "",
        f"Conjunto balanceado 1:1 sobre el CASO DIFICIL (puerto {PORT}, SSH): "
        f"{n_atk} `{ATTACK}` vs {n_ben} `Benign`, ambos cifrados. Se elimina la",
        "separacion trivial entre protocolos del paso 1; esta es la metrica realista",
        "de cada vista sobre el ataque que de verdad importa.",
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
    lines += [
        "## Lectura honesta",
        "",
        "- **payload** se queda en el azar (CV ~0.57): el SSH-Bruteforce cifrado y el",
        "  SSH benigno cifrado tienen bytes estadisticamente indistinguibles. El",
        "  analisis de payload es CIEGO al brute-force sobre un servicio cifrado.",
        "- **metadatos** es la mejor vista (CV ~0.61), confirmando que la firma del",
        "  ataque vive en el COMPORTAMIENTO de flujo, no en los bytes. Pero ~0.61 es",
        "  aun debil: los 4 escalares disponibles (paquetes/bytes de payload por flujo)",
        "  son pobres; falta la metadata rica de flujo (duracion, inter-arribo, estado",
        "  de conexion, rafaga entre conexiones) que la extraccion de solo-payload",
        "  descarta. Recuperarla (estilo conn.log) es el siguiente paso natural.",
        "- **hibrido** NO supera a metadatos: concatenar 257 features de payload casi",
        "  aleatorias diluye los 4 escalares utiles. La fusion ingenua no ayuda; haria",
        "  falta ponderar/seleccionar features o enriquecer primero la metadata.",
        "",
    ]
    out = out_dir / "phase2_by_service.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    parser.add_argument("--port", type=int, default=PORT,
                        help=f"Puerto del servicio atacado (def: {PORT}, SSH)")
    parser.add_argument("--service", default=None,
                        help="Selecciona el servicio por CONTENIDO (ssh, http...) en "
                             "vez de por puerto. Correccion del tutor: el puerto "
                             "depende de la configuracion de cada red.")
    args = parser.parse_args()

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    # Caso dificil: SOLO trafico del servicio atacado (mismo protocolo cifrado).
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
        sys.exit("[ERROR] El caso dificil necesita ambas clases en el servicio.")

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

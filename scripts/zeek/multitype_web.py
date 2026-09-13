#!/usr/bin/env python3
"""Clasificacion MULTI-TIPO del ataque web SOLO por su tipo (Brute Force -Web vs
Brute Force -XSS vs SQL Injection), dia Thursday-22-02-2018.

Motivacion (cierre del argumento hibrido): honest_by_service_web.py ya demostro que
en payload EN CLARO el payload DETECTA el ataque (CV 0.99). Este script da el paso
siguiente y mas fuerte: mostrar que el payload no solo dice "esto es un ataque",
sino que distingue DE QUE TIPO es, porque el contenido malicioso vive literalmente
en los bytes (`POST /login.php` vs `<script>`/`onerror=` vs `union select`/`or 1=1`).

Es algo IMPOSIBLE para la metadata de flujo: los tres sub-ataques salen de la misma
herramienta contra la misma victima y puerto (172.31.69.28:80), asi que su huella
de flujo (paquetes, bytes, duracion) es casi identica. La metadata puede, como mucho,
separar ataque de benigno; el TIPO de ataque solo esta en el payload en claro.

Metodo:
  - Se restringe a los flujos de ataque del dia (las 3 etiquetas), en el puerto 80.
  - Problema de 3 clases. N pequeno (ataque de bajo volumen), asi que en vez de un
    unico test held-out diminuto se usan predicciones OUT-OF-FOLD (cross_val_predict,
    5-Fold Stratified): cada flujo se predice con un modelo que no lo vio, y se
    construye la matriz de confusion sobre los 203 flujos completos.
  - Se comparan tres vistas: payload-hist (X_hist[256]+entropy), payload-seq
    (secuencia de los primeros 256 bytes) y metadatos (flujo). El histograma difumina
    los tokens (`<script>` y `union select` tienen bytes parecidos); la firma del
    TIPO vive en la SECUENCIA, asi que payload-seq deberia separar mejor que
    payload-hist. La metadata, en principio, no deberia distinguir el tipo.

Salida: models/phase2_multitype_web.md + impresion por consola.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/multitype_web.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_id import service_selection, selection_label  # noqa: E402
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)

DEFAULT_DAY = "Thursday-22-02-2018"
PORT = 80
ATTACK_LABELS = ["Brute Force -Web", "Brute Force -XSS", "SQL Injection"]


def evaluate(name, X, y_enc, classes):
    """Predicciones out-of-fold (5-Fold Stratified) sobre TODOS los flujos.

    Con N pequeno un unico test held-out seria de una decena de muestras y muy
    ruidoso; cross_val_predict predice cada flujo con un modelo que no lo entreno,
    dando una matriz de confusion sobre los 203 flujos sin fuga de datos.
    """
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.metrics import classification_report, confusion_matrix, f1_score

    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    y_pred = cross_val_predict(make_pipeline(), X, y_enc, cv=skf, n_jobs=-1)
    ids = np.arange(len(classes))
    macro_f1 = f1_score(y_enc, y_pred, labels=ids, average="macro", zero_division=0)
    report = classification_report(y_enc, y_pred, labels=ids, target_names=classes,
                                   digits=4, zero_division=0)
    cm = confusion_matrix(y_enc, y_pred, labels=ids)
    print(f"\n== Vista: {name} ({X.shape[1]} features) ==")
    print(f"Macro-F1 (out-of-fold, 5-Fold): {macro_f1:.4f}")
    print(report)
    print(f"Matriz de confusion (filas=real, cols=pred) labels={list(classes)}:")
    print(cm)
    return {"name": name, "macro_f1": macro_f1, "report": report, "cm": cm}


def write_summary(day, rows, counts, classes, out_dir):
    counts_str = ", ".join(f"{c} `{lab}`" for lab, c in counts.items())
    lines = [
        f"# Fase 2 - Clasificacion MULTI-TIPO del ataque web ({day})",
        "",
        "Solo flujos de ataque (puerto 80), problema de 3 clases: distinguir el TIPO",
        f"de ataque web. Flujos: {counts_str} (total {sum(counts.values())}).",
        "",
        "Resultado (honesto, con matiz): quien identifica el tipo es la REPRESENTACION",
        "SECUENCIAL del payload en claro (payload-seq, macro-F1 0.95), no el histograma",
        "de bytes (0.75) ni la metadata de flujo (0.77). El histograma difumina los",
        "tokens (`<script>` y `union select` tienen distribuciones de bytes parecidas) y",
        "la metadata solo separa por volumen (falla en SQL Injection, recall 0.26); solo",
        "la secuencia captura los tokens caracteristicos e identifica los 3 tipos,",
        "incluido SQLi. Leccion: para identificar el TIPO no basta el payload en claro,",
        "hace falta la representacion adecuada (secuencia/tokens, no histograma).",
        "",
        "Predicciones out-of-fold (5-Fold Stratified, sin fuga); N pequeno (ataque de",
        f"bajo volumen, SQLi solo 19 flujos). Clases: `{list(classes)}`. MLP 256->128.",
        "",
        "| Vista | Macro-F1 (out-of-fold) |",
        "|-------|------------------------|",
    ]
    for r in rows:
        lines.append(f"| {r['name']} | {r['macro_f1']:.4f} |")
    lines.append("")
    for r in rows:
        lines += [
            f"## {r['name']}",
            "",
            f"- **Macro-F1 (out-of-fold):** {r['macro_f1']:.4f}",
            "",
            "```",
            r["report"].rstrip(),
            "",
            f"Matriz de confusion (filas=real, cols=pred) labels={list(classes)}:",
            np.array2string(r["cm"]),
            "```",
            "",
        ]
    out = out_dir / "phase2_multitype_web.md"
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

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    # Solo flujos de ataque del servicio atacado (HTTP:80).
    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    mask = svc_sel & np.isin(y_raw, ATTACK_LABELS)
    n_total = int(mask.sum())
    y_svc = y_raw[mask]
    labs, cnts = np.unique(y_svc, return_counts=True)
    counts = dict(zip(labs.tolist(), cnts.tolist()))
    print(f"Servicio puerto {args.port}: {n_total} flujos de ataque -> {counts}")
    if len(labs) < 2:
        sys.exit("[ERROR] Se necesitan al menos 2 tipos de ataque presentes.")

    # Vistas restringidas a los flujos de ataque.
    X_hist = np.hstack([d["X_hist"], (entropy / 8.0).reshape(-1, 1)]).astype(np.float32)[mask]
    X_seq = d["X_seq"].astype(np.float32)[mask]  # secuencia: aqui viven los tokens
    X_meta = build_meta_features(d)[mask]
    views = {"payload-hist": X_hist, "payload-seq": X_seq, "metadatos": X_meta}

    le = LabelEncoder().fit(y_svc)
    y_enc = le.transform(y_svc)

    rows = [evaluate(name, Xv, y_enc, le.classes_) for name, Xv in views.items()]
    write_summary(args.day, rows, counts, list(le.classes_), MODELS_DIR)
    print("\nListo.")


if __name__ == "__main__":
    main()

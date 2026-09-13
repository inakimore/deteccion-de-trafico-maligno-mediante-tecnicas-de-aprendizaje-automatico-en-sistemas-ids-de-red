#!/usr/bin/env python3
"""Atributos del payload (literatura) UNIDOS a las caracteristicas de Zeek.

Responde a la revision del tutor (11-ago-2026), punto 1b: "igual no me ha quedado
claro si has extraido atributos concretos del payload tipo entropia... (y los que
haya en la literatura cientifica) para unirlos a las caracteristicas obtenidas con
Zeek". Este script mide exactamente eso, en las mismas condiciones honestas que el
resto del proyecto (balanceo 1:1 por servicio, 5-Fold CV + test held-out).

Vistas comparadas
-----------------
  payload-attrs   19 descriptores interpretables del payload (payload_features.py:
                  entropia, chi2, indice de coincidencia, ratio de compresion,
                  2-gramas, composicion lexica, momentos de la distribucion de
                  bytes). Origen bibliografico documentado en ese modulo.
  payload-hist    257 = histograma de 256 bytes + entropia. La vista "clasica" del
                  proyecto desde la Fase 2, incluida para comparar.
  zeek-meta       Caracteristicas derivadas de la extraccion de Zeek: n_pkts,
                  tot_bytes, bytes/pkt, seq_len + rafaga de conexiones por origen
                  (1/5/30 s).
  zeek+attrs      LA UNION QUE PIDE EL TUTOR: descriptores del payload + Zeek.
  zeek+hist       La fusion previa (histograma completo + Zeek), para comprobar si
                  los 19 descriptores evitan la "dilucion" observada el 16 de junio
                  (257 features casi aleatorias tapaban los escalares utiles).

Seleccion del subconjunto
-------------------------
Por SERVICIO identificado por contenido (`--service ssh|http|...`, correccion del
tutor sobre los puertos) o, para reproducir resultados historicos, por `--port`.

Ejemplos
--------
    conda run -n tfg_ia python scripts/zeek/payload_attrs_eval.py \
        --day Wednesday-14-02-2018 --service ssh --cap 4000
    conda run -n tfg_ia python scripts/zeek/payload_attrs_eval.py \
        --day Thursday-22-02-2018 --service http --cap 4000
    conda run -n tfg_ia python scripts/zeek/payload_attrs_eval.py \
        --day Friday-16-02-2018 --service http --cap 4000

Salida: models/phase3_payload_attrs_<dia>_<seleccion>.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, TEST_SIZE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import build_burst_features, BURST_WINDOWS  # noqa: E402
from payload_features import (  # noqa: E402
    FEATURE_NAMES, build_payload_attr_features, describe,
)
from service_id import service_selection, selection_label  # noqa: E402

ATTACKER_EXCLUDED = True   # el benigno se limpia de la IP atacante (leccion 17-jun)


def evaluate(name, X, y_enc, classes, folds):
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.metrics import accuracy_score, f1_score

    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(make_pipeline(), X, y_enc, cv=skf,
                             scoring="accuracy", n_jobs=-1)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y_enc, test_size=TEST_SIZE, stratify=y_enc, random_state=RANDOM_STATE)
    clf = make_pipeline().fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    atk_id = list(classes).index("Attack")
    row = {
        "name": name, "n_feat": X.shape[1],
        "cv": f"{scores.mean():.4f} ± {scores.std():.4f}", "cv_mean": scores.mean(),
        "acc": accuracy_score(yte, ypred),
        "f1": f1_score(yte, ypred, pos_label=atk_id),
    }
    print(f"  [{name:14s}] {X.shape[1]:>4d} feats | CV {row['cv']} | "
          f"test acc {row['acc']:.4f} | F1 ataque {row['f1']:.4f}")
    return row, (clf, Xte, yte)


def permutation_ranking(clf, Xte, yte, names, n_repeats=5):
    """Importancia por permutacion sobre el test held-out (que atributo pesa)."""
    from sklearn.inspection import permutation_importance
    r = permutation_importance(clf, Xte, yte, n_repeats=n_repeats,
                               random_state=RANDOM_STATE, scoring="accuracy")
    order = np.argsort(-r.importances_mean)
    return [(names[i], float(r.importances_mean[i]), float(r.importances_std[i]))
            for i in order]


def write_summary(day, sel_desc, counts, rows, attrs_table, ranking, out_path):
    L = [
        f"# Atributos del payload (literatura) + caracteristicas de Zeek ({day})",
        "",
        f"Subconjunto: **{sel_desc}**. Balanceo 1:1 Attack/Benign "
        f"({counts['n_atk']:,} ataque / {counts['n_ben']:,} benigno disponibles; "
        f"{counts['n_used']:,} flujos usados tras balanceo y `--cap`).",
        "MLP 256→128 con StandardScaler, 5-Fold CV estratificada + test held-out (20%).",
        "",
        "Responde al punto 1b de la revision del tutor: extraer atributos concretos del",
        "payload (entropia y los de la literatura) y **unirlos** a las caracteristicas",
        "obtenidas con Zeek, en lugar de dejar la entropia como un escalar suelto dentro",
        "del histograma de 256 dimensiones.",
        "",
        "| Vista | nº features | CV accuracy | Test acc | F1 ataque |",
        "|-------|-------------|-------------|----------|-----------|",
    ]
    for r in rows:
        L.append(f"| `{r['name']}` | {r['n_feat']} | {r['cv']} | {r['acc']:.4f} | "
                 f"{r['f1']:.4f} |")
    L += [
        "",
        "## Atributos del payload: media por clase",
        "",
        "Los 19 descriptores son interpretables uno a uno, a diferencia del histograma",
        "de 256 dimensiones. Origen bibliografico de cada familia en `payload_features.py`.",
        "",
    ]
    L += attrs_table
    L += [
        "",
        "## Importancia por permutacion en la vista `zeek+attrs`",
        "",
        "Caida de accuracy en el test held-out al permutar cada atributo (media ± desv.",
        "sobre 5 repeticiones). Mide que aporta cada bloque en la union payload+Zeek.",
        "",
        "| Atributo | Importancia | ± |",
        "|----------|-------------|---|",
    ]
    for name, mean, std in ranking[:15]:
        L.append(f"| `{name}` | {mean:+.4f} | {std:.4f} |")
    L += ["", ""]
    out_path.write_text("\n".join(L), encoding="utf-8")
    print(f"\nResumen -> {out_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--day", required=True)
    p.add_argument("--service", default=None,
                   help="Servicio identificado por contenido (ssh, http, ssl...). "
                        "Via preferente tras la correccion del tutor.")
    p.add_argument("--port", type=int, default=None,
                   help="Alternativa historica: seleccionar por resp_p (no recomendado)")
    p.add_argument("--cap", type=int, default=4000,
                   help="Max flujos por clase tras balancear 1:1 (def: 4000)")
    p.add_argument("--folds", type=int, default=CV_FOLDS)
    args = p.parse_args()

    if not args.service and args.port is None:
        sys.exit("[ERROR] Indica --service (recomendado) o --port")

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    orig_h = d["orig_h"].astype(str)

    sel_desc = selection_label(args.port, args.service)
    print(f"Seleccionando subconjunto por {sel_desc} en {len(y_raw):,} flujos...")
    svc_mask = service_selection(d, port=args.port, service=args.service)

    attack_labels = sorted(set(y_raw[svc_mask & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en {sel_desc} de {args.day}")
    print(f"Ataques en el servicio: {attack_labels}")

    # Benigno limpio: se excluyen las IPs atacantes (leccion del 17 de junio, la
    # contaminacion del benigno por el propio atacante fuera de ventana).
    atk_ips = set(orig_h[svc_mask & np.isin(y_raw, attack_labels)])
    y = np.where(np.isin(y_raw, attack_labels), "Attack", y_raw)
    ben_ok = (y == "Benign") & (~np.isin(orig_h, list(atk_ips)) if ATTACKER_EXCLUDED
                                else np.ones(len(y), dtype=bool))
    mask = svc_mask & ((y == "Attack") | ben_ok)

    n_atk = int((y[mask] == "Attack").sum())
    n_ben = int((y[mask] == "Benign").sum())
    print(f"Disponibles -> Attack {n_atk:,} | Benign {n_ben:,} "
          f"(benigno limpio, {len(atk_ips)} IP(s) atacante(s) excluidas)")
    if n_atk == 0 or n_ben == 0:
        sys.exit("[ERROR] Falta una de las dos clases tras limpiar el benigno.")

    # Rafaga: sobre TODO el dataset (cada flujo mira a sus vecinos del mismo
    # origen), antes de subsetear.
    print(f"Calculando rafaga (ventanas {BURST_WINDOWS} s)...")
    burst = build_burst_features(d)

    idx_all = np.nonzero(mask)[0]
    y_svc = y[mask]
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    sel_local, y_bal = rus.fit_resample(np.arange(len(y_svc)).reshape(-1, 1), y_svc)
    sel = idx_all[sel_local.ravel()]
    le = LabelEncoder().fit(np.array(["Attack", "Benign"]))
    y_enc = le.transform(y_bal)

    if args.cap and args.cap > 0:
        rng = np.random.default_rng(RANDOM_STATE)
        keep = np.concatenate([
            (lambda ci: rng.choice(ci, args.cap, replace=False)
             if len(ci) > args.cap else ci)(np.nonzero(y_enc == c)[0])
            for c in np.unique(y_enc)])
        keep.sort()
        sel, y_bal, y_enc = sel[keep], y_bal[keep], y_enc[keep]

    print(f"Balance -> {dict(zip(*np.unique(y_bal, return_counts=True)))}\n")

    # Vistas (solo para `sel`: pico de RAM acotado en los dias masivos).
    print("Extrayendo atributos del payload...")
    attrs = build_payload_attr_features(d, sel)
    zeek = np.hstack([build_meta_features(d, sel), burst[sel]]).astype(np.float32)
    hist = np.hstack([d["X_hist"][sel],
                      (d["entropy"][sel] / 8.0).reshape(-1, 1)]).astype(np.float32)

    views = {
        "payload-attrs": attrs,
        "payload-hist": hist,
        "zeek-meta": zeek,
        "zeek+attrs": np.hstack([zeek, attrs]).astype(np.float32),
        "zeek+hist": np.hstack([zeek, hist]).astype(np.float32),
    }

    classes = list(le.classes_)
    rows, fitted = [], {}
    for name, Xv in views.items():
        row, model = evaluate(name, Xv, y_enc, classes, args.folds)
        rows.append(row)
        fitted[name] = model

    zeek_names = ["n_pkts", "tot_bytes", "bytes_per_pkt", "seq_len"] + \
                 [f"burst_{int(w)}s" for w in BURST_WINDOWS]
    clf, Xte, yte = fitted["zeek+attrs"]
    print("\nCalculando importancia por permutacion (zeek+attrs)...")
    ranking = permutation_ranking(clf, Xte, yte, zeek_names + FEATURE_NAMES)
    for name, mean, std in ranking[:8]:
        print(f"  {name:22s} {mean:+.4f} ± {std:.4f}")

    attrs_table = describe(attrs, y_bal, "Attack")
    tag = (args.service or f"port{args.port}")
    out = MODELS_DIR / f"phase3_payload_attrs_{args.day}_{tag}.md"
    write_summary(args.day, sel_desc,
                  {"n_atk": n_atk, "n_ben": n_ben, "n_used": len(sel)},
                  rows, attrs_table, ranking, out)


if __name__ == "__main__":
    main()

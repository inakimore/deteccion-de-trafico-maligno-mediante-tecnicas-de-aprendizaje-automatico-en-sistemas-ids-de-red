#!/usr/bin/env python3
"""Busqueda de hiperparametros: ¿estabamos dejando rendimiento sobre la mesa?

POR QUE ESTE EXPERIMENTO
------------------------
Hasta el 24-ago TODOS los modelos del trabajo usaban hiperparametros FIJOS,
elegidos a mano y nunca buscados. Para un TFG de IA es una carencia obvia, y
sobre todo deja una duda abierta: cuando el MLP pierde frente a XGBoost dentro
del dia (o al reves entre dias), ¿es una diferencia real entre modelos o solo
que uno estaba mejor ajustado que el otro?

Este script responde con una busqueda aleatoria (RandomizedSearchCV) sobre las
vistas que la memoria cita, comparando el modelo POR DEFECTO con el mejor
encontrado. Se usa busqueda aleatoria y no exhaustiva porque con este numero de
combinaciones da practicamente el mismo resultado a una fraccion del coste.

IMPORTANTE PARA LA HONESTIDAD DEL RESULTADO: la busqueda se hace SOLO con
validacion cruzada DENTRO del dia de entrenamiento. El dia de test nunca
participa en la eleccion, asi que el numero de transferencia sigue siendo
honesto (si se ajustara mirando el test, la comparacion estaria contaminada,
que es justo el error que este trabajo denuncia en otros sitios).

Uso:
    python scripts/zeek/hyperparam_search.py --day Thursday-22-02-2018 \\
        --service http --vista metadatos
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import build_burst_features  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

N_ITER = 30          # combinaciones muestreadas por modelo


def rejillas():
    """Espacios de busqueda. Nombres con el prefijo del paso del Pipeline."""
    return {
        "MLP": {
            "mlpclassifier__hidden_layer_sizes": [(128,), (256,), (256, 128),
                                                  (512, 256), (256, 128, 64)],
            "mlpclassifier__alpha": [1e-5, 1e-4, 1e-3, 1e-2],
            "mlpclassifier__learning_rate_init": [3e-4, 1e-3, 3e-3],
            "mlpclassifier__batch_size": [32, 64, 128],
        },
        "XGBoost": {
            "n_estimators": [100, 300, 600],
            "max_depth": [3, 6, 9, 12],
            "learning_rate": [0.03, 0.1, 0.3],
            "subsample": [0.7, 0.85, 1.0],
            "colsample_bytree": [0.7, 0.85, 1.0],
            "min_child_weight": [1, 3, 7],
        },
    }


def modelos_base():
    from xgboost import XGBClassifier
    return {
        "MLP": make_pipeline(),
        "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                 n_jobs=-1, tree_method="hist",
                                 eval_metric="logloss", random_state=RANDOM_STATE),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default=None)
    ap.add_argument("--vista", choices=["payload", "metadatos", "meta+rafaga"],
                    default="metadatos")
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    from sklearn.model_selection import (RandomizedSearchCV, StratifiedKFold,
                                         cross_val_score)
    from imblearn.under_sampling import RandomUnderSampler

    rng = np.random.default_rng(RANDOM_STATE)
    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    svc = service_selection(d, port=args.port, service=args.service)
    etiquetas = sorted(set(y_raw[svc & (y_raw != "Benign")]))
    y_bin = np.where(np.isin(y_raw, etiquetas), 1, np.where(y_raw == "Benign", 0, -1))
    idx = np.nonzero(svc & (y_bin >= 0))[0]
    sel_l, _ = RandomUnderSampler(random_state=RANDOM_STATE).fit_resample(
        np.arange(len(idx)).reshape(-1, 1), y_bin[idx])
    sel = idx[sel_l.ravel()]
    y = y_bin[sel]
    if args.cap > 0:
        keep = np.concatenate([
            (lambda c: rng.choice(c, args.cap, replace=False) if len(c) > args.cap else c)(
                np.nonzero(y == k)[0]) for k in (0, 1)])
        keep.sort(); sel, y = sel[keep], y[keep]

    if args.vista == "payload":
        X = np.hstack([d["X_hist"][sel],
                       (d["entropy"][sel] / 8.0).reshape(-1, 1)]).astype(np.float32)
    elif args.vista == "metadatos":
        X = build_meta_features(d, sel).astype(np.float32)
    else:
        X = np.hstack([build_meta_features(d, sel),
                       build_burst_features(d)[sel]]).astype(np.float32)

    print(f"== Busqueda de hiperparametros: {args.day}, vista {args.vista} ==")
    print(f"   {selection_label(args.port, args.service)} | "
          f"{int(y.sum())} ataque / {int((y == 0).sum())} benigno | "
          f"{X.shape[1]} caracteristicas\n")

    cv = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=RANDOM_STATE)
    resultados = {}
    for nombre, base in modelos_base().items():
        t0 = time.time()
        f1_base = float(np.mean(cross_val_score(base, X, y, cv=cv,
                                                scoring="f1_macro", n_jobs=1)))
        bus = RandomizedSearchCV(base, rejillas()[nombre], n_iter=N_ITER, cv=cv,
                                 scoring="f1_macro", random_state=RANDOM_STATE,
                                 n_jobs=1, refit=False)
        bus.fit(X, y)
        resultados[nombre] = {
            "f1_por_defecto": f1_base,
            "f1_mejor": float(bus.best_score_),
            "ganancia": float(bus.best_score_ - f1_base),
            "mejores_parametros": {k: str(v) for k, v in bus.best_params_.items()},
            "segundos": round(time.time() - t0, 1),
        }
        r = resultados[nombre]
        print(f"{nombre:9s} por defecto {r['f1_por_defecto']:.4f}  ->  "
              f"mejor {r['f1_mejor']:.4f}   ganancia {r['ganancia']:+.4f}  "
              f"({r['segundos']:.0f}s)")
        print(f"          {r['mejores_parametros']}")

    out = MODELS_DIR / f"phase3_hiperparametros_{args.day}_{args.vista}.json"
    out.write_text(json.dumps({"dia": args.day, "vista": args.vista,
                               "n_iter": N_ITER, "resultados": resultados},
                              indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

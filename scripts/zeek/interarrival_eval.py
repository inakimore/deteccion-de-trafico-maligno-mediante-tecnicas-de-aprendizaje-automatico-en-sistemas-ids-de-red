#!/usr/bin/env python3
"""Eje E - ¿Sirve el INTER-ARRIBO como vista, y aguanta la evasion? (TFG)

CONTEXTO
--------
El HALLAZGO 15 mostro que la firma del Bot (Ares, 02-03) es la PERIODICIDAD: sus
conexiones al C2 llegan con dos intervalos discretos (~0,5 s y ~2,0 s) que
concentran el 91,1% de los casos en dos bandas de 50 ms, frente a la curva suave
del trafico legitimo. Pero ese hallazgo era una MEDIDA, no un experimento:
ninguna vista del trabajo usa el inter-arribo como caracteristica de entrada.

Este script cierra el hueco. Y lo hace por la via que importa, que NO es la
exactitud dentro del dia -en el Bot todas las vistas ya rondan 0,999 y no hay
margen- sino la ROBUSTEZ ANTE EVASION, igual que el HALLAZGO 11 demostro la de
la rafaga: si el atacante camufla los primeros bytes con los de un cliente
benigno, ¿que vistas sobreviven?

    payload (byte-CNN) ... se desploma: depende del contenido
    meta+rafaga .......... invariante: cuenta conexiones, no bytes
    inter-arribo ......... invariante: mide CUANDO llegan, no que traen

La pregunta real es si el inter-arribo, ademas de invariante, SEPARA por si solo.

CARACTERISTICAS DE INTER-ARRIBO (6, por flujo)
----------------------------------------------
Para cada origen se ordenan sus flujos por tiempo y se calculan los intervalos
entre consecutivos. De cada flujo se toma:

    dt_prev, dt_next .... intervalo al flujo anterior y al siguiente del origen
    media_local ......... media de los intervalos en una ventana de W vecinos
    cv_local ............ coeficiente de variacion (std/media) de esa ventana
                          -> es LA feature del beaconing: ~0 en un metronomo
    regularidad ......... |dt_prev - dt_next| / (dt_prev + dt_next), ~0 si late
    frac_cerca_mediana .. fraccion de la ventana dentro de +-20% de su mediana

Uso:
    python scripts/zeek/interarrival_eval.py --day Friday-02-03-2018 --service http
    python scripts/zeek/interarrival_eval.py --day Friday-16-02-2018 --service http
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import build_burst_features, BURST_WINDOWS  # noqa: E402
from dl_models import ByteCNN, set_seed, train_torch, predict_torch  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

VENTANA = 8          # vecinos del mismo origen para las estadisticas locales
N_FEATS = 6


def build_interarrival_features(d) -> np.ndarray:
    """Seis caracteristicas de inter-arribo por flujo, sobre TODO el dataset.

    Se calcula antes de subsetear, igual que la rafaga: un flujo solo tiene
    intervalo si se le compara con sus vecinos del mismo origen, y filtrar antes
    romperia esa vecindad.
    """
    ts = d["ts"].astype(np.float64)
    orig = d["orig_h"].astype(str)
    n = len(ts)
    X = np.zeros((n, N_FEATS), dtype=np.float32)

    orden = np.lexsort((ts, orig))
    ini = 0
    while ini < n:
        fin = ini
        while fin + 1 < n and orig[orden[fin + 1]] == orig[orden[ini]]:
            fin += 1
        idx = orden[ini:fin + 1]                 # flujos de un origen, por tiempo
        t = ts[idx]
        m = len(t)
        if m >= 3:
            dt = np.diff(t)                       # m-1 intervalos
            dt_prev = np.concatenate([[dt[0]], dt])
            dt_next = np.concatenate([dt, [dt[-1]]])
            suma = dt_prev + dt_next
            regularidad = np.abs(dt_prev - dt_next) / np.where(suma > 0, suma, 1.0)

            media_l = np.zeros(m, dtype=np.float64)
            cv_l = np.zeros(m, dtype=np.float64)
            frac_l = np.zeros(m, dtype=np.float64)
            for k in range(m):
                a = max(0, k - VENTANA // 2)
                b = min(len(dt), k + VENTANA // 2)
                w = dt[a:b] if b > a else dt[:1]
                mu = float(np.mean(w))
                media_l[k] = mu
                cv_l[k] = float(np.std(w)) / mu if mu > 0 else 0.0
                med = float(np.median(w))
                frac_l[k] = float(np.mean(np.abs(w - med) <= 0.2 * med)) if med > 0 else 0.0

            X[idx, 0] = dt_prev
            X[idx, 1] = dt_next
            X[idx, 2] = media_l
            X[idx, 3] = cv_l
            X[idx, 4] = regularidad
            X[idx, 5] = frac_l
        ini = fin + 1

    # log1p en los tiempos: los intervalos abarcan varios ordenes de magnitud
    X[:, 0:3] = np.log1p(X[:, 0:3])
    return X


def recall_attack(y_pred) -> float:
    return float(np.mean(y_pred == 1))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default=None)
    ap.add_argument("--prefix", type=int, default=160,
                    help="Bytes iniciales que camufla el atacante")
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--test-size", type=float, default=0.3)
    args = ap.parse_args()

    from sklearn.model_selection import train_test_split
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    set_seed(RANDOM_STATE)
    rng = np.random.default_rng(RANDOM_STATE)

    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en {selection_label(args.port, args.service)}")
    print(f"Ataques: {attack_labels}")

    print(f"Calculando rafaga (ventanas {BURST_WINDOWS} s) sobre {len(y_raw)} flujos...")
    burst = build_burst_features(d)
    print(f"Calculando inter-arribo (ventana de {VENTANA} vecinos)...")
    inter = build_interarrival_features(d)

    y_bin_full = np.where(np.isin(y_raw, attack_labels), 1,
                          np.where(y_raw == "Benign", 0, -1))
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
    print(f"Balance -> attack {int((y == 1).sum())} / benign {int((y == 0).sum())}\n")

    X_seq = d["X_seq"][sel].astype(np.int64)
    meta = build_meta_features(d, sel)
    v_meta_raf = np.hstack([meta, burst[sel]]).astype(np.float32)
    v_inter = inter[sel].astype(np.float32)
    v_meta_int = np.hstack([meta, inter[sel]]).astype(np.float32)

    ii = np.arange(len(y))
    tr, te = train_test_split(ii, test_size=args.test_size, stratify=y,
                              random_state=RANDOM_STATE)
    atk_te = te[y[te] == 1]
    ben_te = te[y[te] == 0]

    print("Entrenando byte-CNN (payload)...")
    modelo = ByteCNN(n_classes=2)
    train_torch(modelo, X_seq[tr], y[tr], epochs=args.epochs)
    rec_orig = recall_attack(predict_torch(modelo, X_seq[atk_te]))
    X_ev = X_seq[atk_te].copy()
    donantes = rng.choice(ben_te, len(atk_te), replace=True)
    pfx = min(args.prefix, X_seq.shape[1])
    X_ev[:, :pfx] = X_seq[donantes][:, :pfx]
    rec_evad = recall_attack(predict_torch(modelo, X_ev))

    filas = [("payload (byte-CNN)", rec_orig, rec_evad)]
    for nombre, V in (("meta+rafaga", v_meta_raf),
                      ("inter-arribo SOLO", v_inter),
                      ("meta+inter-arribo", v_meta_int)):
        print(f"Entrenando {nombre}...")
        clf = make_pipeline().fit(V[tr], y[tr])
        r = recall_attack(clf.predict(V[atk_te]))
        filas.append((nombre, r, r))       # invariantes al spoofing de bytes

    print("\n================ EVASION: QUE VISTA SOBREVIVE ================")
    for nombre, ro, re_ in filas:
        caida = ro - re_
        marca = "  <-- se desploma" if caida > 0.2 else ""
        print(f"{nombre:22s} original {ro:.4f} | evadido {re_:.4f} | "
              f"caida {caida:.4f}{marca}")

    lines = [
        f"# Eje E - El inter-arribo como vista, y su robustez ante evasion ({args.day})",
        "",
        f"Binario Attack vs Benign en {selection_label(args.port, args.service)}, "
        f"balanceado 1:1, split {int((1-args.test_size)*100)}/{int(args.test_size*100)}. "
        f"El atacante camufla los primeros **{pfx} bytes** de cada flujo de ataque con los "
        "de un cliente benigno; el resto del flujo no cambia.",
        "",
        "| Vista | Recall ataque (original) | Recall ataque (evadido) | Caida |",
        "|-------|--------------------------|-------------------------|-------|",
    ]
    for nombre, ro, re_ in filas:
        lines.append(f"| {nombre} | {ro:.4f} | {re_:.4f} | **{ro - re_:.4f}** |")
    lines += [
        "",
        f"Caracteristicas de inter-arribo ({N_FEATS}, ventana de {VENTANA} vecinos del mismo "
        "origen): `dt_prev`, `dt_next`, `media_local`, **`cv_local`** (coeficiente de "
        "variacion: ~0 en un metronomo), `regularidad` y `frac_cerca_mediana`. Se calculan "
        "desde el `.npz` (`ts` + `orig_h`), **sin necesidad del `conn.log`**.",
        "",
        "Las tres vistas conductuales son **invariantes al spoofing de payload** por "
        "construccion: no miran el contenido de los bytes, sino cuando llegan los flujos y "
        "cuantos hay. Por eso su recall evadido es identico al original.",
        "",
    ]
    out = MODELS_DIR / f"phase3_interarribo_{args.day}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

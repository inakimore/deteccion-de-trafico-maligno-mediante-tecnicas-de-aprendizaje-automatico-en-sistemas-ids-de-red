#!/usr/bin/env python3
"""IC 95% (bootstrap) del MACRO-F1 en el caso dificil de un dia cualquiera.

MOTIVO
------
Las cifras que circulaban de los "casos dificiles" (0.9908/0.9793/1.0000 en el
SSH del 14-02; 0.9877/0.9286 en el web del 22-02) son **exactitud en validacion
cruzada**, no macro-F1, y los resumenes antiguos daban ademas el F1 de la clase
ataque sobre un unico test held-out, donde las vistas saturan y el ranking
desaparece. Para la memoria hace falta:

  1. **macro-F1 out-of-fold**, coherente con la metrica que se declara en el
     capitulo de metodologia (y no la exactitud, que alli se critica).
  2. Un **intervalo de confianza**, porque las clases son pequenas (358 benignos
     genuinos en el SSH, 203 flujos de ataque en el web) y un F1 de 0.99 sobre
     unos cientos de ejemplos, sin intervalo, no distingue una vista de otra.
  3. El **recall de la clase de ataque**, que se reporta siempre por separado.

Y sobre todo hace falta que las TRES VISTAS se midan en TODOS los dias. La
figura F19 comparaba `meta-rica` (con rafaga) en el lado SSH contra
`build_meta_features` (sin rafaga) en el lado web, ambas rotuladas igual: el dia
web nunca se habia evaluado con la vista conductual. Este script evalua siempre
las mismas tres vistas, de modo que los dias son comparables entre si.

CASO DIFICIL: ataque contra benigno GENUINO (de terceros) del MISMO servicio.
Comparar contra benigno diverso mide la capacidad de distinguir servicios, no de
detectar el ataque.

MEMORIA: los dias DoS tienen millones de flujos y materializar `X_hist` entero
por vista no cabe en 16 GB. Se resuelven primero TODAS las selecciones
(repeticiones x clases), se toma su union -- a lo sumo `2 * cap * repeticiones`
filas -- y solo esas se materializan. El resto del dataset nunca se castea.

Salida: models/phase2_ic_caso_dificil_<day>.md

Ejemplos:
    conda run --no-capture-output -n tfg_ia python -u \
        scripts/zeek/ic_caso_dificil.py --day Wednesday-14-02-2018 --service ssh
    conda run --no-capture-output -n tfg_ia python -u \
        scripts/zeek/ic_caso_dificil.py --day Friday-16-02-2018 --port 80 --service http
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, DEFAULT_DAY, RANDOM_STATE, CV_FOLDS,
    load_dataset, build_meta_features, make_pipeline,
)
from honest_by_service_rich import (  # noqa: E402
    build_burst_features, BURST_WINDOWS,
)
from service_id import service_selection, selection_label  # noqa: E402
from attack_metadata import DAYS  # noqa: E402

N_BOOT = 2000           # remuestreos de bootstrap, repartidos entre repeticiones
N_REPS = 10             # semillas distintas de submuestreo 1:1
CAP = 5000              # tope de flujos por clase y repeticion
POS = "Ataque"          # nombre de la clase positiva ya colapsada
BENIGN = "Benign"


def etiquetas_de_ataque(y, mask, explicitas=None):
    """Etiquetas de ataque a colapsar en la clase positiva.

    Por defecto se deducen de los DATOS: cualquier etiqueta distinta de Benign
    presente bajo la mascara del servicio. Asi el script vale para el SSH (una
    etiqueta) y para el dia web (tres: Brute Force -Web / -XSS / SQL Injection)
    sin cablear nada. Se pueden forzar con --attack.
    """
    if explicitas:
        return [e.strip() for e in explicitas.split(",") if e.strip()]
    return sorted({str(lab) for lab in np.unique(y[mask]) if str(lab) != BENIGN})


def ips_atacantes(day, labels):
    """Union de las IPs atacantes documentadas de esas etiquetas."""
    ips = set()
    for a in DAYS[day]["attacks"]:
        if a["label"] in labels:
            ips |= set(a["attacker_ips"])
    return ips


def selecciones(idx_atk, idx_ben, n_reps, cap, seed=RANDOM_STATE):
    """Indices balanceados 1:1 (con tope) para cada repeticion.

    Se resuelven TODAS antes de materializar nada, para poder cargar solo su
    union. Cada repeticion usa su propia semilla: cuales flujos entran mueve el
    punto estimado justo en la cifra decimal donde se separan las vistas, asi
    que se promedia en vez de fijar una semilla arbitraria.
    """
    n = min(len(idx_atk), len(idx_ben), cap)
    out = []
    for r in range(n_reps):
        rng = np.random.default_rng(seed + r)
        a = rng.choice(idx_atk, size=n, replace=False)
        b = rng.choice(idx_ben, size=n, replace=False)
        out.append((a, b))
    return out, n


def oof_pred(X, y_enc):
    """Prediccion out-of-fold: cada flujo lo predice el modelo que no lo vio."""
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    return cross_val_predict(make_pipeline(), X, y_enc, cv=skf, n_jobs=-1)


def boot_vals(y_true, y_pred, metric, n_boot, seed=RANDOM_STATE):
    """Valores de la metrica sobre n_boot remuestreos del conjunto evaluado.

    Se remuestrea el conjunto de evaluacion (no se reentrena): mide la
    incertidumbre debida al tamano de la muestra. Devuelve la lista para poder
    AGRUPAR los valores de varias repeticiones de submuestreo, de modo que el
    intervalo recoja tambien esa segunda fuente de variabilidad.
    """
    rng = np.random.default_rng(seed)
    n = len(y_true)
    vals = []
    for _ in range(n_boot):
        ix = rng.integers(0, n, n)
        if len(np.unique(y_true[ix])) < 2:
            continue
        vals.append(metric(y_true[ix], y_pred[ix]))
    return vals


def construir_vistas(d, union, burst):
    """Materializa las tres vistas SOLO para las filas de `union`.

    Devuelve tambien el mapa fila_global -> posicion en las matrices, porque a
    partir de aqui se trabaja con posiciones locales.
    """
    pos = {int(g): i for i, g in enumerate(union)}
    hist = d["X_hist"][union].astype(np.float32)
    ent = (d["entropy"][union] / 8.0).astype(np.float32).reshape(-1, 1)
    meta = build_meta_features(d, sel=union).astype(np.float32)
    vistas = {
        "payload (histograma + entropia)": np.hstack([hist, ent]),
        "metadatos de flujo": meta,
        "conducta (metadatos + rafaga)": np.hstack([meta, burst[union]]).astype(np.float32),
    }
    return vistas, pos


def evaluar(nombre, sels, vistas, pos, n_atk, n_ben, n_por_clase, metricas):
    """Evalua las tres vistas sobre cada repeticion y agrupa los resultados."""
    macro_f1, rec_atk = metricas
    print(f"\n### {nombre}: ataque {n_atk}, Benign {n_ben}")
    print(f"   Balanceado 1:1 -> {2 * n_por_clase} flujos por repeticion, "
          f"{len(sels)} repeticiones")

    boot_por_rep = max(1, N_BOOT // len(sels))
    acum = {v: {"f1": [], "rec": [], "f1_pt": [], "rec_pt": []} for v in vistas}

    for r, (ia, ib) in enumerate(sels):
        loc = np.array([pos[int(g)] for g in np.concatenate([ia, ib])])
        y_enc = np.concatenate([np.ones(len(ia), int), np.zeros(len(ib), int)])
        for vista, X in vistas.items():
            pred = oof_pred(X[loc], y_enc)
            a = acum[vista]
            a["f1_pt"].append(macro_f1(y_enc, pred))
            a["rec_pt"].append(rec_atk(y_enc, pred))
            a["f1"].extend(boot_vals(y_enc, pred, macro_f1, boot_por_rep,
                                     seed=RANDOM_STATE + r))
            a["rec"].extend(boot_vals(y_enc, pred, rec_atk, boot_por_rep,
                                      seed=RANDOM_STATE + r))

    filas = []
    for vista in vistas:
        a = acum[vista]
        f1_pt, f1_sd = float(np.mean(a["f1_pt"])), float(np.std(a["f1_pt"]))
        rc_pt = float(np.mean(a["rec_pt"]))
        f_lo, f_hi = np.percentile(a["f1"], [2.5, 97.5])
        r_lo, r_hi = np.percentile(a["rec"], [2.5, 97.5])
        filas.append((vista, f1_pt, float(f_lo), float(f_hi),
                      rc_pt, float(r_lo), float(r_hi), f1_sd))
        print(f"   [{vista:34s}] macro-F1 {f1_pt:.4f} [{f_lo:.4f}, {f_hi:.4f}]"
              f" (sd {f1_sd:.4f}) | recall {rc_pt:.4f} [{r_lo:.4f}, {r_hi:.4f}]")
    return {"label": nombre, "n_atk": n_atk, "n_ben": n_ben,
            "n_por_clase": n_por_clase, "n_reps": len(sels), "filas": filas}


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", default=DEFAULT_DAY)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--service", default="ssh")
    ap.add_argument("--repeticiones", type=int, default=N_REPS,
                    help=f"Submuestreos 1:1 con semillas distintas (def: {N_REPS}).")
    ap.add_argument("--cap", type=int, default=CAP,
                    help=f"Tope de flujos por clase y repeticion (def: {CAP}). "
                         "Necesario en los dias DoS, con millones de flujos.")
    ap.add_argument("--attack", default=None,
                    help="Etiquetas de ataque separadas por coma. Por defecto se "
                         "deducen de los datos.")
    args = ap.parse_args()

    from sklearn.metrics import f1_score, recall_score

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    orig_h = d["orig_h"].astype(str)

    svc = service_selection(d, port=args.port, service=args.service)
    print("Seleccion del servicio:", selection_label(args.port, args.service))

    labels = etiquetas_de_ataque(y_raw, svc, args.attack)
    if not labels:
        sys.exit("No hay etiquetas de ataque bajo ese servicio.")
    conteo = {lab: int((y_raw[svc] == lab).sum()) for lab in labels}
    print(f"Etiquetas colapsadas en '{POS}': {conteo}")

    atk_ips = ips_atacantes(args.day, labels)
    print("   IPs atacantes documentadas:", sorted(atk_ips) or "(ninguna)")

    is_atk = np.isin(y_raw, labels)
    is_ben = (y_raw == BENIGN)
    is_atk_ip = np.isin(orig_h, list(atk_ips))

    n_contaminantes = int((svc & is_ben & is_atk_ip).sum())
    aviso = None
    if not n_contaminantes:
        aviso = (
            "El escenario **contaminado no es reproducible** desde este `.npz`: no "
            "queda ningun flujo etiquetado `Benign` procedente de una IP atacante "
            "bajo este servicio. La correccion del limite de ventana ya reetiqueto "
            "esos flujos como ataque, de modo que la contaminacion esta corregida "
            "en el propio conjunto de datos y no en tiempo de evaluacion."
        )
        print("\n[aviso] escenario contaminado no reproducible "
              "(0 flujos Benign de IP atacante bajo este servicio).")
    else:
        print(f"\n[info] {n_contaminantes} flujos Benign proceden de una IP atacante.")

    idx_atk = np.flatnonzero(svc & is_atk)
    idx_ben = np.flatnonzero(svc & is_ben & ~is_atk_ip)
    if len(idx_atk) == 0 or len(idx_ben) == 0:
        sys.exit(f"Faltan clases: ataque {len(idx_atk)}, benigno genuino {len(idx_ben)}")

    sels, n_por_clase = selecciones(idx_atk, idx_ben, args.repeticiones, args.cap)
    union = np.unique(np.concatenate([np.concatenate([a, b]) for a, b in sels]))
    print(f"\nFilas distintas a materializar: {len(union)} "
          f"(de {len(y_raw)} del dia)")

    print(f"Calculando features de rafaga (ventanas {BURST_WINDOWS})...")
    burst = build_burst_features(d)

    vistas, pos = construir_vistas(d, union, burst)

    def macro_f1(a, b):
        return f1_score(a, b, average="macro", zero_division=0)

    def rec_atk(a, b):
        return recall_score(a, b, pos_label=1, zero_division=0)

    e = evaluar("limpio (Benign de terceros)", sels, vistas, pos,
                len(idx_atk), len(idx_ben), n_por_clase, (macro_f1, rec_atk))

    L = [
        f"# IC 95% del caso dificil - {args.day}",
        "",
        f"Servicio: {selection_label(args.port, args.service)}. Clase positiva: "
        f"`{POS}` = {conteo}. Metrica **out-of-fold** ({CV_FOLDS}-Fold "
        f"estratificado). El macro-F1 es la **media sobre {e['n_reps']} submuestreos "
        f"1:1 con semillas distintas** (tope {args.cap} por clase), y el IC 95% "
        f"agrupa los {N_BOOT} remuestreos de bootstrap repartidos entre ellos: "
        f"recoge la incertidumbre del tamano de muestra Y la de que flujos "
        f"concretos entran en el balanceo.",
        "",
        f"Ataque {e['n_atk']}, Benign genuino {e['n_ben']}; "
        f"{2 * e['n_por_clase']} flujos evaluados por repeticion.",
        "",
        "| Vista | Macro-F1 [IC 95%] | sd entre repeticiones | Recall ataque [IC 95%] |",
        "|---|---|---|---|",
    ]
    for vista, f1_pt, f_lo, f_hi, rc_pt, r_lo, r_hi, f1_sd in e["filas"]:
        L.append(f"| {vista} | {f1_pt:.4f} [{f_lo:.4f}, {f_hi:.4f}] | {f1_sd:.4f} "
                 f"| {rc_pt:.4f} [{r_lo:.4f}, {r_hi:.4f}] |")
    L.append("")
    if aviso:
        L += [aviso, ""]
    L += [
        "**Por que este fichero existe:** las cifras que se venian citando de los "
        "casos dificiles son **exactitud en validacion cruzada**, no macro-F1, y "
        "no todas las vistas se habian medido en todos los dias (la vista "
        "conductual faltaba en el dia web). Aqui las tres vistas se miden igual en "
        "todos los dias, con la metrica que declara la memoria y con intervalo.",
        "",
    ]
    out = MODELS_DIR / f"phase2_ic_caso_dificil_{args.day}.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Leave-One-Attacker-Out: romper el atajo del host y ver si las vistas se separan.

MOTIVO (HALLAZGO 19)
--------------------
La evaluacion intra-dia esta saturada: las tres vistas dan >=0.97 en los seis
dias. La causa propuesta es que cada dia tiene UN SOLO host atacante, de modo
que cualquier representacion puede memorizar lo idiosincrasico de ese host en
lugar de aprender el ataque. Esa explicacion, tal cual, es una hipotesis: no se
puede contrastar en un dia con un unico atacante.

El DDoS del 20-02 si permite contrastarla porque tiene **diez hosts atacantes**
con ~29.000 flujos cada uno. Si el exito intra-dia se debe a memorizar el host,
evaluar sobre un atacante NUNCA VISTO deberia hundirlo. Si no se hunde, lo que
la vista aprende no es la identidad del host.

PROTOCOLO
---------
Diez pliegues. En cada uno:
  - se aparta un host atacante entero y se entrena con los otros nueve;
  - se aparta ademas un grupo disjunto de hosts BENIGNOS, para que tampoco la
    clase negativa se pueda memorizar por host;
  - se entrena y se predice con tamanos fijos, iguales en todos los pliegues.

DOS CONTROLES (ambos imprescindibles)
------------------------------------
1. **Control negativo**: los MISMOS tamanos con particion ALEATORIA, ignorando
   el host. Sin el, una caida podria deberse al tamano del entrenamiento y no al
   cambio de host. La comparacion informativa es LOAO frente a este control.
2. **Control positivo**: una cuarta vista deliberadamente tramposa, los cuatro
   octetos de la IP de origen, que no puede sino memorizar el host. Debe dar
   ~1.0 en la particion aleatoria y DESPLOMARSE en LOAO. Si no se desploma, el
   protocolo no es sensible al efecto que pretende medir y ningun resultado
   negativo de las otras vistas seria creible.

MATIZ SOBRE LO QUE ESTE TEST PUEDE Y NO PUEDE DECIR
---------------------------------------------------
Los diez atacantes ejecutan la MISMA herramienta (LOIC). Por tanto el test
distingue "memoriza este host" de "aprende la herramienta o la conducta", pero
NO puede distinguir "aprende la herramienta" de "aprende el ataque": para eso
hacen falta la evasion y la transferencia entre dominios. Conviene decirlo antes
de leer los resultados.

Salida: models/phase3_loao_<day>.md

Ejemplo:
    conda run --no-capture-output -n tfg_ia python -u \
        scripts/zeek/loao_eval.py --day Tuesday-20-02-2018 --port 80 --service http
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
from service_id import service_selection, selection_label  # noqa: E402

N_TRAIN = 5000          # por clase
N_TEST = 2000           # por clase
BENIGN = "Benign"


def muestrear(rng, pool, n):
    """n indices de `pool` sin reemplazo (o el pool entero si es menor)."""
    if len(pool) <= n:
        return np.asarray(pool)
    return rng.choice(pool, size=n, replace=False)


def octetos_ip(orig_sel):
    """Los cuatro octetos de la IP de origen, como vector numerico.

    CONTROL POSITIVO: es un identificador de host puro. Se incluye para
    comprobar que el protocolo detecta la memorizacion de host cuando existe.
    No es una vista candidata: no debe leerse como un resultado.
    """
    out = np.zeros((len(orig_sel), 4), dtype=np.float32)
    for i, ip in enumerate(orig_sel):
        partes = str(ip).split(".")
        if len(partes) == 4:
            try:
                out[i] = [float(p) for p in partes]
            except ValueError:
                pass
    return out


def construir_vistas(d, union, burst):
    """Materializa las vistas SOLO para las filas de `union`."""
    pos = {int(g): i for i, g in enumerate(union)}
    hist = d["X_hist"][union].astype(np.float32)
    ent = (d["entropy"][union] / 8.0).astype(np.float32).reshape(-1, 1)
    meta = build_meta_features(d, sel=union).astype(np.float32)
    vistas = {
        "payload (histograma + entropia)": np.hstack([hist, ent]),
        "metadatos de flujo": meta,
        "conducta (metadatos + rafaga)":
            np.hstack([meta, burst[union]]).astype(np.float32),
        "[control] octetos de la IP de origen":
            octetos_ip(d["orig_h"].astype(str)[union]),
    }
    return vistas, pos


def evaluar_pliegues(pliegues, d, burst, metricas):
    """Entrena y evalua las tres vistas en cada pliegue ya definido por indices."""
    macro_f1, rec_atk = metricas
    union = np.unique(np.concatenate(
        [np.concatenate(p) for p in pliegues.values()]))
    print(f"   Materializando {len(union)} filas de {len(d['y'])}...")
    vistas, pos = construir_vistas(d, union, burst)

    res = {v: {"f1": [], "rec": []} for v in vistas}
    for nombre, (tr_a, tr_b, te_a, te_b) in pliegues.items():
        loc = lambda ix: np.array([pos[int(g)] for g in ix])  # noqa: E731
        itr = np.concatenate([loc(tr_a), loc(tr_b)])
        ite = np.concatenate([loc(te_a), loc(te_b)])
        ytr = np.concatenate([np.ones(len(tr_a), int), np.zeros(len(tr_b), int)])
        yte = np.concatenate([np.ones(len(te_a), int), np.zeros(len(te_b), int)])
        for vista, X in vistas.items():
            clf = make_pipeline().fit(X[itr], ytr)
            pred = clf.predict(X[ite])
            res[vista]["f1"].append(macro_f1(yte, pred))
            res[vista]["rec"].append(rec_atk(yte, pred))
        print(f"      {nombre}: " + " | ".join(
            f"{v.split(' ')[0]} {res[v]['f1'][-1]:.4f}" for v in vistas))
    return res


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", default="Tuesday-20-02-2018")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--service", default="http")
    args = ap.parse_args()

    from sklearn.metrics import f1_score, recall_score

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y = d["y"].astype(str)
    orig = d["orig_h"].astype(str)
    svc = service_selection(d, port=args.port, service=args.service)
    print("Servicio:", selection_label(args.port, args.service))

    labels = sorted({l for l in np.unique(y[svc]) if l != BENIGN})
    is_atk = svc & np.isin(y, labels)
    is_ben = svc & (y == BENIGN)
    print("Etiquetas de ataque:", labels)

    hosts_atk = sorted({h for h in np.unique(orig[is_atk])})
    if len(hosts_atk) < 3:
        sys.exit(f"Este dia solo tiene {len(hosts_atk)} host(s) atacante(s): "
                 "el test leave-one-attacker-out no es aplicable.")
    hosts_ben = np.array(sorted({h for h in np.unique(orig[is_ben])}))
    print(f"Hosts atacantes: {len(hosts_atk)} | hosts benignos: {len(hosts_ben)}")

    idx_atk_por_host = {h: np.flatnonzero(is_atk & (orig == h)) for h in hosts_atk}

    rng = np.random.default_rng(RANDOM_STATE)
    orden_ben = rng.permutation(len(hosts_ben))
    grupos_ben = np.array_split(hosts_ben[orden_ben], len(hosts_atk))

    def bolsa(hosts):
        return np.flatnonzero(is_ben & np.isin(orig, list(hosts)))

    def macro_f1(a, b):
        return f1_score(a, b, average="macro", zero_division=0)

    def rec_atk(a, b):
        return recall_score(a, b, pos_label=1, zero_division=0)

    # ------------------------------------------------------------ LOAO
    print(f"\n### Leave-one-attacker-out ({len(hosts_atk)} pliegues)")
    pliegues = {}
    for i, h in enumerate(hosts_atk):
        r = np.random.default_rng(RANDOM_STATE + i)
        te_a = muestrear(r, idx_atk_por_host[h], N_TEST)
        tr_a = muestrear(r, np.concatenate(
            [idx_atk_por_host[o] for o in hosts_atk if o != h]), N_TRAIN)
        te_b = muestrear(r, bolsa(grupos_ben[i]), N_TEST)
        tr_b = muestrear(r, bolsa(np.concatenate(
            [g for j, g in enumerate(grupos_ben) if j != i])), N_TRAIN)
        pliegues[f"sin {h}"] = (tr_a, tr_b, te_a, te_b)
    res_loao = evaluar_pliegues(pliegues, d, burst_global(d), (macro_f1, rec_atk))

    # --------------------------------------------------------- CONTROL
    print(f"\n### Control: particion ALEATORIA, mismos tamanos "
          f"({len(hosts_atk)} pliegues)")
    todos_a = np.flatnonzero(is_atk)
    todos_b = np.flatnonzero(is_ben)
    pliegues_c = {}
    for i in range(len(hosts_atk)):
        r = np.random.default_rng(RANDOM_STATE + 1000 + i)
        sa = muestrear(r, todos_a, N_TRAIN + N_TEST)
        sb = muestrear(r, todos_b, N_TRAIN + N_TEST)
        pliegues_c[f"aleatorio {i}"] = (sa[:N_TRAIN], sb[:N_TRAIN],
                                        sa[N_TRAIN:], sb[N_TRAIN:])
    res_ctrl = evaluar_pliegues(pliegues_c, d, burst_global(d), (macro_f1, rec_atk))

    escribir_resumen(args, labels, hosts_atk, hosts_ben, res_loao, res_ctrl)


_BURST = {}


def burst_global(d):
    """Rafaga sobre TODO el dia (causal, por origen). Se calcula una sola vez."""
    if "b" not in _BURST:
        print(f"Calculando features de rafaga (ventanas {BURST_WINDOWS})...")
        _BURST["b"] = build_burst_features(d)
    return _BURST["b"]


def escribir_resumen(args, labels, hosts_atk, hosts_ben, res_loao, res_ctrl):
    L = [
        f"# Leave-one-attacker-out - {args.day}",
        "",
        f"Servicio: {selection_label(args.port, args.service)}. Clase positiva: "
        f"{labels}. **{len(hosts_atk)} hosts atacantes** y {len(hosts_ben)} hosts "
        f"benignos.",
        "",
        f"Cada pliegue aparta un host atacante entero **y** un grupo disjunto de "
        f"hosts benignos, entrena con {N_TRAIN} flujos por clase y evalua sobre "
        f"{N_TEST} por clase. El **control** usa exactamente los mismos tamanos "
        f"con particion aleatoria por flujo, ignorando el host: sin el, una caida "
        f"podria deberse al tamano del entrenamiento y no al cambio de host.",
        "",
        "| Vista | Control (aleatorio) | LOAO (atacante no visto) | Diferencia |",
        "|---|---|---|---|",
    ]
    for vista in res_loao:
        c = np.array(res_ctrl[vista]["f1"])
        l_ = np.array(res_loao[vista]["f1"])
        L.append(f"| {vista} | {c.mean():.4f} ± {c.std():.4f} "
                 f"| {l_.mean():.4f} ± {l_.std():.4f} "
                 f"| {l_.mean() - c.mean():+.4f} |")
    L += ["", "Recall de la clase de ataque:", "",
          "| Vista | Control | LOAO |", "|---|---|---|"]
    for vista in res_loao:
        c = np.array(res_ctrl[vista]["rec"])
        l_ = np.array(res_loao[vista]["rec"])
        L.append(f"| {vista} | {c.mean():.4f} ± {c.std():.4f} "
                 f"| {l_.mean():.4f} ± {l_.std():.4f} |")
    L += [
        "",
        "**Como leer la tabla.** Si el exito intra-dia se debiera a memorizar el "
        "host atacante, la columna LOAO deberia hundirse frente al control.",
        "",
        "La fila `[control] octetos de la IP de origen` **no es una vista "
        "candidata**: es un identificador de host puro, incluido para comprobar "
        "que el protocolo detecta la memorizacion cuando existe. Debe dar ~1.0 "
        "en la particion aleatoria y desplomarse en LOAO. Si no se desploma, el "
        "test no es sensible y el resultado de las otras tres vistas no "
        "significa nada.",
        "",
        "**Matiz importante:** los diez atacantes ejecutan la MISMA herramienta "
        "(LOIC), asi que este test distingue *memorizar el host* de *aprender la "
        "herramienta o la conducta*, pero NO distingue *aprender la herramienta* "
        "de *aprender el ataque*. Para eso hacen falta la evasion y la "
        "transferencia entre dominios.",
        "",
    ]
    out = MODELS_DIR / f"phase3_loao_{args.day}.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

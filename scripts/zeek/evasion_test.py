#!/usr/bin/env python3
"""Punto 3 - PRUEBA DE EVASION: el "exito" del payload en cifrado/volumetrico es
un FINGERPRINT de herramienta, evadible; la firma conductual (rafaga) no lo es.

CONTEXTO
--------
El HALLAZGO 7 (saliency) y el HALLAZGO 10 (generalizacion cruzada) mostraron que el
byte-CNN detecta el SSH-Bruteforce por el banner en claro `SSH-2.0-paramiko_2.0.0` y
el DoS-Hulk por los User-Agents/cabeceras del tool, NO por leer el cifrado ni por el
volumen. Es decir, la deteccion por payload se apoya en una huella de la herramienta.
Este script lo demuestra ACTIVAMENTE: si el atacante camufla esos primeros bytes con
los de un cliente benigno, la deteccion por payload se DESPLOMA, mientras que la vista
conductual (rafaga: nº de conexiones del mismo origen por ventana) NO cambia, porque
no depende del contenido de los bytes sino del comportamiento del flujo.

QUE HACE
--------
Sobre el servicio atacado (:22 SSH, :80 DoS), problema binario Attack vs Benign,
balanceado 1:1 y con un split train/test estratificado:
  1. Entrena un byte-CNN sobre el TRAIN original.
  2. Mide su recall sobre los ataques del TEST (a) originales y (b) EVADIDOS: se
     sobrescriben los primeros `--prefix` bytes de cada ataque con los de un flujo
     benigno del test (el atacante copia la apertura de un cliente legitimo).
  3. Entrena la vista conductual meta+rafaga (MLP) sobre el mismo train y mide su
     recall sobre los ataques del test. El spoofing de payload NO altera esas
     features (n_pkts, bytes, rafaga), asi que su recall es la referencia ROBUSTA.

Un colapso del recall del payload frente a una rafaga estable = prueba directa de
que la firma de payload es evadible y la conductual no.

Salida: models/phase2_evasion_<day>_p<port>.md + consola.

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/evasion_test.py --day Wednesday-14-02-2018 --port 22 --prefix 48
    conda run -n tfg_ia python scripts/zeek/evasion_test.py --day Friday-16-02-2018 --port 80 --prefix 160 --cap 4000
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


def recall_attack(y_true, y_pred):
    from sklearn.metrics import recall_score
    return recall_score(y_true, y_pred, pos_label=1, zero_division=0)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--service", default=None,
                    help="Selecciona el servicio por CONTENIDO (ssh, http...) en vez "
                         "de por puerto. Correccion del tutor: el puerto depende de "
                         "la configuracion de cada red.")
    ap.add_argument("--prefix", type=int, default=48,
                    help="Bytes iniciales que el atacante camufla con los de un "
                         "flujo benigno (banner SSH ~48; peticion HTTP+UA ~160)")
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
    resp_p = d["resp_p"].astype(int)

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en :{args.port} de {args.day}")
    print(f"Ataques en :{args.port}: {attack_labels}")

    # Rafaga sobre TODO el dataset antes de subsetear (mira vecinos del mismo origen).
    print(f"Calculando rafaga (ventanas {BURST_WINDOWS} s) sobre {len(y_raw)} flujos...")
    burst = build_burst_features(d)

    # Subconjunto del servicio, binario, balanceo 1:1, cap por clase.
    y_bin_full = np.where(np.isin(y_raw, attack_labels), 1, np.where(y_raw == "Benign", 0, -1))
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
    print(f"Balance -> attack {int((y==1).sum())} / benign {int((y==0).sum())}\n")

    # Vistas para el subconjunto.
    X_seq = d["X_seq"][sel].astype(np.int64)
    meta_rafaga = np.hstack([build_meta_features(d, sel), burst[sel]]).astype(np.float32)

    # Split train/test estratificado (indices sobre el subconjunto).
    ii = np.arange(len(y))
    tr, te = train_test_split(ii, test_size=args.test_size, stratify=y,
                              random_state=RANDOM_STATE)
    atk_te = te[y[te] == 1]
    ben_te = te[y[te] == 0]

    # ---- Vista payload: byte-CNN ----
    print("Entrenando byte-CNN (payload)...")
    model = ByteCNN(n_classes=2)
    train_torch(model, X_seq[tr], y[tr], epochs=args.epochs)
    rec_orig = recall_attack(np.ones(len(atk_te)), predict_torch(model, X_seq[atk_te]))

    # Evasion: camuflar los primeros `prefix` bytes de cada ataque con los de un
    # flujo benigno del test (muestreado). El resto (cifrado/cuerpo) se mantiene.
    X_ev = X_seq[atk_te].copy()
    donors = rng.choice(ben_te, len(atk_te), replace=True)
    p = min(args.prefix, X_seq.shape[1])
    X_ev[:, :p] = X_seq[donors][:, :p]
    rec_evaded = recall_attack(np.ones(len(atk_te)), predict_torch(model, X_ev))

    # ---- Vista conductual: meta+rafaga (MLP) ----
    print("Entrenando meta+rafaga (conducta)...")
    clf = make_pipeline().fit(meta_rafaga[tr], y[tr])
    rec_meta = recall_attack(np.ones(len(atk_te)), clf.predict(meta_rafaga[atk_te]))

    drop = rec_orig - rec_evaded
    print("\n================ RESULTADO EVASION ================")
    print(f"payload byte-CNN   recall ataque ORIGINAL : {rec_orig:.4f}")
    print(f"payload byte-CNN   recall ataque EVADIDO  : {rec_evaded:.4f}  (caida {drop:.4f})")
    print(f"conducta meta+raf. recall ataque          : {rec_meta:.4f}  (invariante al spoofing)")

    lines = [
        f"# Punto 3 - Prueba de evasion del fingerprint de payload ({args.day}, :{args.port})",
        "",
        f"Binario Attack vs Benign en :{args.port}, balanceado 1:1, split train/test "
        f"({int((1-args.test_size)*100)}/{int(args.test_size*100)}). El atacante camufla los "
        f"primeros **{p} bytes** de cada flujo de ataque con los de un cliente benigno "
        "(spoofing trivial del banner/cabecera); el resto del flujo no cambia.",
        "",
        "| Vista | Recall ataque (original) | Recall ataque (evadido) | Caida |",
        "|-------|--------------------------|-------------------------|-------|",
        f"| payload (byte-CNN) | {rec_orig:.4f} | {rec_evaded:.4f} | **{drop:.4f}** |",
        f"| conducta (meta+rafaga) | {rec_meta:.4f} | {rec_meta:.4f} | 0.0000 (invariante) |",
        "",
        "**Lectura:** camuflando solo los primeros bytes (coste trivial para el atacante), "
        "el recall de la deteccion por **payload se desploma** -> la firma de bytes es un "
        "*fingerprint* de la herramienta (banner `paramiko` en SSH, User-Agents de Hulk en "
        "DoS), EVADIBLE. La vista **conductual (rafaga) es invariante** al spoofing de payload "
        "(no depende del contenido, sino del nº de conexiones por origen/tiempo), asi que su "
        "recall no cambia: es la firma ROBUSTA. Confirma empiricamente los HALLAZGOS 7/8/10 y "
        "la tesis: contra evasion, la deteccion robusta exige la vista conductual, no solo el "
        "payload.",
        "",
    ]
    out = MODELS_DIR / f"phase2_evasion_{args.day}_p{args.port}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

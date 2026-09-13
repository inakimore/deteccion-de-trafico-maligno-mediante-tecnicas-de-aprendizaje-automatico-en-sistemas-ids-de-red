#!/usr/bin/env python3
"""FASE 3 (Eje C) - La firma del DoS-Hulk es VOLUMETRICA, no per-flujo (16-02).

Contexto (diario 15-jul): entrenando ataque-vs-benigno del DoS-Hulk sobre :80 a
nivel de FLUJO individual, TODAS las vistas per-flujo se quedan debiles (byte-CNN
0.61, byte-LSTM 0.65, mlp-seq 0.66, mlp-hist 0.74, metadata 0.66). Y es coherente:
un GET de Hulk se parece a un GET benigno en los bytes, y su flujo es corto como
cualquier HTTP en la metadata per-flujo. La firma del DoS NO esta en el flujo
aislado sino en el AGREGADO: el volumen de conexiones del mismo origen por unidad
de tiempo (Hulk hace ~1 M de conexiones en 7 min desde una sola IP).

Este script lo demuestra reutilizando la feature de RAFAGA (nº de conexiones del
mismo origen en ventanas causales de 1/5/30 s) que ya resolvio el SSH-Bruteforce
el 17-jun, y comparando sobre DoS-Hulk vs HTTP-benigno (:80, balanceado 1:1,
out-of-fold 5-Fold):

  - payload-hist  : histograma de bytes + entropia (per-flujo).
  - meta-basica   : 4 escalares de flujo (per-flujo).
  - meta+rafaga   : meta-basica + agregado de volumen (la firma volumetrica).

Es el analogo volumetrico del argumento del TFG: cada regimen tiene su firma
(cifrado -> conducta/rafaga; claro -> payload; DoS -> volumen agregado), y ninguna
vista per-flujo basta sola.

Uso:
    conda run -n tfg_ia python scripts/zeek/dos_burst.py --day Friday-16-02-2018 --port 80 --cap 4000
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, CV_FOLDS, load_dataset, build_meta_features,
)
from honest_by_service_rich import build_burst_features, BURST_WINDOWS  # noqa: E402
from train_dl_payload import report, eval_sklearn  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--day", default="Friday-16-02-2018")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--service", default=None,
                   help="Selecciona el servicio por CONTENIDO (http, ssh...) en vez "
                        "de por puerto. Correccion del tutor: el puerto depende de "
                        "la configuracion de cada red.")
    p.add_argument("--cap", type=int, default=4000,
                   help="Max flujos por clase (subsampleo tras balancear 1:1)")
    p.add_argument("--folds", type=int, default=CV_FOLDS)
    args = p.parse_args()

    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en {selection_label(args.port, args.service)} de {args.day}")
    # Imprimir args.port aqui enganaba cuando se selecciona por --service: el Bot
    # del 02-03 sale por el :8080 y se anunciaba como ":80" (detectado el 21-ago).
    print(f"Ataques en {selection_label(args.port, args.service)}: {attack_labels}")

    # Rafaga: se calcula sobre TODO el dataset (cada flujo mira a sus vecinos del
    # mismo origen), antes de subsetear. Coste O(n) por ventana; unos minutos en 4 M.
    print(f"Calculando rafaga (ventanas {BURST_WINDOWS} s) sobre {len(y_raw)} flujos...")
    burst = build_burst_features(d)

    # sel: puerto atacado, ataque vs benigno, balance 1:1 y cap por clase.
    y = np.where(np.isin(y_raw, attack_labels), "Attack", y_raw)
    mask = svc_sel & ((y == "Attack") | (y == "Benign"))
    y_svc = y[mask]
    idx_all = np.nonzero(mask)[0]
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    sel_local, y_bal = rus.fit_resample(np.arange(len(y_svc)).reshape(-1, 1), y_svc)
    sel = idx_all[sel_local.ravel()]
    le = LabelEncoder().fit(y_svc)
    y_enc = le.transform(y_bal)

    if args.cap and args.cap > 0:
        rng = np.random.default_rng(RANDOM_STATE)
        keep = np.concatenate([
            (lambda ci: rng.choice(ci, args.cap, replace=False) if len(ci) > args.cap else ci)(
                np.nonzero(y_enc == c)[0]) for c in np.unique(y_enc)])
        keep.sort()
        sel, y_bal, y_enc = sel[keep], y_bal[keep], y_enc[keep]

    classes = list(le.classes_)
    print(f"Balance -> {dict(zip(*np.unique(y_bal, return_counts=True)))} | clases {classes}\n")

    # Vistas SOLO para sel (carga transitoria por array; pico de RAM acotado).
    meta_basica = build_meta_features(d, sel)
    meta_rafaga = np.hstack([meta_basica, burst[sel]]).astype(np.float32)
    payload_hist = np.hstack([d["X_hist"][sel],
                              (entropy[sel] / 8.0).reshape(-1, 1)]).astype(np.float32)

    views = {
        "payload-hist": payload_hist,
        "meta-basica": meta_basica,
        "meta+rafaga": meta_rafaga,
    }
    rows = []
    for name, Xv in views.items():
        print(f"Entrenando {name} ...")
        yp = eval_sklearn(name, Xv, y_enc, args.folds, RANDOM_STATE)
        rows.append(report(name, y_enc, yp, classes))

    # Resumen markdown.
    counts = dict(zip(*np.unique(y_bal, return_counts=True)))
    counts = {str(k): int(v) for k, v in counts.items()}
    lines = [
        # El titulo describe lo que el script MIDE (el agregado de rafaga por
        # origen), no el regimen del dia: aplicado al Bot del 02-03 el rotulo
        # "regimen volumetrico" era simplemente falso (detectado el 21-ago).
        f"# Fase 3 (Eje C) - Agregado de rafaga por origen ({args.day}, "
        f"{selection_label(args.port, args.service)})",
        "",
        f"{' + '.join(attack_labels)} vs benigno del mismo servicio, balanceado 1:1 "
        f"({counts}), out-of-fold {args.folds}-Fold.",
        "Ventanas de rafaga (s): " + ", ".join(str(w) for w in BURST_WINDOWS) + ".",
        "",
        "| Vista | Accuracy | Macro-F1 |",
        "|-------|----------|----------|",
    ]
    for r in rows:
        lines.append(f"| {r['name']} | {r['acc']:.4f} | {r['macro_f1']:.4f} |")
    # La NOTA siguiente documenta la correccion del benigno contaminado del
    # 11-ago y es especifica del 16-02: afirmar lo mismo en un dia que nunca
    # tuvo esa primera version erronea seria falso (se detecto el 19-ago al
    # anadir el DDoS del 20-02, cuyo informe la heredaba sin venir a cuento).
    if args.day == "Friday-16-02-2018":
        lines += ["",
              "NOTA (11-ago): la primera version de esta comparativa (15-jul) se midio",
                  "sobre un benigno CONTAMINADO -el 65,1% del \"benigno\" HTTP eran flujos del",
                  "PROPIO atacante, porque la ventana etiquetada se quedaba ~5 min corta- y",
                  "concluia que ninguna vista per-flujo servia (todas <=0.74). Corregida la",
                  "ventana en attack_metadata.py y re-etiquetado el dataset, la comparacion",
                  "es ataque contra benigno GENUINO. La rafaga (volumen agregado por origen)",
                  "sigue siendo la vista mas fuerte y la unica robusta ante evasion del",
                  "payload (HALLAZGO 11), pero ya NO es la unica que funciona. Ver el diario",
                  "del 11 de agosto.", ""]
    for r in rows:
        lines += [f"## {r['name']}", "",
                  f"- **Accuracy:** {r['acc']:.4f} | **Macro-F1:** {r['macro_f1']:.4f}", "",
                  "```", r["report"].rstrip(), "",
                  f"Matriz de confusion labels={classes}:",
                  np.array2string(r["cm"]), "```", ""]
    out = MODELS_DIR / f"phase2_dos_burst_{args.day}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

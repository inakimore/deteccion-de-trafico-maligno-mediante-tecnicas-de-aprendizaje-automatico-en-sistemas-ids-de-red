#!/usr/bin/env python3
"""Punto 4 - DETECCION DE ANOMALIAS NO SUPERVISADA (deteccion tipo zero-day).

CONTEXTO
--------
Todo el TFG hasta ahora es SUPERVISADO: se entrena con ataques etiquetados. Pero un
NIDS real debe detectar ataques DESCONOCIDOS (zero-day), sin haberlos visto nunca.
Este script explora el enfoque no supervisado: se entrena SOLO con trafico BENIGNO y
se mide si los ataques emergen como ANOMALIAS (puntuaciones atipicas), sin usar sus
etiquetas para entrenar.

QUE HACE
--------
Sobre el servicio atacado (:22, :80), separa el benigno en fit/test y trata TODOS los
ataques como test. Entrena modelos no supervisados solo sobre el benigno-fit y puntua
anomalia sobre benigno-test (negativos) + ataques (positivos):
  - IsolationForest sobre payload (histograma+entropia).
  - IsolationForest sobre metadatos de flujo (+ rafaga si --with-burst).
  - Autoencoder (PyTorch) sobre payload: el error de reconstruccion es la anomalia.
Metricas: ROC-AUC (ataque=positivo) y tasa de deteccion (recall de ataque) fijando el
umbral al 5% de falsos positivos sobre el benigno (percentil 95 del score benigno).

Se espera (y es parte del argumento): el ataque en CLARO (web) emerge como anomalia
por su payload; el SSH cifrado apenas (su payload ~ benigno cifrado), pero su RAFAGA
si; el DoS per-flujo poco, su volumen agregado mas. Cada regimen, su vista.

Salida: models/phase2_anomaly_<day>_p<port>.md + consola.

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/anomaly_detection.py --day Thursday-22-02-2018 --port 80
    conda run -n tfg_ia python scripts/zeek/anomaly_detection.py --day Wednesday-14-02-2018 --port 22
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import (  # noqa: E402
    MODELS_DIR, RANDOM_STATE, load_dataset, build_meta_features,
)
from honest_by_service_rich import build_burst_features, BURST_WINDOWS  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402


def det_at_fpr(scores_ben, scores_atk, fpr=0.05):
    """Tasa de deteccion de ataque fijando el umbral al percentil (1-fpr) del benigno."""
    thr = np.quantile(scores_ben, 1 - fpr)
    return float((scores_atk > thr).mean()), float(thr)


def iso_scores(Xfit, Xben, Xatk, seed):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    sc = StandardScaler().fit(Xfit)
    iso = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1)
    iso.fit(sc.transform(Xfit))
    # -score_samples: mayor = mas anomalo.
    s_ben = -iso.score_samples(sc.transform(Xben))
    s_atk = -iso.score_samples(sc.transform(Xatk))
    return s_ben, s_atk


def ae_scores(Xfit, Xben, Xatk, seed, epochs=40):
    """Autoencoder MLP sobre payload; error de reconstruccion = anomalia."""
    import torch
    import torch.nn as nn
    from sklearn.preprocessing import StandardScaler
    torch.manual_seed(seed)
    sc = StandardScaler().fit(Xfit)
    Xf = torch.tensor(sc.transform(Xfit), dtype=torch.float32)
    dim = Xf.shape[1]
    net = nn.Sequential(
        nn.Linear(dim, 64), nn.ReLU(), nn.Linear(64, 16), nn.ReLU(),
        nn.Linear(16, 64), nn.ReLU(), nn.Linear(64, dim))
    opt = torch.optim.Adam(net.parameters(), lr=1e-3, weight_decay=1e-5)
    lossf = nn.MSELoss()
    from torch.utils.data import DataLoader, TensorDataset
    dl = DataLoader(TensorDataset(Xf), batch_size=256, shuffle=True)
    net.train()
    for _ in range(epochs):
        for (xb,) in dl:
            opt.zero_grad(); loss = lossf(net(xb), xb); loss.backward(); opt.step()
    net.eval()
    def err(X):
        with torch.no_grad():
            t = torch.tensor(sc.transform(X), dtype=torch.float32)
            return ((net(t) - t) ** 2).mean(dim=1).numpy()
    return err(Xben), err(Xatk)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--service", default=None,
                    help="Selecciona el servicio por CONTENIDO (ssh, http...) en vez "
                         "de por puerto. Correccion del tutor: el puerto depende de "
                         "la configuracion de cada red.")
    ap.add_argument("--fit-cap", type=int, default=8000, help="Max benigno para entrenar")
    ap.add_argument("--test-cap", type=int, default=4000, help="Max benigno/ataque en test")
    ap.add_argument("--with-burst", action="store_true", default=True)
    ap.add_argument("--no-burst", dest="with_burst", action="store_false")
    args = ap.parse_args()

    from sklearn.metrics import roc_auc_score
    rng = np.random.default_rng(RANDOM_STATE)

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    entropy = d["entropy"]

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    if not attack_labels:
        sys.exit(f"[ERROR] No hay ataques en :{args.port} de {args.day}")
    print(f"Ataques en :{args.port}: {attack_labels}")

    ben_idx = np.nonzero(svc_sel & (y_raw == "Benign"))[0]
    atk_idx = np.nonzero(svc_sel & np.isin(y_raw, attack_labels))[0]
    print(f"Benigno :{args.port} = {len(ben_idx)} | ataque = {len(atk_idx)}")

    # Split benigno fit/test; ataques todos en test (capados).
    rng.shuffle(ben_idx)
    n_fit = min(args.fit_cap, int(len(ben_idx) * 0.7))
    ben_fit = ben_idx[:n_fit]
    ben_test = ben_idx[n_fit:n_fit + args.test_cap]
    if len(atk_idx) > args.test_cap:
        atk_idx = rng.choice(atk_idx, args.test_cap, replace=False)
    print(f"Fit benigno={len(ben_fit)} | test benigno={len(ben_test)} ataque={len(atk_idx)}\n")

    # Vistas.
    def payload(ix):
        return np.hstack([d["X_hist"][ix], (entropy[ix] / 8.0).reshape(-1, 1)]).astype(np.float32)
    burst = build_burst_features(d) if args.with_burst else None
    def meta(ix):
        m = build_meta_features(d, ix)
        return np.hstack([m, burst[ix]]).astype(np.float32) if args.with_burst else m

    y_true = np.concatenate([np.zeros(len(ben_test)), np.ones(len(atk_idx))])
    rows = []

    def evaluate(name, s_ben, s_atk):
        auc = roc_auc_score(y_true, np.concatenate([s_ben, s_atk]))
        det, _ = det_at_fpr(s_ben, s_atk, 0.05)
        print(f"  [{name}] ROC-AUC {auc:.4f} | deteccion@5%FPR {det:.4f}")
        rows.append((name, auc, det))

    print("IsolationForest sobre payload (hist+entropia)...")
    evaluate("payload-IF", *iso_scores(payload(ben_fit), payload(ben_test), payload(atk_idx), RANDOM_STATE))
    mlabel = "meta+rafaga-IF" if args.with_burst else "meta-IF"
    print(f"IsolationForest sobre {mlabel}...")
    evaluate(mlabel, *iso_scores(meta(ben_fit), meta(ben_test), meta(atk_idx), RANDOM_STATE))
    print("Autoencoder sobre payload...")
    evaluate("payload-AE", *ae_scores(payload(ben_fit), payload(ben_test), payload(atk_idx), RANDOM_STATE))

    lines = [
        f"# Punto 4 - Deteccion de anomalias no supervisada ({args.day}, :{args.port})",
        "",
        f"Entrenado SOLO con benigno (fit={len(ben_fit)}); test = benigno "
        f"({len(ben_test)}) + ataque ({len(atk_idx)}). Sin usar etiquetas de ataque para "
        "entrenar (escenario zero-day). Rafaga: " + ("SI" if args.with_burst else "NO") + ".",
        "",
        "| Vista (no supervisada) | ROC-AUC | Deteccion @5% FPR |",
        "|------------------------|---------|-------------------|",
    ]
    for name, auc, det in rows:
        lines.append(f"| {name} | {auc:.4f} | {det:.4f} |")
    lines += [
        "",
        "**Lectura:** ROC-AUC 0.5 = no distingue; 1.0 = separacion perfecta. La deteccion "
        "@5% FPR es la fraccion de ataques capturados aceptando solo 5% de falsas alarmas "
        "sobre el benigno. Cada regimen esconde su anomalia en una vista distinta (payload "
        "en el ataque en claro; rafaga/agregado en el cifrado y el volumetrico), coherente "
        "con la tesis: incluso sin etiquetas, ninguna vista unica basta.",
        "",
    ]
    out = MODELS_DIR / f"phase2_anomaly_{args.day}_p{args.port}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nResumen -> {out}")


if __name__ == "__main__":
    main()

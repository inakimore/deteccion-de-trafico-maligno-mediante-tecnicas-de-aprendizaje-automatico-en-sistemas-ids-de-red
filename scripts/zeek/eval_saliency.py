#!/usr/bin/env python3
"""FASE 3 - Eje D: interpretabilidad (saliency) del byte-CNN sobre el SSH cifrado.

Los Ejes A/B mostraron que el byte-CNN separa el SSH-Bruteforce del SSH benigno
limpio casi perfecto (~0.99). Pero el trafico SSH esta CIFRADO: el modelo no puede
estar leyendo el contenido. La hipotesis (del 17-jun) es que decide por el BANNER
del handshake, que viaja EN CLARO al principio de la conexion ("SSH-2.0-<cliente>"):
el atacante usa un cliente fijo (paramiko) y los usuarios legitimos, clientes
diversos. Esa senal es real pero EVADIBLE (basta falsear el banner); la firma
robusta es conductual (rafaga).

Este script lo demuestra de dos formas sobre el caso SSH por servicio:
  1. SALIENCY: entrena un byte-CNN y calcula la importancia (|gradiente| respecto al
     embedding de entrada) de cada posicion de byte, promediada sobre los flujos de
     ataque. Si la hipotesis es cierta, la importancia se concentra en los primeros
     ~20-30 bytes (el banner), no en el cuerpo cifrado. Genera un PNG.
  2. DECODIFICACION: imprime el byte modal por posicion en los primeros bytes de los
     flujos de ataque (deberia deletrear el banner del cliente del atacante) y unos
     ejemplos de banners benignos para contrastar la diversidad.

Salida: models/phase2_saliency_ssh.png + models/phase2_saliency_ssh.md + consola.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/eval_saliency.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hybrid_compare import MODELS_DIR, RANDOM_STATE, load_dataset  # noqa: E402
from dl_models import ByteCNN, train_torch, set_seed  # noqa: E402
from service_id import service_selection, selection_label  # noqa: E402

FRONT = 48  # bytes iniciales que se decodifican/inspeccionan (zona del banner)


def to_ascii(b: int) -> str:
    return chr(b) if 32 <= b < 127 else "."


def modal_banner(seq_rows: np.ndarray, n: int = FRONT) -> str:
    """Byte mas frecuente por posicion en los primeros n bytes -> texto."""
    out = []
    for pos in range(n):
        col = seq_rows[:, pos]
        vals, cnts = np.unique(col, return_counts=True)
        out.append(to_ascii(int(vals[cnts.argmax()])))
    return "".join(out)


def saliency(model, X_seq_attack, attack_id, batch=128):
    """|d(logit_attack)/d(embedding)| sumado sobre la dim de embedding, por posicion."""
    model.eval()
    acc = np.zeros(X_seq_attack.shape[1], dtype=np.float64)
    n = 0
    for i in range(0, len(X_seq_attack), batch):
        xb = torch.as_tensor(X_seq_attack[i:i + batch], dtype=torch.long)
        e = model.emb(xb)                 # (B, L, emb)
        e.requires_grad_(True)
        e.retain_grad()
        et = e.transpose(1, 2)
        feats = [F.relu(c(et)).max(dim=2).values for c in model.convs]
        logits = model.fc(torch.cat(feats, dim=1))
        model.zero_grad()
        logits[:, attack_id].sum().backward()
        acc += e.grad.abs().sum(dim=2).sum(dim=0).detach().numpy()
        n += len(xb)
    return acc / max(n, 1)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--day", default="Wednesday-14-02-2018")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--service", default=None,
                   help="Selecciona el servicio por CONTENIDO (ssh, http...) en vez "
                        "de por puerto. Correccion del tutor: el puerto depende de "
                        "la configuracion de cada red.")
    p.add_argument("--epochs", type=int, default=40)
    args = p.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.preprocessing import LabelEncoder
    from imblearn.under_sampling import RandomUnderSampler

    set_seed()
    d = load_dataset(args.day)
    y_raw = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)
    X_seq_all = d["X_seq"].astype(np.int64)

    svc_sel = service_selection(d, port=args.port, service=args.service)
    print(f"Seleccion del servicio: {selection_label(args.port, args.service)}")
    attack_labels = sorted(set(y_raw[svc_sel & (y_raw != "Benign")]))
    y = np.where(np.isin(y_raw, attack_labels), "Attack", y_raw)
    mask = svc_sel & ((y == "Attack") | (y == "Benign"))
    idx_all = np.nonzero(mask)[0]
    y_svc = y[mask]
    rus = RandomUnderSampler(random_state=RANDOM_STATE)
    sel_local, y_bal = rus.fit_resample(np.arange(len(y_svc)).reshape(-1, 1), y_svc)
    sel = idx_all[sel_local.ravel()]
    le = LabelEncoder().fit(y_svc)
    y_enc = le.transform(y_bal)
    attack_id = int(le.transform(["Attack"])[0])
    X_seq = X_seq_all[sel]
    print(f"SSH por servicio: {len(sel)} flujos balanceados {dict(zip(*np.unique(y_bal, return_counts=True)))}")

    # Entrena un CNN sobre todo el conjunto balanceado (para interpretar, no evaluar).
    set_seed()
    model = ByteCNN(len(le.classes_))
    train_torch(model, X_seq, y_enc, epochs=args.epochs)

    sal = saliency(model, X_seq[y_enc == attack_id], attack_id)
    front_mass = sal[:FRONT].sum() / sal.sum()
    print(f"\nSaliency: masa en los primeros {FRONT} bytes = {front_mass*100:.1f}% del total")

    atk_banner = modal_banner(X_seq_all[idx_all][y_svc == "Attack"])
    print(f"\nBanner modal ATAQUE (primeros {FRONT} bytes): {atk_banner!r}")
    ben_rows = X_seq_all[idx_all][y_svc == "Benign"]
    print("Ejemplos de banner BENIGNO (primeros 40 bytes de 5 flujos):")
    ben_examples = []
    for r in ben_rows[:5]:
        s = "".join(to_ascii(int(b)) for b in r[:40])
        ben_examples.append(s)
        print(f"  {s!r}")

    # Grafico de saliency por posicion.
    out_png = MODELS_DIR / "phase2_saliency_ssh.png"
    plt.figure(figsize=(9, 3.2))
    plt.plot(sal, lw=0.8, color="#c0392b")
    plt.axvspan(0, FRONT, color="#f1c40f", alpha=0.25, label=f"primeros {FRONT} B (banner)")
    plt.xlabel("posicion de byte en el flujo (0-255)")
    plt.ylabel("importancia media |grad|")
    plt.title(f"Saliency del byte-CNN sobre SSH-Bruteforce ({args.day})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=110)
    print(f"\nGrafico -> {out_png}")

    out_md = MODELS_DIR / "phase2_saliency_ssh.md"
    lines = [
        f"# Fase 3 (Eje D) - Interpretabilidad: por que el byte-CNN 've' el SSH cifrado ({args.day})",
        "",
        "El byte-CNN separa SSH-ataque de SSH-benigno limpio casi perfecto (~0.99), pero",
        "el SSH esta CIFRADO. Este analisis muestra que el modelo decide por el BANNER",
        "del handshake (en claro), no por el contenido cifrado.",
        "",
        f"- **Saliency:** el {front_mass*100:.1f}% de la importancia media se concentra en",
        f"  los primeros {FRONT} bytes del flujo (la zona del banner), no en el cuerpo",
        "  cifrado. Ver `phase2_saliency_ssh.png`.",
        "",
        f"- **Banner modal del ATAQUE** (primeros {FRONT} bytes, byte mas frecuente por",
        f"  posicion): `{atk_banner}`",
        "",
        "- **Banners BENIGNOS** (diversos, 5 ejemplos):",
        "",
        "```",
        *[f"  {s}" for s in ben_examples],
        "```",
        "",
        "**Conclusion:** el exito del payload sobre el SSH cifrado es un *fingerprint* del",
        "cliente del atacante (banner en claro), no una lectura del cifrado; es una senal",
        "real pero EVADIBLE (basta falsear el banner). La firma robusta del brute-force",
        "sigue siendo conductual (rafaga de conexiones). Refuerza la tesis del enfoque",
        "hibrido: el payload aporta en claro, la conducta aporta cuando el contenido no.",
    ]
    out_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"Resumen -> {out_md}")


if __name__ == "__main__":
    main()

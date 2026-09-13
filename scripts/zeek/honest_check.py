#!/usr/bin/env python3
"""Prueba honesta del modelo de payload: ¿distingue el ATAQUE o solo el PROTOCOLO?

Al consolidar el día completo (9 de mayo) el tráfico benigno pasa a ser 99,9%
NO-SSH (RDP, HTTPS, HTTP, SMB...). Un modelo balanceado alcanza ~0.9996 de
accuracy, pero ese número es engañoso: puede estar aprendiendo a separar "payload
de SSH cifrado" de "otros protocolos", NO el SSH-Bruteforce del SSH legítimo.

Esta prueba aísla el caso difícil —los flujos BENIGNOS que SÍ son SSH (puerto 22)—
y mide cuántos clasifica el modelo como SSH-Bruteforce (falsos positivos). Si la
tasa es alta, el 0.9996 es un espejismo: el modelo reconoce el protocolo, no el
ataque, y en producción inundaría de alertas a los usuarios SSH legítimos.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/honest_check.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_id import service_selection, selection_label  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = REPO_ROOT / "data" / "processed" / "zeek"
MODELS_DIR = REPO_ROOT / "models"

DEFAULT_DAY = "Wednesday-14-02-2018"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY)
    parser.add_argument("--port", type=int, default=22,
                        help="Puerto del servicio benigno a auditar (def: 22, SSH)")
    parser.add_argument("--service", default=None,
                        help="Audita el servicio identificado por CONTENIDO (ssh, "
                             "http...) en vez de por puerto. Correccion del tutor: "
                             "el puerto depende de la configuracion de cada red.")
    args = parser.parse_args()

    import joblib
    from sklearn.preprocessing import LabelEncoder

    base = PROCESSED / args.day.lower() / f"dataset_{args.day}"
    npz = base.with_suffix(".npz")
    if not npz.is_file():
        sys.exit(f"[ERROR] No existe {npz}. Ejecuta build_dataset.py")
    d = np.load(npz, allow_pickle=True)
    X_hist, X_seq, entropy = d["X_hist"], d["X_seq"], d["entropy"]
    y = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)

    X_a = np.hstack([X_hist, (entropy / 8.0).reshape(-1, 1)]).astype(np.float32)
    X_b = X_seq.astype(np.float32) / 255.0

    views = [
        ("histograma+entropia", X_a, MODELS_DIR / "phase2_mlp_histogramaentropia.joblib"),
        ("secuencial", X_b, MODELS_DIR / "phase2_mlp_secuencial.joblib"),
    ]

    # Caso difícil: benigno que SÍ usa el servicio atacado (mismo protocolo cifrado).
    mask = (y == "Benign") & service_selection(d, port=args.port, service=args.service)
    n = int(mask.sum())
    print(f"Día {args.day} — benigno en {selection_label(args.port, args.service)}: "
          f"{n} flujos\n")
    if n == 0:
        sys.exit("[aviso] no hay flujos benignos en ese puerto.")

    for view, X, path in views:
        if not path.is_file():
            print(f"[{view}] modelo no encontrado ({path.name}); ejecuta train_phase2.py")
            continue
        obj = joblib.load(path)
        clf, classes = obj["model"], obj["classes"]
        le = LabelEncoder().fit(classes)
        pred = le.inverse_transform(clf.predict(X[mask]))
        fp = int((pred == "SSH-Bruteforce").sum())
        print(f"[{view}]")
        print(f"  Falsos positivos (benigno-SSH marcado como ataque): "
              f"{fp}/{n} ({fp/n*100:.1f}%)")
        print(f"  Correctos (benigno-SSH como Benign): {n-fp}/{n} "
              f"({(n-fp)/n*100:.1f}%)\n")

    print("Interpretación: una tasa alta de falsos positivos demuestra que el modelo")
    print("aprende el PROTOCOLO (SSH cifrado), no el ATAQUE. El accuracy global ~0.9996")
    print("es un espejismo del desbalanceo de servicios en el tráfico benigno.")


if __name__ == "__main__":
    main()

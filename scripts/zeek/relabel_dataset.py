#!/usr/bin/env python3
"""Re-aplica las etiquetas al dataset existente SIN re-leer los TSV (67 GB).

El etiquetado solo necesita la 5-tupla y el timestamp del flujo, que ya estan
guardados en dataset_<dia>.npz (orig_h/orig_p/resp_h/resp_p/ts). Por tanto, cuando
se corrige la ground-truth en attack_metadata.py (p. ej. la ventana del SSH), NO
hace falta re-ejecutar build_dataset.py sobre los 67 GB de payload: basta recalcular
la columna `y` con el DayLabeler actualizado y reescribir el .npz y el _meta.csv.

Hace una copia .bak del .npz/.csv antes de sobreescribir, e imprime el diff de la
distribucion de etiquetas (antes -> despues) para verificar la correccion.

Ejemplo:
    conda run -n tfg_ia python scripts/zeek/relabel_dataset.py
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_metadata import DayLabeler  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = REPO_ROOT / "data" / "processed" / "zeek"
DEFAULT_DAY = "Wednesday-14-02-2018"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    parser.add_argument("--no-backup", action="store_true",
                        help="No crear copia .bak antes de sobreescribir")
    args = parser.parse_args()

    in_dir = PROCESSED / args.day.lower()
    npz_path = in_dir / f"dataset_{args.day}.npz"
    csv_path = in_dir / f"dataset_{args.day}_meta.csv"
    if not npz_path.is_file():
        sys.exit(f"[ERROR] No existe {npz_path}. Ejecuta antes build_dataset.py")

    d = np.load(npz_path, allow_pickle=True)
    oh = d["orig_h"].astype(str); op = d["orig_p"].astype(int)
    rh = d["resp_h"].astype(str); rp = d["resp_p"].astype(int)
    ts = d["ts"].astype(float)
    y_old = d["y"].astype(str)

    labeler = DayLabeler(args.day)
    print(labeler.summary())

    y_new = np.array([labeler.label(oh[i], op[i], rh[i], rp[i], ts[i])
                      for i in range(len(ts))], dtype=object)

    # Diff de distribucion.
    def dist(y):
        u, c = np.unique(y, return_counts=True)
        return dict(zip(u.tolist(), c.tolist()))
    old, new = dist(y_old), dist(y_new)
    changed = int((y_old != y_new).sum())
    print(f"\nFlujos: {len(y_new)} | cambian de etiqueta: {changed}")
    print("Distribucion (antes -> despues):")
    for k in sorted(set(old) | set(new)):
        print(f"  {k:16s} {old.get(k,0):>10d} -> {new.get(k,0):>10d}")

    if changed == 0:
        print("\nNo hay cambios; el etiquetado ya esta al dia. No se reescribe nada.")
        return

    if not args.no_backup:
        shutil.copy2(npz_path, npz_path.with_suffix(".npz.bak"))
        if csv_path.is_file():
            shutil.copy2(csv_path, csv_path.with_suffix(".csv.bak"))
        print(f"\nBackup -> {npz_path.name}.bak / {csv_path.name}.bak")

    # Reescribe el .npz con la nueva y (resto de arrays intactos).
    arrays = {k: d[k] for k in d.files}
    arrays["y"] = y_new
    np.savez_compressed(npz_path, **arrays)
    print(f"NPZ actualizado -> {npz_path}")

    # Reescribe el meta CSV (mismas columnas que build_dataset.py).
    if csv_path.is_file():
        import pandas as pd
        meta = pd.read_csv(csv_path)
        meta["label"] = y_new
        meta.to_csv(csv_path, index=False)
        print(f"Meta CSV actualizado -> {csv_path}")

    print("\nListo. Re-ejecuta los evaluadores (honest_by_service*.py) para confirmar.")


if __name__ == "__main__":
    main()

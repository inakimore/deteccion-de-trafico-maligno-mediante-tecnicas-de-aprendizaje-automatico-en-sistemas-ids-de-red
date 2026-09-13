#!/usr/bin/env python3
"""Extraccion de payload por lotes con borrado incremental del PCAP (TFG Fase 3).

Envoltorio de run_zeek_payload.run_one para dias que NO caben en disco con el
procedimiento literal del README ("extraer todo -> Zeek -> borrar PCAP+TSV").

Motivo (medido el 19-ago sobre el log del 16-02): los TSV de payload ocupan
~1,48x el PCAP de origen (69,1 GB de TSV desde 46,8 GB de PCAP). El dia
Tuesday-20-02-2018 tiene 61,5 GB de PCAP -> ~91 GB de TSV, que no caben en los
87 GB libres si ademas se conservan los PCAP.

Este script procesa captura a captura y BORRA cada PCAP en cuanto su TSV existe,
asi el balance por captura pasa de +1,48x a +0,48x (se escribe el TSV pero se
libera el PCAP). Ordena de MAYOR a MENOR: la copia saneada temporal (1x el
tamano de la captura) es el pico transitorio, y conviene pagarlo cuando aun
queda mucho disco libre.

La existencia de <captura>.payload.tsv es el unico estado: run_one() ya escribe
un TSV vacio para las capturas sin payload TCP, asi que reanudar es idempotente
y basta con re-lanzar el script si se interrumpe.

Uso:
    python scripts/zeek/run_zeek_payload_batched.py --day Tuesday-20-02-2018
    python scripts/zeek/run_zeek_payload_batched.py --day X --min-free-gb 20
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_zeek_payload as rz  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


def free_gb(path: Path) -> float:
    return shutil.disk_usage(path).free / 1024**3


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True)
    ap.add_argument("--min-free-gb", type=float, default=15.0,
                    help="Aborta limpiamente si el disco libre baja de este umbral")
    ap.add_argument("--keep-pcap", action="store_true",
                    help="No borrar los PCAP (vuelve al comportamiento clasico)")
    args = ap.parse_args()

    pcap_dir = REPO_ROOT / rz.PCAP_SUBDIR / args.day / "pcap"
    out_dir = REPO_ROOT / rz.OUTPUT_SUBDIR / args.day.lower()
    out_dir.mkdir(parents=True, exist_ok=True)

    pcaps = rz.list_pcaps(pcap_dir)
    pcaps.sort(key=lambda p: p.stat().st_size, reverse=True)

    pend = [p for p in pcaps if not (out_dir / f"{p.name}.payload.tsv").exists()]
    done = len(pcaps) - len(pend)
    total = sum(p.stat().st_size for p in pend)
    print(f"Dataset:  {pcap_dir}")
    print(f"Salida:   {out_dir}")
    print(f"Capturas: {len(pcaps)} ({done} ya con TSV, {len(pend)} pendientes, "
          f"{rz.human(total)} por procesar)")
    print(f"Disco libre: {free_gb(out_dir):.1f} GB  (umbral {args.min_free_gb} GB)\n")

    counts = {"ok": 0, "error": 0}
    t0 = time.time()
    for i, pcap in enumerate(pend, 1):
        libre = free_gb(out_dir)
        if libre < args.min_free_gb:
            print(f"\n[ABORTADO] disco libre {libre:.1f} GB < umbral "
                  f"{args.min_free_gb} GB. Procesadas {i-1}/{len(pend)}.")
            print("Libera espacio y re-lanza: es idempotente, reanuda donde quedo.")
            sys.exit(2)

        size = pcap.stat().st_size
        print(f"[{i}/{len(pend)}] {pcap.name} ({rz.human(size)})  "
              f"libre={libre:.1f}GB", flush=True)
        status = rz.run_one(pcap, pcap_dir, out_dir, force=False)
        counts["ok" if status in ("ok", "skip") else "error"] += 1

        tsv = out_dir / f"{pcap.name}.payload.tsv"
        if status == "ok" and tsv.exists() and not args.keep_pcap:
            pcap.unlink()
            print(f"        PCAP borrado ({rz.human(size)} liberados)", flush=True)

    dt = time.time() - t0
    print(f"\nResumen: {counts['ok']} ok, {counts['error']} con error "
          f"en {dt/3600:.1f} h. Disco libre: {free_gb(out_dir):.1f} GB")
    if counts["error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()

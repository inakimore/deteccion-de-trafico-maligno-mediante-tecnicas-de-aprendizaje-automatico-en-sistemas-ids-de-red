#!/usr/bin/env python3
"""Localiza en que capturas de un dia aparece una IP (TFG Fase 2).

Cada dia del dataset son >30 GB repartidos en cientos de PCAP por host. Para no
procesar todo con Zeek, este script hace un barrido binario rapido: cuenta cuantas
veces aparecen los 4 bytes de una IP (tal y como van en la cabecera IP) dentro de
cada captura. Las capturas con muchas apariciones contienen trafico real de esa IP
(la cabecera lleva la IP en cada paquete); unas pocas apariciones suelen ser
coincidencias espurias dentro de algun payload.

Es un FILTRO: confirma siempre los candidatos con conn.log (ver README) antes de
extraer el payload, porque el conteo de bytes no distingue puerto, sentido ni hora.

Uso:
    python scripts/zeek/find_host.py --ip 18.221.219.4
    python scripts/zeek/find_host.py --ip 18.221.219.4 --day Wednesday-14-02-2018 --top 15
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PCAP_SUBDIR = Path("data/raw/Original Network Traffic and Log data")
DEFAULT_DAY = "Wednesday-14-02-2018"
CHUNK = 8 * 1024 * 1024  # 8 MB


def ip_to_bytes(ip: str) -> bytes:
    try:
        return socket.inet_aton(ip)
    except OSError:
        sys.exit(f"[ERROR] IP invalida: {ip}")


def count_in_file(path: Path, pat: bytes) -> int:
    """Cuenta apariciones de `pat` en el fichero leyendo por trozos."""
    n = 0
    tail = b""
    overlap = len(pat) - 1
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf = tail + chunk
            n += buf.count(pat)
            tail = buf[-overlap:] if overlap else b""
    return n


def human(n: int) -> str:
    size = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or u == "TB":
            return f"{size:.0f}{u}"
        size /= 1024
    return f"{size:.0f}TB"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", required=True, help="IP a buscar (p.ej. 18.221.219.4)")
    ap.add_argument("--day", default=DEFAULT_DAY, help=f"Dia (def: {DEFAULT_DAY})")
    ap.add_argument("--top", type=int, default=20, help="Cuantas capturas mostrar")
    ap.add_argument("--min", type=int, default=1,
                    help="Conteo minimo para listar una captura (def: 1)")
    args = ap.parse_args()

    pat = ip_to_bytes(args.ip)
    pcap_dir = REPO_ROOT / PCAP_SUBDIR / args.day / "pcap"
    if not pcap_dir.is_dir():
        sys.exit(f"[ERROR] No existe {pcap_dir}")

    pcaps = sorted(p for p in pcap_dir.iterdir() if p.is_file())
    print(f"Buscando {args.ip} ({pat.hex(' ')}) en {len(pcaps)} capturas de {args.day}\n")

    results = []
    t0 = time.time()
    for i, p in enumerate(pcaps, 1):
        c = count_in_file(p, pat)
        if c >= args.min:
            results.append((c, p.name, p.stat().st_size))
        if i % 50 == 0:
            print(f"  ...{i}/{len(pcaps)} ({time.time()-t0:.0f}s)", file=sys.stderr)

    results.sort(reverse=True)
    print(f"Capturas con >= {args.min} apariciones (top {args.top}):")
    print(f"{'apariciones':>12}  {'tamano':>8}  captura")
    for c, name, size in results[: args.top]:
        print(f"{c:>12}  {human(size):>8}  {name}")
    print(f"\n{len(results)} capturas con coincidencias. Barrido en {time.time()-t0:.0f}s.")
    print("Confirma los candidatos con conn.log antes de extraer payload.")


if __name__ == "__main__":
    main()

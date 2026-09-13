#!/usr/bin/env python3
"""Lectura/decodificacion de los payloads extraidos por Zeek (TFG Fase 2).

Toma un TSV generado por extract_payload.zeek (payload en hexadecimal) y muestra
el contenido de los paquetes de forma legible: los bytes imprimibles ASCII se
muestran tal cual y el resto como '.'. Util para inspeccionar trafico en claro
(FTP, HTTP, telnet...) y confirmar visualmente la extraccion.

Ejemplos:

    # Primeras 20 lineas de payload de una captura
    python scripts/zeek/decode_payload.py data/processed/zeek/.../X.payload.tsv -n 20

    # Solo trafico de/hacia el puerto 21 (FTP), util en el dia de Brute Force
    python scripts/zeek/decode_payload.py X.payload.tsv --port 21 -n 40

    # Volcado hexadecimal estilo hexdump de cada paquete
    python scripts/zeek/decode_payload.py X.payload.tsv --hexdump -n 5
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

FIELDS_PREFIX = "#fields"


def printable(data: bytes) -> str:
    """Representa bytes como texto: imprimibles tal cual, el resto como '.'."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def hexdump(data: bytes, width: int = 16) -> str:
    """Volcado estilo hexdump (offset, hex, ascii)."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        lines.append(f"    {off:06x}  {hex_part}  {printable(chunk)}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tsv", help="TSV generado por extract_payload.zeek")
    parser.add_argument("-n", "--num", type=int, default=20,
                        help="Numero maximo de paquetes a mostrar (def: 20)")
    parser.add_argument("--port", type=int, default=None,
                        help="Filtrar por puerto (origen o destino)")
    parser.add_argument("--dir", choices=["orig", "resp"], default=None,
                        help="Filtrar por direccion del paquete")
    parser.add_argument("--hexdump", action="store_true",
                        help="Mostrar volcado hexadecimal completo de cada paquete")
    parser.add_argument("--maxbytes", type=int, default=120,
                        help="Bytes a mostrar por paquete en modo texto (def: 120)")
    args = parser.parse_args()

    path = Path(args.tsv)
    if not path.is_file():
        sys.exit(f"[ERROR] No existe: {path}")

    cols: list[str] | None = None
    shown = 0
    with path.open(encoding="utf-8", errors="replace") as fin:
        for line in fin:
            line = line.rstrip("\n")
            if line.startswith("#"):
                if line.startswith(FIELDS_PREFIX):
                    # #fields\tts\torig_h\t...  -> nombres de columna
                    cols = line.split("\t")[1:]
                continue
            if not line:
                continue
            if cols is None:
                sys.exit("[ERROR] TSV sin cabecera #fields; ¿es de Zeek?")

            row = dict(zip(cols, line.split("\t")))
            orig_p = int(row["orig_p"])
            resp_p = int(row["resp_p"])
            if args.port is not None and args.port not in (orig_p, resp_p):
                continue
            if args.dir is not None and row["dir"] != args.dir:
                continue

            data = bytes.fromhex(row["payload_hex"])
            arrow = "->" if row["dir"] == "orig" else "<-"
            print(f"[{row['ts']}] {row['orig_h']}:{orig_p} {arrow} "
                  f"{row['resp_h']}:{resp_p}  ({row['len']} bytes)")
            if args.hexdump:
                print(hexdump(data))
            else:
                text = printable(data[: args.maxbytes])
                suffix = "..." if len(data) > args.maxbytes else ""
                print(f"    {text}{suffix}")

            shown += 1
            if shown >= args.num:
                break

    if shown == 0:
        print("(sin paquetes que coincidan con el filtro)")


if __name__ == "__main__":
    main()

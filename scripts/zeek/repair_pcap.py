#!/usr/bin/env python3
"""Saneado de PCAPs truncados del dataset CSE-CIC-IDS2018 (TFG Fase 2).

Muchas capturas del dataset terminan con un ultimo record cortado (la captura
se interrumpio a mitad de un paquete). Al leerlas, Zeek aborta con un
"fatal error: truncated dump file". Este script reescribe la captura
conservando UNICAMENTE los records completos, truncando en el primer record
imposible de leer. La parte valida del fichero no se altera.

Soporta el formato clasico libpcap (magic a1b2c3d4 / d4c3b2a1, en sus variantes
de micro y nanosegundos). No soporta pcapng.

Uso:
    python scripts/zeek/repair_pcap.py entrada.pcap salida.pcap
    python scripts/zeek/repair_pcap.py --check entrada.pcap   # solo diagnostica
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

# Magics libpcap conocidos -> (endianness struct, resolucion). El valor es el
# uint32 leido en orden de bytes nativo del fichero.
_MAGICS = {
    0xA1B2C3D4: (">", "us"),   # big-endian, microsegundos
    0xD4C3B2A1: ("<", "us"),   # little-endian, microsegundos
    0xA1B23C4D: (">", "ns"),   # big-endian, nanosegundos
    0x4D3CB2A1: ("<", "ns"),   # little-endian, nanosegundos
}


PCAPNG_MAGIC = 0x0A0D0D0A  # bloque Section Header de pcapng (orden de bytes fijo)


def is_pcapng(path: Path) -> bool:
    """True si el fichero es pcapng (magic 0x0a0d0d0a) en vez de libpcap clasico.

    Algunas capturas del dataset (p.ej. la victima del DoS del 16-02,
    UCAP172.31.69.25-part1.pcap) se guardaron en pcapng, que repair() no sabe
    sanear pero Zeek lee de forma nativa. Los llamadores usan esto para, en ese
    caso, pasar el fichero original a Zeek sin el saneado clasico.
    """
    with path.open("rb") as f:
        return struct.unpack(">I", f.read(4))[0] == PCAPNG_MAGIC


def detect_format(global_header: bytes) -> str:
    """Devuelve el caracter de endianness ('<' o '>') segun el magic."""
    if len(global_header) < GLOBAL_HEADER_LEN:
        raise ValueError("Cabecera global incompleta: no es un PCAP clasico.")
    magic = struct.unpack(">I", global_header[:4])[0]
    if magic not in _MAGICS:
        raise ValueError(
            f"Magic 0x{magic:08x} desconocido (¿pcapng o fichero corrupto?).")
    return _MAGICS[magic][0]


def repair(src: Path, dst: Path | None) -> tuple[int, int, bool]:
    """Copia records completos de src a dst (si dst no es None).

    Devuelve (records_validos, bytes_descartados, estaba_truncado).
    """
    with src.open("rb") as fin:
        global_header = fin.read(GLOBAL_HEADER_LEN)
        endian = detect_format(global_header)

        out = dst.open("wb") if dst is not None else None
        try:
            if out is not None:
                out.write(global_header)

            n_records = 0
            while True:
                rec_header = fin.read(RECORD_HEADER_LEN)
                if len(rec_header) < RECORD_HEADER_LEN:
                    # No queda cabecera de record completa -> fin/truncado.
                    truncated = len(rec_header) > 0
                    discarded = len(rec_header)
                    break

                # ts_sec, ts_usec, incl_len, orig_len
                _, _, incl_len, _ = struct.unpack(endian + "IIII", rec_header)
                payload = fin.read(incl_len)
                if len(payload) < incl_len:
                    # Record final cortado: lo descartamos por completo.
                    truncated = True
                    discarded = RECORD_HEADER_LEN + len(payload)
                    break

                if out is not None:
                    out.write(rec_header)
                    out.write(payload)
                n_records += 1
        finally:
            if out is not None:
                out.close()

    return n_records, discarded, truncated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("src", help="PCAP de entrada")
    parser.add_argument("dst", nargs="?", default=None,
                        help="PCAP de salida saneado (omitir con --check)")
    parser.add_argument("--check", action="store_true",
                        help="Solo diagnostica: no escribe fichero de salida")
    args = parser.parse_args()

    src = Path(args.src)
    if not src.is_file():
        sys.exit(f"[ERROR] No existe: {src}")

    dst = None if args.check else (Path(args.dst) if args.dst else None)
    if not args.check and dst is None:
        sys.exit("[ERROR] Indica el PCAP de salida o usa --check.")

    try:
        n, discarded, truncated = repair(src, dst)
    except ValueError as exc:
        sys.exit(f"[ERROR] {exc}")

    state = "TRUNCADO" if truncated else "intacto"
    print(f"{src.name}: {n} records validos, {discarded} bytes descartados "
          f"({state}).")
    if dst is not None:
        print(f"  -> escrito {dst}")


if __name__ == "__main__":
    main()

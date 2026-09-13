#!/usr/bin/env python3
"""Orquestador de extraccion de payloads TCP con Zeek sobre Docker (TFG Fase 2).

Recorre los PCAP de un dia del dataset CSE-CIC-IDS2018 y, por cada captura,
lanza el contenedor oficial ``zeek/zeek`` para ejecutar el script personalizado
``extract_payload.zeek``. El resultado es un TSV por captura con el payload TCP
en hexadecimal, listo para la vectorizacion (histograma de bytes, entropia,
n-gramas...) de la Fase 2.

Sigue el flujo descrito en docker_zeek.pdf (seccion 2.3-2.4):

    docker run --rm -v <work>:/work -v <scripts>:/scripts:ro -w /work zeek/zeek \
        zeek -C -r /work/clean.pcap /scripts/extract_payload.zeek

Se ejecuta desde el host (Windows/PowerShell) con Python; subprocess pasa las
rutas del contenedor sin la traduccion de MSYS/Git-Bash que rompe los montajes.

IMPORTANTE - saneado previo obligatorio:
    Cada captura se SANEA antes con repair_pcap (se reescribe una copia con solo
    los records validos) y Zeek se ejecuta sobre esa copia. Esto NO es opcional:
    se detecto que en algunas capturas (p.ej. UCAP172.31.69.25) Zeek se detenia a
    mitad del fichero por un record que libpcap rechaza, perdiendo TODA la tarde
    en silencio (129k paquetes extraidos frente a 2,9 M reales; se perdia la
    ventana del SSH-Bruteforce). Reescribir la captura elimina ese problema y Zeek
    procesa el fichero completo (exit 0). Ver README, seccion «Pipeline de Fase 2».

Ejemplos de uso:

    # Procesar solo las 3 capturas mas pequenas (prueba rapida)
    python scripts/zeek/run_zeek_payload.py --limit 3 --smallest

    # Procesar una captura concreta
    python scripts/zeek/run_zeek_payload.py --only UCAP172.31.69.18

    # Procesar todas las capturas del miercoles (puede tardar mucho: 46 GB)
    python scripts/zeek/run_zeek_payload.py
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

# repair_pcap.py vive en el mismo directorio que este script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from repair_pcap import repair, is_pcapng  # noqa: E402

# --- Rutas del proyecto (relativas a la raiz del repo) -----------------------
# El script vive en scripts/zeek/, asi que la raiz esta dos niveles arriba.
REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_DAY = "Wednesday-14-02-2018"
PCAP_SUBDIR = Path("data/raw/Original Network Traffic and Log data")
OUTPUT_SUBDIR = Path("data/processed/zeek")
SCRIPT_DIR = REPO_ROOT / "scripts" / "zeek"
ZEEK_SCRIPT = "extract_payload.zeek"
DOCKER_IMAGE = "zeek/zeek"


def human(n_bytes: int) -> str:
    """Formatea un tamano en bytes de forma legible."""
    size = float(n_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def list_pcaps(pcap_dir: Path) -> list[Path]:
    """Devuelve los ficheros de captura (cualquier fichero regular) del dia."""
    if not pcap_dir.is_dir():
        sys.exit(f"[ERROR] No existe el directorio de PCAPs: {pcap_dir}")
    return sorted(p for p in pcap_dir.iterdir() if p.is_file())


def run_one(pcap: Path, pcap_dir: Path, out_dir: Path, force: bool) -> str:
    """Ejecuta Zeek sobre una captura y deja <captura>.payload.tsv en out_dir.

    Devuelve un estado: "ok", "skip" o "error".
    """
    out_tsv = out_dir / f"{pcap.name}.payload.tsv"
    if out_tsv.exists() and not force:
        print(f"  [skip] ya existe {out_tsv.name}")
        return "skip"

    # Directorio temporal por captura: aqui se escribe la copia saneada
    # (clean.pcap) y el payload.log que genera Zeek. Aislado por captura.
    work_dir = out_dir / f".work_{pcap.name}"
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.time()

    # 1) SANEADO OBLIGATORIO (solo pcap clasico): reescribe la captura con solo
    #    records validos. Evita que Zeek se detenga en mitad del fichero (perdida
    #    silenciosa de datos). Las capturas pcapng (p.ej. la victima del DoS del
    #    16-02) NO se pueden sanear con repair(); Zeek lee pcapng de forma nativa,
    #    asi que en ese caso se le pasa el fichero original directamente.
    truncated = False
    discarded = 0
    if is_pcapng(pcap):
        mounts = ["-v", f"{pcap.parent}:/pcap:ro", "-v", f"{work_dir}:/work"]
        target = f"/pcap/{pcap.name}"
    else:
        clean = work_dir / "clean.pcap"
        try:
            _, discarded, truncated = repair(pcap, clean)
        except ValueError as exc:
            print(f"  [ERROR] {pcap.name}: no es un PCAP clasico ({exc})")
            shutil.rmtree(work_dir, ignore_errors=True)
            return "error"
        mounts = ["-v", f"{work_dir}:/work"]
        target = "/work/clean.pcap"

    # 2) Zeek sobre la captura (copia saneada, o pcapng original). exit 0 esperado.
    cmd = [
        "docker", "run", "--rm",
        *mounts,
        "-v", f"{SCRIPT_DIR}:/scripts:ro",
        "-w", "/work",
        DOCKER_IMAGE,
        "zeek", "-C", "-r", target, f"/scripts/{ZEEK_SCRIPT}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0

    payload_log = work_dir / "payload.log"
    if proc.returncode != 0 and not payload_log.exists():
        # Fallo real: ni siquiera se genero el log.
        print(f"  [ERROR] Zeek fallo ({elapsed:.0f}s) en {pcap.name}")
        if proc.stderr.strip():
            for line in proc.stderr.strip().splitlines()[:5]:
                print(f"          {line}")
        shutil.rmtree(work_dir, ignore_errors=True)
        return "error"

    if not payload_log.exists():
        # Captura sin payload TCP (p.ej. solo trafico de control / UDP).
        print(f"  [vacio] {pcap.name}: sin payload TCP ({elapsed:.0f}s)")
        out_tsv.write_text("", encoding="utf-8")
        shutil.rmtree(work_dir, ignore_errors=True)
        return "ok"

    # Mover el payload.log al destino final con nombre por captura.
    shutil.move(str(payload_log), str(out_tsv))
    rows = max(0, sum(1 for _ in out_tsv.open(encoding="utf-8", errors="replace"))
               - 8)  # ~8 lineas de cabecera Zeek (#separator, #fields, ...)

    note = f" (saneado: {discarded} B descartados)" if truncated else ""
    if proc.returncode != 0:
        note += " (con avisos de Zeek)"
    print(f"  [ok]  {pcap.name} -> {out_tsv.name} "
          f"({human(out_tsv.stat().st_size)}, ~{rows} paquetes, "
          f"{elapsed:.0f}s){note}")
    shutil.rmtree(work_dir, ignore_errors=True)
    return "ok"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY,
                        help=f"Carpeta del dia dentro del dataset (def: {DEFAULT_DAY})")
    parser.add_argument("--pcap-dir", default=None,
                        help="Directorio con los PCAP a procesar (override). Por "
                             "defecto usa la estructura de CSE-CIC-IDS2018 "
                             "('.../<dia>/pcap'). Util para otros datasets como "
                             "CIC-IDS2017 (ruta relativa a la raiz del repo o absoluta).")
    parser.add_argument("--limit", type=int, default=0,
                        help="Procesar como mucho N capturas (0 = todas)")
    parser.add_argument("--smallest", action="store_true",
                        help="Ordenar por tamano ascendente (util con --limit)")
    parser.add_argument("--only", default=None,
                        help="Procesar unicamente la captura con este nombre")
    parser.add_argument("--force", action="store_true",
                        help="Reprocesar aunque ya exista el TSV de salida")
    args = parser.parse_args()

    if args.pcap_dir:
        pcap_dir = Path(args.pcap_dir)
        if not pcap_dir.is_absolute():
            pcap_dir = REPO_ROOT / pcap_dir
    else:
        pcap_dir = REPO_ROOT / PCAP_SUBDIR / args.day / "pcap"
    out_dir = REPO_ROOT / OUTPUT_SUBDIR / args.day.lower()
    out_dir.mkdir(parents=True, exist_ok=True)

    pcaps = list_pcaps(pcap_dir)
    if args.only:
        pcaps = [p for p in pcaps if p.name == args.only]
        if not pcaps:
            sys.exit(f"[ERROR] No se encontro la captura '{args.only}' en {pcap_dir}")
    if args.smallest:
        pcaps.sort(key=lambda p: p.stat().st_size)
    if args.limit > 0:
        pcaps = pcaps[: args.limit]

    total_size = sum(p.stat().st_size for p in pcaps)
    print(f"Dataset:  {pcap_dir}")
    print(f"Salida:   {out_dir}")
    print(f"Capturas: {len(pcaps)}  ({human(total_size)} a procesar)\n")

    counts = {"ok": 0, "skip": 0, "error": 0}
    for i, pcap in enumerate(pcaps, 1):
        print(f"[{i}/{len(pcaps)}] {pcap.name} ({human(pcap.stat().st_size)})")
        status = run_one(pcap, pcap_dir, out_dir, args.force)
        counts[status] += 1

    print(f"\nResumen: {counts['ok']} ok, {counts['skip']} omitidas, "
          f"{counts['error']} con error.")
    if counts["error"]:
        sys.exit(1)


if __name__ == "__main__":
    main()

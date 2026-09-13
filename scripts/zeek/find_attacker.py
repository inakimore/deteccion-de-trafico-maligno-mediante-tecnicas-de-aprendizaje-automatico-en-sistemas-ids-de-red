#!/usr/bin/env python3
"""Identifica el atacante de un dia procesando conn.log con Zeek (TFG Fase 2/3).

Complemento de find_host.py. Mientras que find_host.py necesita una IP CANDIDATA
para localizar la captura, este script no la necesita: ejecuta Zeek (scripts por
defecto -> conn.log) sobre una captura y lista los TOP TALKERS por numero de
conexiones, tanto en total como hacia un puerto de servicio concreto. En un ataque
volumetrico (DoS/DDoS) el atacante domina de forma abrumadora, asi que aparece el
primero sin conocer su IP de antemano. Ademas imprime el rango temporal UTC de esas
conexiones, para fijar la ventana del ataque en attack_metadata.py.

Sigue el mismo patron que run_zeek_payload.py: saneado obligatorio de la captura
(repair_pcap) y Zeek en el contenedor oficial zeek/zeek via Docker.

Uso:
    python scripts/zeek/find_attacker.py --day Friday-16-02-2018 --capture UCAP172.31.69.25 --port 80
    python scripts/zeek/find_attacker.py --day Friday-16-02-2018 --capture UCAP172.31.69.25 --to-victim 172.31.69.25
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from repair_pcap import repair, is_pcapng  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PCAP_SUBDIR = Path("data/raw/Original Network Traffic and Log data")
DOCKER_IMAGE = "zeek/zeek"


def run_zeek_conn(pcap: Path, work_dir: Path) -> Path:
    """Sanea la captura y ejecuta Zeek (scripts por defecto) -> conn.log.

    Para capturas pcapng (que repair() no sabe sanear) se pasa el fichero
    original a Zeek, que lee pcapng de forma nativa.
    """
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    mounts = ["-v", f"{work_dir}:/work"]
    if is_pcapng(pcap):
        print(f"[1/2] {pcap.name} es pcapng -> Zeek directo (sin saneado clasico)", flush=True)
        mounts += ["-v", f"{pcap.parent}:/pcap:ro"]
        target = f"/pcap/{pcap.name}"
    else:
        clean = work_dir / "clean.pcap"
        print(f"[1/2] Saneando {pcap.name} ...", flush=True)
        _, discarded, truncated = repair(pcap, clean)
        if truncated:
            print(f"      (saneado: {discarded} B descartados del final)")
        target = "/work/clean.pcap"

    print("[2/2] Zeek (conn.log) ...", flush=True)
    cmd = [
        "docker", "run", "--rm",
        *mounts,
        "-w", "/work",
        DOCKER_IMAGE,
        "zeek", "-C", "-r", target,
    ]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(f"      Zeek exit={proc.returncode} en {time.time()-t0:.0f}s")
    conn = work_dir / "conn.log"
    if not conn.exists():
        if proc.stderr.strip():
            print(proc.stderr.strip()[:500])
        sys.exit("[ERROR] Zeek no genero conn.log")
    return conn


def parse_conn(conn: Path):
    """Lee conn.log y devuelve (filas, indices de campos)."""
    fields = None
    rows = []
    with conn.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            rows.append(line.rstrip("\n").split("\t"))
    if fields is None:
        sys.exit("[ERROR] conn.log sin cabecera #fields")
    idx = {name: i for i, name in enumerate(fields)}
    return rows, idx


def utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True, help="Carpeta del dia (p.ej. Friday-16-02-2018)")
    ap.add_argument("--capture", required=True, help="Nombre de la captura (p.ej. UCAP172.31.69.25)")
    ap.add_argument("--pcap-dir", default=None,
                    help="Directorio con la captura (override). Por defecto usa la "
                         "estructura de CSE-CIC-IDS2018 ('.../<dia>/pcap'). Para otros "
                         "datasets (p.ej. CIC-IDS2017) apunta aqui a su carpeta de PCAPs "
                         "(ruta relativa a la raiz del repo o absoluta).")
    ap.add_argument("--port", type=int, default=None,
                    help="Puerto de servicio para el ranking dirigido (p.ej. 80)")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    if args.pcap_dir:
        base = Path(args.pcap_dir)
        if not base.is_absolute():
            base = REPO_ROOT / base
        pcap = base / args.capture
    else:
        pcap = REPO_ROOT / PCAP_SUBDIR / args.day / "pcap" / args.capture
    if not pcap.is_file():
        sys.exit(f"[ERROR] No existe la captura {pcap}")

    work_dir = REPO_ROOT / "data" / "processed" / "zeek" / ".conn_probe"
    conn = run_zeek_conn(pcap, work_dir)
    rows, idx = parse_conn(conn)
    oh_i, rh_i, rp_i, ts_i = idx["id.orig_h"], idx["id.resp_h"], idx["id.resp_p"], idx["ts"]

    cs_i = idx.get("conn_state")
    ob_i = idx.get("orig_bytes")
    rb_i = idx.get("resp_bytes")
    total = Counter()
    to_port = Counter()
    pair_port = Counter()
    pair_state: dict[str, Counter] = {}
    pair_bytes: dict[str, int] = {}
    tspan: dict[str, list] = {}
    for r in rows:
        oh, rh, rp = r[oh_i], r[rh_i], r[rp_i]
        total[oh] += 1
        try:
            ts = float(r[ts_i])
        except ValueError:
            ts = None
        if args.port is not None and rp == str(args.port):
            to_port[oh] += 1
            key = f"{oh} -> {rh}:{rp}"
            pair_port[key] += 1
            if cs_i is not None:
                pair_state.setdefault(key, Counter())[r[cs_i]] += 1
            # bytes de aplicacion (orig+resp); '-' cuando Zeek no lo sabe
            def _b(v):
                try:
                    return int(v)
                except (ValueError, TypeError):
                    return 0
            if ob_i is not None and rb_i is not None:
                pair_bytes[key] = pair_bytes.get(key, 0) + _b(r[ob_i]) + _b(r[rb_i])
            if ts is not None:
                sp = tspan.setdefault(key, [ts, ts])
                sp[0] = min(sp[0], ts); sp[1] = max(sp[1], ts)

    print(f"\nconn.log: {len(rows)} conexiones en {args.capture}\n")
    print(f"=== Top {args.top} origenes por nº de conexiones (total) ===")
    for oh, n in total.most_common(args.top):
        print(f"  {oh:16s} {n:>10}")

    if args.port is not None:
        print(f"\n=== Top {args.top} origenes -> :{args.port} ===")
        for oh, n in to_port.most_common(args.top):
            print(f"  {oh:16s} {n:>10}")
        print(f"\n=== Top pares origen->victima:{args.port} (rango UTC, conn_state, bytes app) ===")
        for key, n in pair_port.most_common(args.top):
            sp = tspan.get(key)
            span = f"{utc(sp[0])} .. {utc(sp[1])}" if sp else "-"
            states = pair_state.get(key)
            st = " ".join(f"{s}:{c}" for s, c in states.most_common(4)) if states else "-"
            nb = pair_bytes.get(key, 0)
            print(f"  {key:34s} {n:>10}   [{span} UTC]")
            print(f"      conn_state: {st}   bytes_app(orig+resp): {nb}")

    shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

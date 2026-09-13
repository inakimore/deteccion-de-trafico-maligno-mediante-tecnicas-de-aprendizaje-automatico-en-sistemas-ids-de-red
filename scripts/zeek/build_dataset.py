#!/usr/bin/env python3
"""Construye el dataset de payload etiquetado para la Fase 2 del TFG.

Lee los TSV de payload generados por extract_payload.zeek + run_zeek_payload.py
(uno por captura), agrupa los paquetes por flujo TCP (uid de Zeek) y, por cada
flujo, calcula la representacion vectorial definida el 28 de abril:

  1. Distribucion de bytes + entropia:
       - byte_hist[256]  histograma normalizado de los bytes del payload.
       - entropy         entropia de Shannon (bits/byte) del payload del flujo.
  2. Secuencia de bytes (para modelos secuenciales / sliding-window):
       - byte_seq[SEQ_LEN]  primeros SEQ_LEN bytes del payload (relleno con 0).

Ademas guarda metadatos del flujo (uid, ts, 5-tupla, `service` identificado por
las reglas de Zeek, nº de paquetes, bytes) y la
ETIQUETA, asignada con attack_metadata.DayLabeler (ground-truth por IP+puerto+
ventana temporal, ya que el CSV no trae IPs; ver attack_metadata.py).

Salida en data/processed/zeek/<dia>/:
  - dataset_<dia>.npz         arrays NumPy (X_hist, X_seq, entropy, y, meta...).
  - dataset_<dia>_meta.csv    una fila por flujo con metadatos + escalares +
                              etiqueta (sin las columnas anchas), para inspeccion.

Por que .npz y no .parquet: el entorno tfg_ia no tiene pyarrow. El .npz es
autocontenido y se carga con numpy.load(...); el CSV permite revisar a ojo y con
pandas las etiquetas y los escalares.

Ejemplos:
    conda run -n tfg_ia python scripts/zeek/build_dataset.py
    conda run -n tfg_ia python scripts/zeek/build_dataset.py --only UCAP172.31.69.25.payload.tsv
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np

# attack_metadata.py vive en el mismo directorio que este script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_metadata import DayLabeler  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = REPO_ROOT / "data" / "processed" / "zeek"

DEFAULT_DAY = "Wednesday-14-02-2018"
SEQ_LEN = 256            # bytes iniciales que se guardan como secuencia
MAX_FLOW_BYTES = 65536   # tope de bytes por flujo para el histograma (memoria)


class FlowAcc:
    """Acumulador de un flujo TCP mientras se recorre el TSV."""
    __slots__ = ("hist", "seq", "n_pkts", "tot_bytes", "hist_bytes",
                 "ts", "oh", "op", "rh", "rp", "service")

    def __init__(self, ts, oh, op, rh, rp):
        self.hist = np.zeros(256, dtype=np.int64)
        self.seq = bytearray()
        self.n_pkts = 0
        self.tot_bytes = 0
        self.hist_bytes = 0
        self.ts = ts          # primer timestamp del flujo
        self.oh, self.op, self.rh, self.rp = oh, op, rh, rp
        # Servicio identificado por Zeek (DPI). La deteccion es progresiva, asi
        # que nos quedamos con el ultimo valor no vacio visto en el flujo.
        self.service = "-"

    def add(self, data: bytes) -> None:
        self.n_pkts += 1
        self.tot_bytes += len(data)
        # Secuencia: primeros SEQ_LEN bytes.
        if len(self.seq) < SEQ_LEN:
            self.seq.extend(data[: SEQ_LEN - len(self.seq)])
        # Histograma: hasta MAX_FLOW_BYTES bytes por flujo.
        if self.hist_bytes < MAX_FLOW_BYTES:
            take = data[: MAX_FLOW_BYTES - self.hist_bytes]
            if take:
                arr = np.frombuffer(take, dtype=np.uint8)
                self.hist += np.bincount(arr, minlength=256)
                self.hist_bytes += len(take)


def shannon_entropy(hist: np.ndarray) -> float:
    """Entropia de Shannon (bits/byte) a partir de un histograma de cuentas."""
    total = hist.sum()
    if total == 0:
        return 0.0
    p = hist[hist > 0] / total
    return float(-(p * np.log2(p)).sum())


def parse_tsv(path: Path):
    """Itera filas de un TSV de payload devolviendo dicts por columna."""
    cols = None
    with path.open(encoding="utf-8", errors="replace") as fin:
        for line in fin:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    cols = line.rstrip("\n").split("\t")[1:]
                continue
            line = line.rstrip("\n")
            if not line:
                continue
            if cols is None:
                raise ValueError(f"{path.name}: TSV sin cabecera #fields")
            yield dict(zip(cols, line.split("\t")))


def process_capture(path: Path) -> dict[str, FlowAcc]:
    """Agrupa los paquetes de una captura por uid de flujo."""
    flows: dict[str, FlowAcc] = {}
    for row in parse_tsv(path):
        uid = row.get("uid")
        if uid is None:
            raise ValueError(
                f"{path.name}: el TSV no tiene columna 'uid'. Re-extrae con la "
                "version actual de extract_payload.zeek (incluye uid).")
        acc = flows.get(uid)
        if acc is None:
            acc = FlowAcc(float(row["ts"]), row["orig_h"], int(row["orig_p"]),
                          row["resp_h"], int(row["resp_p"]))
            flows[uid] = acc
        # Columna anadida el 11-ago (correccion del tutor): servicio segun las
        # reglas de Zeek. Los TSV extraidos antes de esa fecha no la traen; el
        # dataset se construye igual y el servicio se deja a "-" (para esos dias
        # se deriva a posteriori con service_id.py sobre los bytes guardados).
        svc = row.get("service")
        if svc and svc != "-":
            acc.service = svc
        acc.add(bytes.fromhex(row["payload_hex"]))
    return flows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--day", default=DEFAULT_DAY,
                        help=f"Dia del dataset (def: {DEFAULT_DAY})")
    parser.add_argument("--only", default=None,
                        help="Procesar solo este TSV (nombre de fichero)")
    parser.add_argument("--out", default=None,
                        help="Prefijo de salida (def: dataset_<dia>)")
    args = parser.parse_args()

    in_dir = PROCESSED / args.day.lower()
    if not in_dir.is_dir():
        sys.exit(f"[ERROR] No existe {in_dir}. Ejecuta antes run_zeek_payload.py")

    tsvs = sorted(in_dir.glob("*.payload.tsv"))
    if args.only:
        tsvs = [p for p in tsvs if p.name == args.only]
    if not tsvs:
        sys.exit(f"[ERROR] No hay *.payload.tsv en {in_dir}")

    labeler = DayLabeler(args.day)
    print(labeler.summary())
    print(f"\nCapturas a procesar: {len(tsvs)}\n")

    # Acumuladores globales (listas -> arrays al final).
    hists, seqs, entropies = [], [], []
    n_pkts_l, tot_bytes_l, seqlen_l = [], [], []
    uids, ts_l, oh_l, op_l, rh_l, rp_l, labels = [], [], [], [], [], [], []
    svc_l = []

    for i, tsv in enumerate(tsvs, 1):
        t0 = time.time()
        flows = process_capture(tsv)
        for uid, f in flows.items():
            label = labeler.label(f.oh, f.op, f.rh, f.rp, f.ts)
            total = f.hist.sum()
            hist_norm = (f.hist / total).astype(np.float32) if total else \
                np.zeros(256, dtype=np.float32)
            seq = np.zeros(SEQ_LEN, dtype=np.uint8)
            seq[: len(f.seq)] = np.frombuffer(bytes(f.seq), dtype=np.uint8)

            hists.append(hist_norm)
            seqs.append(seq)
            entropies.append(shannon_entropy(f.hist))
            n_pkts_l.append(f.n_pkts)
            tot_bytes_l.append(f.tot_bytes)
            seqlen_l.append(len(f.seq))
            uids.append(uid)
            ts_l.append(f.ts)
            oh_l.append(f.oh); op_l.append(f.op)
            rh_l.append(f.rh); rp_l.append(f.rp)
            svc_l.append(f.service)
            labels.append(label)
        print(f"[{i}/{len(tsvs)}] {tsv.name}: {len(flows)} flujos "
              f"({time.time()-t0:.1f}s)")

    n = len(uids)
    if n == 0:
        sys.exit("[ERROR] No se genero ningun flujo.")

    X_hist = np.vstack(hists)
    X_seq = np.vstack(seqs)
    entropy = np.asarray(entropies, dtype=np.float32)
    y = np.asarray(labels, dtype=object)

    prefix = args.out or f"dataset_{args.day}"
    npz_path = in_dir / f"{prefix}.npz"
    np.savez_compressed(
        npz_path,
        X_hist=X_hist, X_seq=X_seq, entropy=entropy,
        n_pkts=np.asarray(n_pkts_l, dtype=np.int32),
        tot_bytes=np.asarray(tot_bytes_l, dtype=np.int64),
        seq_len=np.asarray(seqlen_l, dtype=np.int32),
        uid=np.asarray(uids, dtype=object), ts=np.asarray(ts_l, dtype=np.float64),
        orig_h=np.asarray(oh_l, dtype=object), orig_p=np.asarray(op_l, dtype=np.int32),
        resp_h=np.asarray(rh_l, dtype=object), resp_p=np.asarray(rp_l, dtype=np.int32),
        service=np.asarray(svc_l, dtype=object),
        y=y,
    )

    # CSV de metadatos (sin las columnas anchas) para inspeccion rapida.
    import pandas as pd
    meta = pd.DataFrame({
        "uid": uids, "ts": ts_l, "orig_h": oh_l, "orig_p": op_l,
        "resp_h": rh_l, "resp_p": rp_l, "service": svc_l, "n_pkts": n_pkts_l,
        "tot_bytes": tot_bytes_l, "seq_len": seqlen_l,
        "entropy": entropy, "label": labels,
    })
    csv_path = in_dir / f"{prefix}_meta.csv"
    meta.to_csv(csv_path, index=False)

    print(f"\n== Dataset generado: {n} flujos ==")
    print("Distribucion de etiquetas:")
    print(meta["label"].value_counts().to_string())
    print(f"\nArrays  -> {npz_path}")
    print(f"          X_hist{X_hist.shape} float32, X_seq{X_seq.shape} uint8, "
          f"entropy{entropy.shape}")
    print(f"Metadata-> {csv_path}")


if __name__ == "__main__":
    main()

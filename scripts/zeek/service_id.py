#!/usr/bin/env python3
"""Identificacion del SERVICIO de aplicacion por contenido (correccion del tutor).

MOTIVACION (revision del tutor, 11-ago-2026)
--------------------------------------------
"Los puertos no deberian ir como atributo (es un poco como la IP, depende de cada
configuracion, no es un atributo context independent); el servicio podria ir si es
que Zeek tiene reglas para identificarlo."

Estado del proyecto ante esa observacion:

  - Como ATRIBUTO del modelo el puerto ya estaba excluido a proposito desde la
    Fase 2 (ver hybrid_compare.build_meta_features: n_pkts, tot_bytes, bytes/pkt,
    seq_len; sin puerto). En la Fase 1 si se uso `Dst Port` y fue precisamente la
    variable-atajo que se detecto y ablaciono (diario del 31 de marzo).
  - Pero el puerto SI se seguia usando para SELECCIONAR el subconjunto evaluado
    (`resp_p == 22` = "SSH", `resp_p == 80` = "HTTP"). Eso hereda el mismo defecto:
    define el servicio por una convencion de configuracion, no por el trafico.

Este modulo sustituye esa nocion por el SERVICIO:

  1. Si el dataset trae la columna `service` (extraccion posterior al 11-ago, con
     `extract_payload.zeek` ya emitiendo `c$service`), se usa **la identificacion
     de Zeek** directamente. Es la via preferente y la que pide el tutor.
  2. Si no la trae (los tres dias de 2018 y los tres de 2017 ya vectorizados, cuyos
     PCAP/TSV se borraron por espacio), se deriva del CONTENIDO con firmas DPI
     equivalentes a las de los analizadores de Zeek, aplicadas sobre los bytes que
     el dataset ya guarda (`X_seq`, primeros 256 B del flujo). Mismo criterio
     (el protocolo se reconoce por lo que dice el trafico), sin re-descargar 150 GB.

Las firmas replican lo que hacen los analizadores de Zeek para fijar `conn.log$service`:
banner `SSH-`, metodos/respuesta HTTP, record TLS, NBSS/SMB, TPKT/X.224 de RDP,
saludos SMTP/FTP/POP3/IMAP, negociacion Telnet y greeting de MySQL.

USO COMO LIBRERIA
-----------------
    from service_id import identify_services, service_selection
    svc  = identify_services(d)                      # array de str, uno por flujo
    mask = service_selection(d, port=22, service="ssh")   # service manda si se da

USO COMO CLI (informe de validacion puerto vs servicio)
-------------------------------------------------------
    conda run -n tfg_ia python scripts/zeek/service_id.py --day Wednesday-14-02-2018
    conda run -n tfg_ia python scripts/zeek/service_id.py --day Thursday-22-02-2018 --port 80

Escribe models/phase3_service_id_<dia>.md con la tabla cruzada servicio x puerto,
el grado de acuerdo con la convencion de puertos y los flujos que la contradicen.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSED = REPO_ROOT / "data" / "processed" / "zeek"
MODELS_DIR = REPO_ROOT / "models"

# Servicio de referencia asociado a cada puerto "de libro". SOLO se usa para
# medir el acuerdo entre la convencion de puertos y el contenido real; nunca
# para etiquetar ni como atributo.
PORT_HINT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
    143: "imap", 443: "ssl", 445: "smb", 3306: "mysql", 3389: "rdp",
    8080: "http",
}

NO_PAYLOAD = "no-payload"   # flujo sin datos de aplicacion (p. ej. los REJ del FTP)
OTHER = "other"             # con datos, pero ninguna firma conocida encaja

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ", b"TRACE ", b"PROPFIND ", b"HTTP/")


def _starts(S: np.ndarray, prefix: bytes) -> np.ndarray:
    """Filas de S (n,L) uint8 que empiezan por `prefix`."""
    p = np.frombuffer(prefix, dtype=np.uint8)
    if S.shape[1] < len(p):
        return np.zeros(len(S), dtype=bool)
    return (S[:, : len(p)] == p).all(axis=1)


def _at(S: np.ndarray, off: int, sub: bytes) -> np.ndarray:
    """Filas de S que contienen `sub` exactamente en el offset `off`."""
    p = np.frombuffer(sub, dtype=np.uint8)
    if S.shape[1] < off + len(p):
        return np.zeros(len(S), dtype=bool)
    return (S[:, off : off + len(p)] == p).all(axis=1)


def _contains(S: np.ndarray, sub: bytes, limit: int = 48) -> np.ndarray:
    """Filas de S que contienen `sub` dentro de los primeros `limit` bytes."""
    p = np.frombuffer(sub, dtype=np.uint8)
    end = min(limit, S.shape[1]) - len(p) + 1
    hit = np.zeros(len(S), dtype=bool)
    for i in range(max(end, 0)):
        hit |= (S[:, i : i + len(p)] == p).all(axis=1)
    return hit


def _classify_chunk(S: np.ndarray, seq_len: np.ndarray) -> np.ndarray:
    """Clasifica un bloque de flujos por firma de contenido.

    El orden importa: se prueban las firmas mas especificas primero y cada flujo
    se asigna una sola vez (`free` marca los aun sin decidir), igual que la cadena
    de analizadores de Zeek.
    """
    out = np.full(len(S), OTHER, dtype=object)
    free = seq_len > 0
    out[~free] = NO_PAYLOAD

    def assign(name: str, hit: np.ndarray) -> None:
        nonlocal free
        take = free & hit
        out[take] = name
        free = free & ~take

    # SSH: banner en claro del handshake ("SSH-2.0-...").
    assign("ssh", _starts(S, b"SSH-"))

    # HTTP: linea de peticion (metodo + espacio) o linea de respuesta "HTTP/".
    http = np.zeros(len(S), dtype=bool)
    for m in HTTP_METHODS:
        http |= _starts(S, m)
    assign("http", http)

    # TLS/SSL: record layer -> tipo (0x14..0x17) + version 0x03 0x00-0x04.
    tls = (np.isin(S[:, 0], [0x14, 0x15, 0x16, 0x17]) & (S[:, 1] == 0x03)
           & (S[:, 2] <= 0x04))
    assign("ssl", tls)

    # SMB: cabecera NBSS (4 B) + "\xffSMB" (SMBv1) o "\xfeSMB" (SMB2), o directa.
    smb = (_at(S, 4, b"\xffSMB") | _at(S, 4, b"\xfeSMB")
           | _starts(S, b"\xffSMB") | _starts(S, b"\xfeSMB"))
    assign("smb", smb)

    # RDP: TPKT (version 3, reservado 0) + X.224 CR/CC (0xE0 / 0xD0).
    rdp = (S[:, 0] == 0x03) & (S[:, 1] == 0x00) & np.isin(S[:, 5], [0xE0, 0xD0])
    assign("rdp", rdp)

    # SMTP: saludo del cliente o banner 220 que se identifica como (E)SMTP.
    smtp = (_starts(S, b"EHLO") | _starts(S, b"HELO") | _starts(S, b"MAIL FROM")
            | (_starts(S, b"220") & _contains(S, b"SMTP")))
    assign("smtp", smtp)

    # FTP: comandos de control o banner 220 que se identifica como FTP.
    ftp = (_starts(S, b"USER ") | _starts(S, b"PASS ")
           | (_starts(S, b"220") & _contains(S, b"FTP")))
    assign("ftp", ftp)

    assign("pop3", _starts(S, b"+OK"))
    assign("imap", _starts(S, b"* OK"))

    # Telnet: IAC (0xFF) + WILL/WONT/DO/DONT.
    assign("telnet", (S[:, 0] == 0xFF) & np.isin(S[:, 1], [0xFB, 0xFC, 0xFD, 0xFE]))

    # MySQL: greeting del servidor -> longitud (3 B, <256) + seq 0 + protocolo 10.
    assign("mysql", (S[:, 0] > 0) & (S[:, 1] == 0x00) & (S[:, 2] == 0x00)
           & (S[:, 3] == 0x00) & (S[:, 4] == 0x0A))

    return out


def identify_services(d, sel=None, chunk: int = 200_000,
                      prefer_zeek: bool = True) -> np.ndarray:
    """Servicio por flujo. Usa `service` de Zeek si existe; si no, firmas DPI.

    `sel` (opcional): indices de fila, para no materializar X_seq entero en dias
    masivos (el DoS tiene 4 M de flujos). `chunk` acota los temporales de numpy.
    """
    if prefer_zeek and "service" in getattr(d, "files", []):
        svc = d["service"].astype(str)
        svc = svc[sel] if sel is not None else svc
        # Zeek puede dejar el servicio vacio ("-") en flujos que no llega a
        # identificar; esos caen a la firma de contenido mas abajo.
        if (svc != "-").any():
            unknown = np.flatnonzero(svc == "-")
            if len(unknown):
                sub = sel[unknown] if sel is not None else unknown
                svc[unknown] = identify_services(d, sel=sub, chunk=chunk,
                                                 prefer_zeek=False)
            # Zeek lista varios servicios por conexion ("ssl,http"); nos quedamos
            # con el primero, que es el analizador principal.
            return np.array([s.split(",")[0] for s in svc], dtype=object)

    seq_len_all = d["seq_len"].astype(np.int64)
    idx = np.arange(len(seq_len_all)) if sel is None else np.asarray(sel)
    X_seq = d["X_seq"]
    out = np.empty(len(idx), dtype=object)
    for i in range(0, len(idx), chunk):
        part = idx[i : i + chunk]
        out[i : i + len(part)] = _classify_chunk(X_seq[part], seq_len_all[part])
    return out


def service_selection(d, port: int | None = None, service: str | None = None,
                      sel=None) -> np.ndarray:
    """Mascara booleana del subconjunto a evaluar.

    Si se indica `service`, la seleccion es por SERVICIO identificado por contenido
    (via preferente tras la correccion del tutor). Si no, se cae a la seleccion
    historica por `resp_p == port`, que se conserva solo para reproducir los
    resultados ya publicados en el diario.
    """
    if service:
        svc = identify_services(d, sel=sel)
        wanted = {s.strip().lower() for s in service.split(",")}
        return np.isin(np.array([s.lower() for s in svc], dtype=object),
                       list(wanted))
    if port is None:
        raise ValueError("Indica --port o --service para seleccionar el subconjunto")
    resp_p = d["resp_p"].astype(int)
    resp_p = resp_p[sel] if sel is not None else resp_p
    return resp_p == port


def selection_label(port: int | None, service: str | None) -> str:
    """Descripcion legible de como se selecciono el subconjunto (para informes)."""
    return f"servicio={service} (DPI)" if service else f"puerto={port} (convencion)"


# --------------------------------------------------------------------------- CLI

def load_dataset(day: str):
    npz = PROCESSED / day.lower() / f"dataset_{day}.npz"
    if not npz.is_file():
        sys.exit(f"[ERROR] No existe {npz}. Ejecuta antes build_dataset.py")
    return np.load(npz, allow_pickle=True)


def write_report(day, svc, resp_p, y, focus_port, out_dir) -> Path:
    services, counts = np.unique(svc.astype(str), return_counts=True)
    order = np.argsort(-counts)

    L = [
        f"# Servicio por contenido vs puerto ({day})",
        "",
        "Correccion del tutor (11-ago): el puerto depende de la configuracion de",
        "cada red y no es un atributo *context independent*, asi que no puede",
        "definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con",
        "las mismas firmas que usan los analizadores de Zeek para rellenar",
        "`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,",
        "TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).",
        "",
        f"Flujos analizados: **{len(svc):,}**",
        "",
        "## Servicios detectados",
        "",
        "| Servicio | Flujos | % |",
        "|----------|--------|---|",
    ]
    for i in order:
        L.append(f"| {services[i]} | {counts[i]:,} | "
                 f"{counts[i] / len(svc) * 100:.2f}% |")

    # Acuerdo global con la convencion de puertos (solo puertos "de libro").
    hint = np.array([PORT_HINT.get(int(p), "") for p in resp_p], dtype=object)
    known = hint != ""
    with_payload = svc.astype(str) != NO_PAYLOAD
    comparable = known & with_payload
    agree = comparable & (svc.astype(str) == hint.astype(str))
    L += [
        "",
        "## Acuerdo con la convencion de puertos",
        "",
        f"- Flujos con puerto conocido y con payload: **{int(comparable.sum()):,}**",
        f"- El contenido confirma el servicio del puerto: **{int(agree.sum()):,}** "
        f"({int(agree.sum()) / max(int(comparable.sum()), 1) * 100:.2f}%)",
        f"- El contenido lo **contradice**: **{int((comparable & ~agree).sum()):,}**",
        "",
    ]

    # Detalle del servicio bajo estudio del dia.
    if focus_port is not None:
        target = PORT_HINT.get(focus_port, "?")
        by_port = resp_p == focus_port
        by_svc = svc.astype(str) == target
        L += [
            f"## Servicio bajo estudio: `{target}` (puerto {focus_port})",
            "",
            "| Criterio de seleccion | Flujos | Ataque | Benigno |",
            "|-----------------------|--------|--------|---------|",
        ]
        for name, m in (("puerto == %d" % focus_port, by_port),
                        (f"servicio == {target} (DPI)", by_svc),
                        ("ambos (interseccion)", by_port & by_svc)):
            ys = y[m]
            n_atk = int((ys != "Benign").sum())
            L.append(f"| {name} | {int(m.sum()):,} | {n_atk:,} | "
                     f"{int((ys == 'Benign').sum()):,} |")
        solo_port = by_port & ~by_svc
        solo_svc = by_svc & ~by_port
        L += [
            "",
            f"- En el puerto {focus_port} pero **sin** el contenido de `{target}`: "
            f"**{int(solo_port.sum()):,}** flujos "
            f"({int((y[solo_port] != 'Benign').sum()):,} de ataque). Reparto real: "
            + ", ".join(f"`{s}` {c:,}" for s, c in
                        zip(*np.unique(svc.astype(str)[solo_port], return_counts=True)))
            + ".",
            f"- Con contenido `{target}` **fuera** del puerto {focus_port}: "
            f"**{int(solo_svc.sum()):,}** flujos "
            f"({int((y[solo_svc] != 'Benign').sum()):,} de ataque). Son justo los que "
            "la seleccion por puerto se dejaba fuera.",
            "",
        ]

    out = out_dir / f"phase3_service_id_{day}.md"
    out.write_text("\n".join(L), encoding="utf-8")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--day", required=True, help="Dia del dataset")
    ap.add_argument("--port", type=int, default=None,
                    help="Puerto del servicio bajo estudio del dia (detalle en el informe)")
    args = ap.parse_args()

    MODELS_DIR.mkdir(exist_ok=True)
    d = load_dataset(args.day)
    y = d["y"].astype(str)
    resp_p = d["resp_p"].astype(int)

    print(f"Identificando servicio por contenido en {len(y):,} flujos...")
    svc = identify_services(d)

    services, counts = np.unique(svc.astype(str), return_counts=True)
    for i in np.argsort(-counts):
        print(f"  {services[i]:12s} {counts[i]:>10,}  "
              f"({counts[i]/len(svc)*100:5.2f}%)")

    out = write_report(args.day, svc, resp_p, y, args.port, MODELS_DIR)
    print(f"\nInforme -> {out}")


if __name__ == "__main__":
    main()

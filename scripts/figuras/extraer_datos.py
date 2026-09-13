#!/usr/bin/env python
"""Extrae de los datasets pesados los agregados que necesitan las figuras.

Los `dataset_<dia>.npz` ocupan 5.4 GB y los `_meta.csv` otros 1.0 GB. Leerlos
en cada figura seria inviable, asi que este script los recorre UNA vez y deja
en `figuras/cache/` unos pocos ficheros pequenos (unos MB) con lo justo para
dibujar. Las figuras nunca tocan los datos originales.

    conda run -n tfg_ia python scripts/figuras/extraer_datos.py
    conda run -n tfg_ia python scripts/figuras/extraer_datos.py --dia 14-02

Que se extrae y para que figura:

    resumen.json          composicion de clases y volumenes      F06, F10
    rafaga_<dia>.npz      conexiones/5s por origen, por clase     F21 (clave)
    entropia_<dia>.npz    histograma de entropia por clase        F22
    timeline_<dia>.npz    actividad del atacante minuto a minuto  F09 (clave)
    tam_<dia>.npz         paquetes y bytes por flujo              F23
    bytes_<dia>.npz       perfil medio de bytes + banners         F26, F27
    perfil_<dia>.npz      flujos de ataque por bloque de 10 min   F34 (clave)
    interarribo_<dia>.npz histograma de intervalos por origen     F37 (clave)

Todo se calcula sobre el servicio atacado y separando el benigno GENUINO
(terceros) del contaminado (el propio atacante fuera de ventana), que es la
distincion metodologica central del trabajo.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from estilo import DIR_CACHE, DIR_DATOS  # noqa: E402
import resultados as R  # noqa: E402

# --------------------------------------------------------------------------- config

# dia -> (carpeta, fecha del dia en UTC para situar las ventanas)
DIAS_DISCO = {
    "14-02": ("wednesday-14-02-2018", "Wednesday-14-02-2018", "2018-02-14"),
    "22-02": ("thursday-22-02-2018", "Thursday-22-02-2018", "2018-02-22"),
    "16-02": ("friday-16-02-2018", "Friday-16-02-2018", "2018-02-16"),
    # Anadidos el 22-ago con los dias 4, 5 y 6. El dia 28-02 (Infiltration) NO
    # esta y no puede estarlo: no se construyo su .npz a proposito (HALLAZGO 16),
    # asi que sus cifras salen del conn.log y este extractor no las cubre.
    "15-02": ("thursday-15-02-2018", "Thursday-15-02-2018", "2018-02-15"),
    "20-02": ("tuesday-20-02-2018", "Tuesday-20-02-2018", "2018-02-20"),
    "02-03": ("friday-02-03-2018", "Friday-02-03-2018", "2018-03-02"),
}

VENTANA_RAFAGA = 5.0     # segundos: la ventana que mejor separa (ver 17-jun)
MAX_MUESTRA = 60_000     # tope de puntos por clase que se guarda en cache


def _ts(fecha: str, hhmmss: str) -> float:
    """'2018-02-14' + '19:31:00' -> epoch UTC."""
    return datetime.fromisoformat(f"{fecha}T{hhmmss}+00:00").timestamp()


def _submuestra(a: np.ndarray, n=MAX_MUESTRA, semilla=0) -> np.ndarray:
    if len(a) <= n:
        return a
    rng = np.random.default_rng(semilla)
    return a[rng.choice(len(a), n, replace=False)]


# --------------------------------------------------------------------------- rafaga

def conexiones_en_ventana(ts: np.ndarray, origen: np.ndarray,
                          W: float = VENTANA_RAFAGA) -> np.ndarray:
    """Por cada flujo, nº de conexiones del MISMO origen en los W s previos.

    Misma definicion causal que `build_burst_features` de
    scripts/zeek/honest_by_service_rich.py (solo mira al pasado, como haria un
    IDS en linea), pero devuelve el CONTEO CRUDO en vez de log1p, porque en la
    figura queremos leer "86 conexiones/5 s" directamente en el eje.

    Version vectorizada por grupo (searchsorted) para que 4 M de flujos tarden
    segundos en vez de minutos.
    """
    n = len(ts)
    out = np.zeros(n, dtype=np.int32)
    orden = np.lexsort((ts, origen))
    oh_s, ts_s = origen[orden], ts[orden]
    # frontera de cada grupo de origen
    cortes = np.flatnonzero(oh_s[1:] != oh_s[:-1]) + 1
    ini = np.concatenate(([0], cortes))
    fin = np.concatenate((cortes, [n]))
    for a, b in zip(ini, fin):
        t = ts_s[a:b]
        # nº de elementos del grupo con ts en [t_i - W, t_i]
        izq = np.searchsorted(t, t - W, side="left")
        out[orden[a:b]] = np.arange(b - a) - izq + 1
    return out


# --------------------------------------------------------------------------- carga

def cargar_meta(dia: str) -> pd.DataFrame:
    carpeta, nombre, _ = DIAS_DISCO[dia]
    ruta = DIR_DATOS / carpeta / f"dataset_{nombre}_meta.csv"
    print(f"  leyendo {ruta.name} ...", flush=True)
    df = pd.read_csv(
        ruta,
        usecols=["ts", "orig_h", "resp_p", "n_pkts", "tot_bytes", "seq_len",
                 "entropy", "label"],
        dtype={"ts": np.float64, "orig_h": "string", "resp_p": np.int32,
               "n_pkts": np.int32, "tot_bytes": np.int64, "seq_len": np.int32,
               "entropy": np.float32, "label": "category"},
    )
    print(f"    {len(df):,} flujos", flush=True)
    return df


def info_dia(dia: str) -> dict:
    """Metadatos del dia desde la fuente de verdad (resultados.py)."""
    _, nombre, fecha = DIAS_DISCO[dia]
    d = R.DIAS[nombre]
    return {"nombre": nombre, "fecha": fecha, "atacante": d["atacante"],
            "puerto": d["puerto"], "ataque": d["ataque"],
            "regimen": d["regimen"], "servicio": d["servicio"]}


# --------------------------------------------------------------------------- extractores

def extraer_dia(dia: str, resumen: dict) -> None:
    inf = info_dia(dia)
    print(f"\n=== {dia}  ({inf['ataque']}, regimen {inf['regimen']}) ===")
    df = cargar_meta(dia)

    atacante = inf["atacante"]
    puerto = inf["puerto"]
    es_ataque = (df["label"] != "Benign").to_numpy()
    del_atacante = (df["orig_h"] == atacante).to_numpy()
    en_servicio = (df["resp_p"] == puerto).to_numpy()

    # --- resumen de composicion -------------------------------------------
    conteo = df["label"].value_counts().to_dict()
    resumen[dia] = {
        **{k: v for k, v in inf.items() if k != "fecha"},
        "flujos_total": int(len(df)),
        "clases": {str(k): int(v) for k, v in conteo.items()},
        "flujos_en_servicio": int(en_servicio.sum()),
        "benigno_en_servicio": int((en_servicio & ~es_ataque).sum()),
        "benigno_en_servicio_del_atacante": int(
            (en_servicio & ~es_ataque & del_atacante).sum()),
        "benigno_en_servicio_genuino": int(
            (en_servicio & ~es_ataque & ~del_atacante).sum()),
        "ips_benignas_genuinas": int(
            df.loc[en_servicio & ~es_ataque & ~del_atacante, "orig_h"].nunique()),
    }

    # --- linea temporal: actividad del atacante vs ventana etiquetada ------
    # Es la figura del error de limite de ventana (se repitio en SSH y DoS).
    clave_v = {"14-02": "SSH-Bruteforce (14-02)", "16-02": "DoS-Hulk (16-02)"}.get(dia)
    if clave_v:
        v = R.VENTANAS[clave_v]
        m = del_atacante & en_servicio
        ts_atk = df.loc[m, "ts"].to_numpy()
        # bins de 10 s alrededor de la actividad
        t0, t1 = ts_atk.min(), ts_atk.max()
        bordes = np.arange(t0 - 60, t1 + 120, 10.0)
        cuenta, _ = np.histogram(ts_atk, bins=bordes)
        # cuantos de esos flujos estaban etiquetados Benign (los mal etiquetados)
        ts_mal = df.loc[m & ~es_ataque, "ts"].to_numpy()
        cuenta_mal, _ = np.histogram(ts_mal, bins=bordes)
        np.savez_compressed(
            DIR_CACHE / f"timeline_{dia}.npz",
            bordes=bordes, cuenta=cuenta, cuenta_mal=cuenta_mal,
            t_ventana_fin_orig=_ts(inf["fecha"], v["ventana_fin_original"]),
            t_ventana_fin_corr=_ts(inf["fecha"], v["ventana_fin_corregida"]),
            t_atacante_ini=_ts(inf["fecha"], v["atacante_inicio"]),
            t_atacante_fin=_ts(inf["fecha"], v["atacante_fin"]),
            flujos_reetiquetados=v["flujos_reetiquetados"],
        )
        print(f"  [ok] timeline_{dia}.npz "
              f"({v['flujos_reetiquetados']:,} flujos re-etiquetados)")

    # --- rafaga: conexiones/5 s por origen ---------------------------------
    # Se calcula sobre TODO el dia (un IDS ve todo el trafico) y luego se
    # segmenta por clase, igual que en honest_by_service_rich.py.
    print("  calculando rafaga (conexiones/5 s por origen) ...", flush=True)
    rafaga = conexiones_en_ventana(df["ts"].to_numpy(),
                                   df["orig_h"].to_numpy().astype(str))
    np.savez_compressed(
        DIR_CACHE / f"rafaga_{dia}.npz",
        ataque=_submuestra(rafaga[es_ataque & en_servicio]),
        benigno_genuino=_submuestra(rafaga[~es_ataque & en_servicio & ~del_atacante]),
        benigno_atacante=_submuestra(rafaga[~es_ataque & en_servicio & del_atacante]),
        mediana_ataque=np.median(rafaga[es_ataque & en_servicio]) if es_ataque.any() else 0,
        mediana_benigno=np.median(rafaga[~es_ataque & en_servicio & ~del_atacante]),
        ventana=VENTANA_RAFAGA,
    )
    print(f"  [ok] rafaga_{dia}.npz  "
          f"(mediana ataque {np.median(rafaga[es_ataque & en_servicio]):.0f} vs "
          f"benigno {np.median(rafaga[~es_ataque & en_servicio & ~del_atacante]):.0f} conn/5s)")

    # --- entropia por clase, dentro del servicio atacado --------------------
    ent = df["entropy"].to_numpy()
    np.savez_compressed(
        DIR_CACHE / f"entropia_{dia}.npz",
        ataque=_submuestra(ent[es_ataque & en_servicio]),
        benigno_genuino=_submuestra(ent[~es_ataque & en_servicio & ~del_atacante]),
        benigno_todo=_submuestra(ent[~es_ataque]),
    )
    print(f"  [ok] entropia_{dia}.npz")

    # --- tamano de flujo ---------------------------------------------------
    np.savez_compressed(
        DIR_CACHE / f"tam_{dia}.npz",
        pkts_ataque=_submuestra(df.loc[es_ataque & en_servicio, "n_pkts"].to_numpy()),
        pkts_benigno=_submuestra(
            df.loc[~es_ataque & en_servicio & ~del_atacante, "n_pkts"].to_numpy()),
        bytes_ataque=_submuestra(df.loc[es_ataque & en_servicio, "tot_bytes"].to_numpy()),
        bytes_benigno=_submuestra(
            df.loc[~es_ataque & en_servicio & ~del_atacante, "tot_bytes"].to_numpy()),
    )
    print(f"  [ok] tam_{dia}.npz")

    del df, rafaga, ent


def extraer_bytes(dia: str, n_ejemplos=400) -> None:
    """Perfil medio de bytes por clase + primeros bytes (banners/peticiones).

    Lee `X_seq` del .npz (uint8, 256 B por flujo). Es la unica extraccion que
    toca el fichero pesado; se limita a los dos dias donde el contenido
    importa (SSH cifrado y Web en claro).
    """
    carpeta, nombre, _ = DIAS_DISCO[dia]
    inf = info_dia(dia)
    ruta = DIR_DATOS / carpeta / f"dataset_{nombre}.npz"
    print(f"\n  leyendo secuencias de {ruta.name} ...", flush=True)
    d = np.load(ruta, allow_pickle=True)

    resp_p = d["resp_p"]
    orig_h = d["orig_h"].astype(str)
    y = d["y"].astype(str)
    en_servicio = resp_p == inf["puerto"]
    es_ataque = y != "Benign"
    del_atacante = orig_h == inf["atacante"]

    idx_atk = np.flatnonzero(en_servicio & es_ataque)
    idx_ben = np.flatnonzero(en_servicio & ~es_ataque & ~del_atacante)
    idx_atk = _submuestra(idx_atk, n_ejemplos, semilla=1)
    idx_ben = _submuestra(idx_ben, n_ejemplos, semilla=2)

    X = d["X_seq"]
    seq_atk = np.asarray(X[np.sort(idx_atk)])
    seq_ben = np.asarray(X[np.sort(idx_ben)])

    # perfil medio de bytes (histograma 256) calculado desde las secuencias,
    # para no cargar X_hist entero (varios GB en los dias grandes)
    def perfil(seq):
        h = np.zeros(256, dtype=np.float64)
        for fila in seq:
            h += np.bincount(fila, minlength=256)
        return h / max(h.sum(), 1)

    np.savez_compressed(
        DIR_CACHE / f"bytes_{dia}.npz",
        seq_ataque=seq_atk, seq_benigno=seq_ben,
        perfil_ataque=perfil(seq_atk), perfil_benigno=perfil(seq_ben),
    )
    print(f"  [ok] bytes_{dia}.npz  ({len(seq_atk)} ataque / {len(seq_ben)} benigno)")
    d.close()


# --------------------------------------------------------------------------- CLI

def extraer_perfil(dia: str) -> None:
    """Perfil temporal del ataque: flujos etiquetados como ataque por bloque
    de 10 minutos (hora local del dia).

    Para el Bot del 02-03 esta serie ES el hallazgo (HALLAZGO 15): una meseta
    plana durante casi 4 h delata el beaconing periodico, algo que ninguna
    metrica agregada del trabajo captura. Se calcula para cualquier dia porque
    el contraste con un flood (que sube y baja) es justamente lo que se quiere
    ensenar.
    """
    inf = info_dia(dia)
    df = cargar_meta(dia)
    tz = R.DIAS[inf["nombre"]].get("tz_offset_hours", -4)

    es_ataque = (df["label"] != "Benign").to_numpy()
    if not es_ataque.any():
        print(f"  [salta] perfil_{dia}: el dia no tiene flujos de ataque")
        return

    ts = df.loc[es_ataque, "ts"].to_numpy(dtype=float)
    # a minutos locales desde medianoche, en bloques de 10 min
    mins = ((ts + tz * 3600) % 86400) / 60.0
    bloques = (mins // 10).astype(int)          # 0..143
    conteo = np.bincount(bloques, minlength=144)

    np.savez_compressed(
        DIR_CACHE / f"perfil_{dia}.npz",
        conteo=conteo,
        minuto_inicio=np.arange(144) * 10,
        etiqueta=np.array(inf["ataque"]),
    )
    activos = conteo[conteo > 0]
    print(f"  [ok] perfil_{dia}.npz  ({len(activos)} bloques con ataque, "
          f"max {conteo.max():,}, mediana de los activos {int(np.median(activos)):,})")


def extraer_interarribo(dia: str) -> None:
    """Histograma del INTERVALO entre conexiones consecutivas de un MISMO origen.

    Es la medida directa del beaconing (HALLAZGO 15) y la que justifica el Eje E:
    ninguna vista del trabajo la calcula, pero separa el Bot del benigno de forma
    trivial (41.8% del ataque en la banda 0.50-0.55 s frente al 1.3% del benigno).

    Se descartan los origenes con menos de 50 flujos: con pocos puntos el
    intervalo no es estimable y solo mete ruido.
    """
    df = cargar_meta(dia)
    BINS = np.arange(0, 3.0 + 0.025, 0.025)

    def hist(sub):
        trozos = []
        for _, g in sub.groupby("orig_h"):
            t = np.sort(g["ts"].to_numpy(dtype=float))
            if len(t) >= 50:
                trozos.append(np.diff(t))
        if not trozos:
            return np.zeros(len(BINS) - 1, dtype=np.int64), 0
        d = np.concatenate(trozos)
        d = d[(d > 0) & (d < 3.0)]
        h, _ = np.histogram(d, bins=BINS)
        return h, len(d)

    es_atk = df["label"] != "Benign"
    h_atk, n_atk = hist(df[es_atk])
    h_ben, n_ben = hist(df[~es_atk])
    if n_atk == 0:
        print(f"  [salta] interarribo_{dia}: sin origenes de ataque con >=50 flujos")
        return

    np.savez_compressed(
        DIR_CACHE / f"interarribo_{dia}.npz",
        bins=BINS, ataque=h_atk, benigno=h_ben,
        n_ataque=n_atk, n_benigno=n_ben,
    )
    pico = BINS[int(np.argmax(h_atk))]
    print(f"  [ok] interarribo_{dia}.npz  (ataque n={n_atk:,}, pico en "
          f"{pico:.3f} s con el {100*h_atk.max()/n_atk:.1f}% de los intervalos)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dia", choices=list(DIAS_DISCO), action="append",
                    help="dia a procesar (por defecto: los tres)")
    ap.add_argument("--sin-bytes", action="store_true",
                    help="omite la extraccion de secuencias (la mas pesada)")
    args = ap.parse_args()

    dias = args.dia or list(DIAS_DISCO)
    ruta_resumen = DIR_CACHE / "resumen.json"
    resumen = json.loads(ruta_resumen.read_text(encoding="utf-8")) \
        if ruta_resumen.exists() else {}

    for dia in dias:
        extraer_dia(dia, resumen)
        ruta_resumen.write_text(json.dumps(resumen, indent=2, ensure_ascii=False),
                                encoding="utf-8")

    for dia in dias:
        extraer_perfil(dia)
        extraer_interarribo(dia)

    if not args.sin_bytes:
        for dia in dias:
            if dia in ("14-02", "22-02"):     # cifrado y en claro
                extraer_bytes(dia)

    print(f"\nCache en {DIR_CACHE}")


if __name__ == "__main__":
    main()

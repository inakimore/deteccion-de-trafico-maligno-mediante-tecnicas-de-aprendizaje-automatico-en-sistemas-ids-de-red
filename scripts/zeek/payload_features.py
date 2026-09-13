#!/usr/bin/env python3
"""Atributos CONCRETOS del payload tomados de la literatura (correccion del tutor).

MOTIVACION (revision del tutor, 11-ago-2026)
--------------------------------------------
"Igual no me ha quedado claro si has extraido atributos concretos del payload tipo
entropia... (y los que haya en la literatura cientifica) para unirlos a las
caracteristicas obtenidas con Zeek."

Estado previo del proyecto: del payload se extraian tres representaciones
(build_dataset.py) — histograma de 256 bytes, entropia de Shannon y los primeros
256 bytes en crudo — y la vista "hibrida" concatenaba el histograma completo con
los escalares de flujo de Zeek. Es decir: la entropia SI estaba, pero como un
escalar suelto dentro de un vector de 257 dimensiones dominado por el histograma,
no como un conjunto de DESCRIPTORES interpretables al nivel de los de Zeek. Ese
desequilibrio explica la "dilucion" observada el 16 de junio (concatenar 257
features casi aleatorias tapaba los 4 escalares utiles).

Este modulo extrae ese conjunto de descriptores compactos e interpretables, todos
derivables de lo que el dataset YA guarda (histograma + entropia + secuencia), sin
volver a procesar los PCAP. Origen de cada familia en la literatura:

  - Distribucion de bytes y momentos (media, desviacion, byte dominante, masa de
    los 4 dominantes, riqueza, distancia L1 al uniforme): PAYL, Wang & Stolfo,
    "Anomalous Payload-based Network Intrusion Detection" (RAID 2004), que modela
    el perfil de frecuencia de bytes por servicio y longitud.
  - Entropia de Shannon normalizada y test chi-cuadrado frente a la uniforme, e
    indice de coincidencia: linea clasica de deteccion de contenido cifrado /
    comprimido / empaquetado (Lyda & Hamrock, "Using Entropy Analysis to Find
    Encrypted and Packed Malware", IEEE S&P 2007; Dorfinger et al., "Entropy-Based
    Traffic Filtering to Support Real-Time Skype Detection", 2011).
  - Ratio de compresion (zlib) como aproximacion practica a la complejidad de
    Kolmogorov, usada para separar cifrado de texto estructurado.
  - Entropia y diversidad de 2-gramas: Anagram, Wang, Parekh & Stolfo (RAID 2006),
    que sustituye el modelo 1-grama de PAYL por n-gramas de orden superior.
  - Composicion lexica (imprimibles, alfanumericos, control, no-ASCII, nulos, run
    imprimible mas largo, tasa de transicion texto/binario): descriptores estandar
    en deteccion de inyecciones y shellcode sobre protocolos en claro.

Las 19 features son ADIMENSIONALES y estan acotadas aproximadamente en [0,1], para
que puedan concatenarse con los escalares de Zeek sin que ninguna vista domine por
escala (ademas del StandardScaler del pipeline).

USO
---
    from payload_features import build_payload_attr_features, FEATURE_NAMES
    X = build_payload_attr_features(d, sel=indices)   # (n, 19) float32

Nota de coste: las features de 2-gramas y compresion recorren la secuencia flujo a
flujo en Python, asi que conviene pasar `sel` (subconjunto ya balanceado/limitado)
en los dias masivos. Las derivadas del histograma son vectorizadas.
"""

from __future__ import annotations

import zlib

import numpy as np

FEATURE_NAMES = [
    # --- Distribucion de bytes (PAYL) ---
    "entropy_norm",         # entropia de Shannon / 8
    "distinct_ratio",       # nº de valores de byte presentes / 256
    "max_freq",             # frecuencia del byte dominante
    "top4_mass",            # masa acumulada de los 4 bytes dominantes
    "mean_byte",            # valor medio de byte / 255
    "std_byte",             # desviacion tipica de byte / 128
    "l1_uniform",           # distancia L1 al histograma uniforme / 2
    # --- Aleatoriedad / cifrado ---
    "chi2_uniform",         # log1p(chi2/N) frente a uniforme, comprimido a [0,1]
    "coincidence_idx",      # indice de coincidencia normalizado (1/256 -> 0)
    "compress_ratio",       # len(zlib(seq)) / len(seq)
    # --- n-gramas (Anagram) ---
    "bigram_entropy_norm",  # entropia de 2-gramas / 16
    "bigram_distinct",      # 2-gramas distintos / (len-1)
    # --- Composicion lexica ---
    "printable_ratio",
    "alnum_ratio",
    "ctrl_ratio",           # control excluyendo \t \n \r
    "high_ratio",           # bytes > 0x7F (no ASCII)
    "null_ratio",           # bytes 0x00
    "longest_print_run",    # run imprimible mas largo / longitud
    "transition_rate",      # cambios imprimible<->no imprimible por posicion
]

# Mascaras de clase de byte (se calculan una vez a nivel de modulo).
_VALS = np.arange(256)
_PRINTABLE = ((_VALS >= 0x20) & (_VALS <= 0x7E)) | np.isin(_VALS, [9, 10, 13])
_ALNUM = (((_VALS >= 0x30) & (_VALS <= 0x39)) | ((_VALS >= 0x41) & (_VALS <= 0x5A))
          | ((_VALS >= 0x61) & (_VALS <= 0x7A)))
_CTRL = (_VALS < 0x20) & ~np.isin(_VALS, [9, 10, 13])
_HIGH = _VALS > 0x7F


def _hist_features(H: np.ndarray, entropy: np.ndarray) -> np.ndarray:
    """Descriptores derivados del histograma normalizado (n,256) y la entropia."""
    n = len(H)
    s = H.sum(axis=1, keepdims=True)
    P = np.divide(H, s, out=np.zeros_like(H, dtype=np.float64), where=s > 0)

    distinct = (P > 0).sum(axis=1) / 256.0
    max_freq = P.max(axis=1)
    top4 = np.sort(P, axis=1)[:, -4:].sum(axis=1)
    mean_b = (P * _VALS).sum(axis=1)
    var_b = (P * (_VALS ** 2)).sum(axis=1) - mean_b ** 2
    std_b = np.sqrt(np.maximum(var_b, 0.0))
    l1 = np.abs(P - 1.0 / 256.0).sum(axis=1) / 2.0

    # chi2 frente a uniforme. Sin N real (el histograma llega normalizado) se usa
    # el estadistico por unidad de muestra: 256 * sum((p - 1/256)^2) / (1/256).
    chi2 = 256.0 * ((P - 1.0 / 256.0) ** 2).sum(axis=1) * 256.0
    chi2 = np.log1p(chi2) / np.log1p(256.0 * 256.0)   # a [0,1] aprox

    ic = (P ** 2).sum(axis=1)
    ic = np.clip((ic - 1.0 / 256.0) / (1.0 - 1.0 / 256.0), 0.0, 1.0)

    out = np.empty((n, 10), dtype=np.float64)
    out[:, 0] = np.clip(entropy / 8.0, 0.0, 1.0)
    out[:, 1] = distinct
    out[:, 2] = max_freq
    out[:, 3] = top4
    out[:, 4] = mean_b / 255.0
    out[:, 5] = np.clip(std_b / 128.0, 0.0, 1.0)
    out[:, 6] = l1
    out[:, 7] = chi2
    out[:, 8] = ic
    # La columna 9 (compress_ratio) se rellena desde la secuencia.
    out[:, 9] = 0.0

    # Composicion lexica: masa de cada clase de byte en el histograma.
    lex = np.empty((n, 5), dtype=np.float64)
    lex[:, 0] = P[:, _PRINTABLE].sum(axis=1)
    lex[:, 1] = P[:, _ALNUM].sum(axis=1)
    lex[:, 2] = P[:, _CTRL].sum(axis=1)
    lex[:, 3] = P[:, _HIGH].sum(axis=1)
    lex[:, 4] = P[:, 0]
    return np.hstack([out, lex])


def _seq_features(S: np.ndarray, seq_len: np.ndarray) -> np.ndarray:
    """Descriptores que necesitan el ORDEN de los bytes (compresion, 2-gramas...).

    Devuelve (n,6): compress_ratio, bigram_entropy_norm, bigram_distinct,
    longest_print_run, transition_rate y un hueco de alineacion.
    """
    n = len(S)
    out = np.zeros((n, 5), dtype=np.float64)
    printable_lut = _PRINTABLE
    for i in range(n):
        L = int(min(seq_len[i], S.shape[1]))
        if L <= 1:
            continue
        row = S[i, :L]
        raw = row.tobytes()

        # Ratio de compresion (aprox. a la complejidad de Kolmogorov).
        out[i, 0] = min(len(zlib.compress(raw, 6)) / L, 2.0) / 2.0

        # 2-gramas (Anagram): entropia y diversidad.
        big = row[:-1].astype(np.int32) * 256 + row[1:].astype(np.int32)
        _, cnt = np.unique(big, return_counts=True)
        p = cnt / cnt.sum()
        out[i, 1] = float(-(p * np.log2(p)).sum()) / 16.0
        out[i, 2] = len(cnt) / (L - 1)

        # Run imprimible mas largo y tasa de transicion texto<->binario.
        pr = printable_lut[row]
        best = cur = 0
        for v in pr:
            cur = cur + 1 if v else 0
            if cur > best:
                best = cur
        out[i, 3] = best / L
        out[i, 4] = float((pr[1:] != pr[:-1]).sum()) / (L - 1)
    return out


def build_payload_attr_features(d, sel=None, chunk: int = 50_000) -> np.ndarray:
    """Matriz (n, 19) de atributos del payload. `sel`: indices de fila opcionales.

    Se procesa por bloques para no materializar X_hist/X_seq completos en los dias
    masivos (el DoS del 16-02 tiene 4 M de flujos).
    """
    n_total = len(d["entropy"])
    idx = np.arange(n_total) if sel is None else np.asarray(sel)
    X_hist, X_seq = d["X_hist"], d["X_seq"]
    entropy = d["entropy"]
    seq_len = d["seq_len"].astype(np.int64)

    out = np.empty((len(idx), len(FEATURE_NAMES)), dtype=np.float32)
    for i in range(0, len(idx), chunk):
        part = idx[i : i + chunk]
        H = _hist_features(X_hist[part].astype(np.float64), entropy[part])
        Sq = _seq_features(X_seq[part], seq_len[part])
        block = np.empty((len(part), len(FEATURE_NAMES)), dtype=np.float64)
        block[:, 0:9] = H[:, 0:9]      # entropia ... indice de coincidencia
        block[:, 9] = Sq[:, 0]         # compress_ratio
        block[:, 10] = Sq[:, 1]        # bigram_entropy_norm
        block[:, 11] = Sq[:, 2]        # bigram_distinct
        block[:, 12:17] = H[:, 10:15]  # printable/alnum/ctrl/high/null
        block[:, 17] = Sq[:, 3]        # longest_print_run
        block[:, 18] = Sq[:, 4]        # transition_rate
        out[i : i + len(part)] = block.astype(np.float32)
    return np.nan_to_num(out, nan=0.0, posinf=0.0, neginf=0.0)


def describe(X: np.ndarray, y: np.ndarray, positive: str) -> list[str]:
    """Tabla comparativa de las medias de cada atributo por clase (para informes)."""
    pos = y == positive
    lines = ["| Atributo | Ataque (media) | Benigno (media) | Δ |",
             "|----------|----------------|-----------------|---|"]
    for j, name in enumerate(FEATURE_NAMES):
        a = float(X[pos, j].mean()) if pos.any() else float("nan")
        b = float(X[~pos, j].mean()) if (~pos).any() else float("nan")
        lines.append(f"| `{name}` | {a:.4f} | {b:.4f} | {a - b:+.4f} |")
    return lines

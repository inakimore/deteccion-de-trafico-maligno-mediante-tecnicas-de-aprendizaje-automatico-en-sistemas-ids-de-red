#!/usr/bin/env python
"""Bloque 0 - Diagramas conceptuales (esquemas, sin datos medidos).

Estas figuras explican el METODO, no los resultados: son las que hacen que
el lector entienda el resto del trabajo sin tener que reconstruirlo.

F01 pipeline            De la captura PCAP al resultado
F02 mapa_regimenes      Los tres regimenes y donde vive la firma
F03 arquitectura        El hibrido de dos ramas con fusion tardia
F04 anatomia_flujo      De una conexión TCP a los vectores del modelo
F05 cronologia          Fases del proyecto y sus hitos
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib.patches as mp
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AQUA, AZUL, CRITICO, NARANJA, REJILLA, TINTA,  # noqa: E402
                    TINTA_2, VIOLETA, ANCHO_COMPLETO, envolver, guardar,
                    nota, nueva, titulo)


def caja(ax, x, y, an, al, texto, *, color=AZUL, relleno=None, fs=7.5,
         negrita=False, tinta="#ffffff", radio=0.012) -> None:
    """Caja redondeada con texto centrado, en coordenadas de ejes."""
    ax.add_patch(mp.FancyBboxPatch(
        (x, y), an, al, boxstyle=mp.BoxStyle("Round", pad=0, rounding_size=radio),
        linewidth=0 if relleno is None else 1.2,
        facecolor=color if relleno is None else relleno,
        edgecolor=color, transform=ax.transAxes, zorder=2))
    ax.text(x + an / 2, y + al / 2, texto, transform=ax.transAxes,
            ha="center", va="center", fontsize=fs, color=tinta,
            fontweight="bold" if negrita else "normal", linespacing=1.35,
            zorder=3)


def flecha(ax, x1, y1, x2, y2, color=APAGADO, lw=1.3) -> None:
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), xycoords=ax.transAxes,
                textcoords=ax.transAxes, zorder=1,
                arrowprops=dict(arrowstyle="-|>", color=color, lw=lw,
                                shrinkA=0, shrinkB=0))


def _lienzo(alto=2.4):
    fig, ax = nueva(ANCHO_COMPLETO, alto)
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    return fig, ax


# --------------------------------------------------------------------- F01
def f01_pipeline() -> None:
    """El camino completo del dato. Incluye los dos pasos que costaron un
    hallazgo cada uno: el saneado previo del PCAP (sin el, Zeek perdia la
    tarde entera en silencio) y el etiquetado por ground-truth verificada
    (el CSV no trae IPs, asi que no hay join posible por 5-tupla).
    """
    fig, ax = _lienzo(2.7)

    # El nombre del script va en el pie, no dentro de la caja: dentro no cabe
    # sin reducir la fuente por debajo de lo legible en papel.
    pasos = [
        (0.000, "PCAP crudo", AZUL, "~150 GB de capturas\ndel día"),
        (0.205, "Saneado", CRITICO, "repair_pcap.py\nobligatorio: si no,\nZeek se corta"),
        (0.410, "Zeek", AZUL, "extract_payload.zeek\n1 fila por paquete\ncon datos"),
        (0.615, "Vectorizacion", AZUL, "build_dataset.py\nagrega por uid =\nconexión TCP"),
        (0.820, "Dataset", AQUA, "npz + meta.csv\nautocontenido, 5.4 GB"),
    ]
    an, al, y = 0.175, 0.15, 0.52
    for i, (x, txt, color, pie) in enumerate(pasos):
        caja(ax, x, y, an, al, txt, color=color, fs=7.5, negrita=True)
        ax.text(x + an / 2, y - 0.045, pie, transform=ax.transAxes, ha="center",
                va="top", fontsize=6.3, color=TINTA_2, linespacing=1.45)
        if i:
            flecha(ax, x - 0.027, y + al / 2, x - 0.004, y + al / 2)

    # La ground-truth entra POR ARRIBA: abajo chocaria con los pies de paso.
    caja(ax, 0.615, 0.80, 0.175, 0.13, "Ground-truth\nverificada",
         color=NARANJA, fs=7.0, negrita=True)
    flecha(ax, 0.7025, 0.79, 0.7025, 0.685, color=NARANJA)
    ax.text(0.805, 0.865, "IP + puerto + ventana:\nel CSV no trae IPs,\nno hay join por 5-tupla",
            transform=ax.transAxes, ha="left", va="center", fontsize=6.3,
            color=NARANJA, linespacing=1.45)

    # La salida cuelga directamente del dataset, sin rodeos que crucen texto.
    caja(ax, 0.545, 0.03, 0.45, 0.13,
         "Evaluacion por servicio  ->  models/*.md", color=AQUA, fs=7.0,
         negrita=True)
    flecha(ax, 0.9075, 0.26, 0.9075, 0.17, color=AQUA)

    titulo(ax, "De la captura de red al resultado",
           "Cada día del dataset recorre esta cadena una sola vez. Los PCAP y los TSV intermedios se "
           "borran despues (son re-derivables); lo que se conserva es el .npz vectorizado, que basta "
           "para re-etiquetar y re-evaluar sin volver a descargar nada.")
    nota(fig, "Scripts en scripts/zeek/. El saneado previo y el etiquetado por ground-truth verificada no son "
              "detalles de implementacion: cada uno corrige un error que habia invalidado resultados "
              "(Hallazgos 2 y 3).")
    guardar(fig, "F01_pipeline")


# --------------------------------------------------------------------- F02
def f02_mapa_regimenes() -> None:
    """El mapa conceptual de la tesis: tres regimenes, tres sitios distintos
    donde vive la firma del ataque, y una conclusion que solo se sostiene si
    se miran los tres a la vez.
    """
    fig, ax = _lienzo(3.3)

    cols = [
        ("CIFRADO", "SSH-Bruteforce\n(14-02)", "El contenido no dice nada:\nbytes casi aleatorios",
         "Conducta\n(ráfaga de conexiones)", AZUL),
        ("EN CLARO", "Web BF / XSS / SQLi\n(22-02)", "El ataque esta escrito\nen los bytes",
         "Payload\n(byte-CNN)", NARANJA),
        ("VOLUMÉTRICO", "DoS-Hulk\n(16-02)", "Cada petición es normal;\nlo anormal es el volumen",
         "Conducta\n(volumen agregado)", VIOLETA),
    ]
    an = 0.305
    for i, (reg, dia, donde, gana, color) in enumerate(cols):
        x = i * 0.3475
        caja(ax, x, 0.80, an, 0.16, f"{reg}\n{dia}", color=color, fs=7.2,
             negrita=True)
        caja(ax, x, 0.47, an, 0.26, donde, color=color, relleno="#fcfcfb",
             tinta=TINTA, fs=7.0)
        ax.text(x + an / 2, 0.415, "la firma vive en", transform=ax.transAxes,
                ha="center", va="center", fontsize=6.5, color=APAGADO,
                style="italic")
        caja(ax, x, 0.20, an, 0.17, gana, color=color, fs=7.2, negrita=True)
        flecha(ax, x + an / 2, 0.79, x + an / 2, 0.74, color=color)
        flecha(ax, x + an / 2, 0.46, x + an / 2, 0.38, color=color)

    ax.add_patch(mp.FancyBboxPatch(
        (0.0, 0.02), 1.0, 0.13,
        boxstyle=mp.BoxStyle("Round", pad=0, rounding_size=0.012),
        facecolor="#f2f6fd", edgecolor=AZUL, linewidth=1.2,
        transform=ax.transAxes, zorder=2))
    ax.text(0.5, 0.085, "Ninguna vista gana en los tres  ->  la detección robusta exige combinar "
                        "payload y conducta",
            transform=ax.transAxes, ha="center", va="center", fontsize=8,
            color=TINTA, fontweight="bold", zorder=3)

    titulo(ax, "Los tres regimenes de firma",
           "El trabajo se estructura sobre tres ataques deliberadamente opuestos. Cada uno esconde su "
           "firma en un sitio distinto, y ese es el argumento: una sola vista de los datos es "
           "suficiente para uno de ellos y ciega para otro.")
    nota(fig, "Los tres días proceden del mismo dataset (CSE-CIC-IDS2018) y se evaluan con identico protocolo, "
              "de modo que las diferencias entre ellos son atribuibles al ataque y no al montaje experimental.")
    guardar(fig, "F02_mapa_regimenes")


# --------------------------------------------------------------------- F03
def f03_arquitectura() -> None:
    """El hibrido de dos ramas. La clave del diseno es DONDE se fusiona: cada
    vista se convierte primero en su propio embedding y la fusion ocurre
    despues, ya sobre representaciones comparables.
    """
    fig, ax = _lienzo(3.0)

    # rama de payload
    caja(ax, 0.02, 0.72, 0.20, 0.17, "Secuencia\n256 bytes", color=AZUL, fs=7.2,
         negrita=True)
    caja(ax, 0.26, 0.72, 0.24, 0.17, "byte-CNN\nkernels 3 / 5 / 7", color=AZUL,
         fs=7.2, negrita=True)
    caja(ax, 0.54, 0.72, 0.16, 0.17, "embedding", color=AZUL, relleno="#eaf2fd",
         tinta=AZUL, fs=7.0)
    flecha(ax, 0.225, 0.805, 0.255, 0.805, color=AZUL)
    flecha(ax, 0.505, 0.805, 0.535, 0.805, color=AZUL)

    # rama de metadatos
    caja(ax, 0.02, 0.30, 0.20, 0.17, "Metadatos\nZeek + ráfaga", color=NARANJA,
         fs=7.2, negrita=True)
    caja(ax, 0.26, 0.30, 0.24, 0.17, "MLP\n256 -> 128", color=NARANJA, fs=7.2,
         negrita=True)
    caja(ax, 0.54, 0.30, 0.16, 0.17, "embedding", color=NARANJA,
         relleno="#fdeee8", tinta=NARANJA, fs=7.0)
    flecha(ax, 0.225, 0.385, 0.255, 0.385, color=NARANJA)
    flecha(ax, 0.505, 0.385, 0.535, 0.385, color=NARANJA)

    # fusion tardia
    caja(ax, 0.75, 0.50, 0.11, 0.20, "fusión\ntardía", color=AQUA, fs=7.2,
         negrita=True)
    flecha(ax, 0.705, 0.805, 0.745, 0.66, color=AZUL)
    flecha(ax, 0.705, 0.385, 0.745, 0.54, color=NARANJA)
    caja(ax, 0.89, 0.50, 0.10, 0.20, "clase", color=TINTA_2, fs=7.2, negrita=True)
    flecha(ax, 0.865, 0.60, 0.885, 0.60, color=AQUA)

    ax.text(0.5, 0.13, "La fusión INGENUA concatenaría aquí las 257 dimensiones crudas del payload "
                       "con los 7 escalares de Zeek:\nlos escalares útiles quedarían diluidos. Entrenar "
                       "una rama por vista y fusionar los embeddings lo evita.",
            transform=ax.transAxes, ha="center", va="center", fontsize=7,
            color=TINTA_2, linespacing=1.5)

    titulo(ax, "El hibrido de dos ramas con fusion tardia",
           "Cada vista se procesa con la arquitectura que le corresponde —convolucion para la secuencia "
           "de bytes, perceptron para los escalares de flujo— y solo se combinan al final, cuando ambas "
           "son ya representaciones de dimension comparable.")
    nota(fig, "Implementado en PyTorch (CPU): scripts/zeek/dl_models.py y train_dl_hybrid.py. "
              "Resultados en F23 y en models/phase2_dlhybrid_*.md.")
    guardar(fig, "F03_arquitectura")


# --------------------------------------------------------------------- F04
def f04_anatomia_flujo() -> None:
    """Que es exactamente un ejemplo del dataset. Lo confirmo el tutor en la
    revision del 11 de agosto: cada ejemplo es una conexión TCP completa, no
    un paquete suelto.
    """
    fig, ax = _lienzo(2.9)

    caja(ax, 0.02, 0.66, 0.26, 0.22,
         "Conexión TCP\n(uid de Zeek)\nN paquetes con datos",
         color=AZUL, fs=7.2, negrita=True)
    ax.text(0.15, 0.60, "se agregan todos los paquetes del flujo",
            transform=ax.transAxes, ha="center", va="top", fontsize=6.4,
            color=TINTA_2, style="italic")

    vistas = [
        (0.36, "X_hist (256)", "histograma de bytes\nde todo el flujo", AZUL),
        (0.52, "entropy (1)", "entropía de\nShannon", AZUL),
        (0.68, "X_seq (256)", "primeros 256 B\n(la secuencia)", AZUL),
        (0.84, "escalares (4)", "n_pkts, tot_bytes,\nbytes/pkt, seq_len", NARANJA),
    ]
    for x, nombre, desc, color in vistas:
        caja(ax, x, 0.66, 0.145, 0.22, nombre, color=color, fs=6.8, negrita=True)
        ax.text(x + 0.0725, 0.60, desc, transform=ax.transAxes, ha="center",
                va="top", fontsize=6.2, color=TINTA_2, linespacing=1.4)
        flecha(ax, 0.29, 0.77, x - 0.005, 0.77, color=REJILLA, lw=0.9)

    caja(ax, 0.36, 0.30, 0.30, 0.15, "+ ráfaga (3): conexiones\ndel mismo origen en 1/5/30 s",
         color=NARANJA, relleno="#fdeee8", tinta=NARANJA, fs=6.8)
    ax.text(0.68, 0.375, "derivada del meta.csv, sin reprocesar los TSV",
            transform=ax.transAxes, ha="left", va="center", fontsize=6.3,
            color=TINTA_2, style="italic")

    caja(ax, 0.02, 0.30, 0.26, 0.15, "+ etiqueta", color=AQUA, fs=7.0,
         negrita=True)

    ax.text(0.5, 0.16, "Cada fila del dataset = una conexión. El histograma acumula hasta 64 KB del flujo "
                       "completo;\nla secuencia guarda los primeros 256 bytes, que es donde vive la cabecera "
                       "del protocolo.",
            transform=ax.transAxes, ha="center", va="center", fontsize=7,
            color=TINTA_2, linespacing=1.5)

    titulo(ax, "Anatomia de un ejemplo del dataset",
           "La unidad de analisis es la conexión TCP identificada por el uid de Zeek, no el paquete "
           "individual. De cada conexión se derivan cuatro representaciones distintas del mismo "
           "tráfico, y son esas vistas las que se comparan a lo largo del trabajo.")
    nota(fig, "Construido por scripts/zeek/build_dataset.py (clase FlowAcc). Confirmado como correcto en la "
              "revision del tutor del 11 de agosto.")
    guardar(fig, "F04_anatomia_flujo")


# --------------------------------------------------------------------- F05
def f05_cronologia() -> None:
    """Cronologia del trabajo. Util en la presentacion y en el capitulo de
    metodologia: ensena que el proyecto avanzo por correcciones sucesivas.
    """
    fig, ax = _lienzo(2.7)

    fases = [
        (0.00, 0.20, "FASE 1\nmar - abr", "Baseline con metadatos\nde flujo (CSV)", AZUL),
        (0.22, 0.36, "FASE 2\nabr - jul", "Payload en crudo:\nPCAP -> Zeek -> bytes", NARANJA),
        (0.60, 0.40, "FASE 3\njul - ago", "Deep learning, hibrido,\nrobustez y evasión", AQUA),
    ]
    for x, an, nombre, desc, color in fases:
        caja(ax, x, 0.60, an - 0.015, 0.20, nombre, color=color, fs=7.2,
             negrita=True)
        ax.text(x + (an - 0.015) / 2, 0.55, desc, transform=ax.transAxes,
                ha="center", va="top", fontsize=6.6, color=TINTA_2,
                linespacing=1.4)

    hitos = [
        (0.10, "Cae el mito\ndel 99.99 %"),
        (0.31, "El espejismo\ndel 99.96 %"),
        (0.46, "Benigno\ncontaminado"),
        (0.66, "byte-CNN\ne hibrido"),
        (0.80, "Evasión y\nzero-day"),
        (0.93, "Servicio y\natributos"),
    ]
    ax.plot([0.0, 1.0], [0.34, 0.34], color=REJILLA, lw=2,
            transform=ax.transAxes)
    for x, txt in hitos:
        ax.plot([x], [0.34], "o", color=CRITICO, markersize=6,
                transform=ax.transAxes, zorder=3)
        ax.text(x, 0.27, txt, transform=ax.transAxes, ha="center", va="top",
                fontsize=6.3, color=TINTA, linespacing=1.4)

    ax.text(0.5, 0.06, "Cada hito es una correccion de un resultado propio, no un resultado nuevo.",
            transform=ax.transAxes, ha="center", va="center", fontsize=7,
            color=TINTA_2, style="italic")

    titulo(ax, "Cronologia: el proyecto avanza corrigiendose",
           "Los seis hitos marcados son los momentos en que una medida que parecia buena resulto ser "
           "un artefacto y hubo que rehacer el analisis. Es la linea argumental de la memoria.")
    nota(fig, "Diario completo y fechado en README.md; resumen ejecutivo en SUMMARY.md.")
    guardar(fig, "F05_cronologia")


def generar_todo() -> None:
    print("Bloque 0 - Diagramas conceptuales")
    f01_pipeline()
    f02_mapa_regimenes()
    f03_arquitectura()
    f04_anatomia_flujo()
    f05_cronologia()


if __name__ == "__main__":
    generar_todo()

#!/usr/bin/env python
"""Bloque 7 - Atributos del payload (revision del tutor, 11 de agosto).

F30 atributos_vistas       19 descriptores valen lo que 257 dimensiones
F31 atributos_separacion   Que descriptor separa en cada regimen
F32 importancia_permutacion  La union payload+Zeek usa DE VERDAD las dos familias
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AQUA, AZUL, NARANJA, TINTA, TINTA_2,  # noqa: E402
                    ANCHO_COMPLETO, envolver, etiquetar_barras_h,
                    etiquetar_barras_v, guardar, leyenda_abajo, limpiar_ejes,
                    nota, nueva, titulo, titulo_figura)


# --------------------------------------------------------------------- F30
def f30_atributos_vistas() -> None:
    """Hallazgo 13: un vector compacto de descriptores con significado iguala
    al histograma crudo con 13 veces menos dimensiones, y ademas se fusiona
    bien con los metadatos de Zeek en vez de diluirse.
    """
    regimenes = ["Cifrado (14-02)", "En claro (22-02)"]   # el DoS satura a 1.0
    vistas = R.ATRIBUTOS_VISTAS
    colores = [AZUL, "#86b6ef", NARANJA, AQUA, APAGADO]

    x = np.arange(len(regimenes))
    an = 0.16
    fig, ax = nueva(ANCHO_COMPLETO, 3.1)
    for i, (v, c) in enumerate(zip(vistas, colores)):
        vals = [R.ATRIBUTOS_PAYLOAD[r][i] for r in regimenes]
        b = ax.bar(x + (i - 2) * an, vals, an * 0.9, color=c, label=v)
        etiquetar_barras_v(ax, b, vals, fmt="{:.3f}", dy=0.002)

    ax.set_xticks(x, regimenes)
    ax.set_ylim(0.94, 1.008)
    ax.set_ylabel("accuracy (5-Fold CV)")
    limpiar_ejes(ax)
    leyenda_abajo(ax, ncols=3, dy=-0.16)

    titulo(ax, "19 descriptores interpretables valen lo que 257 dimensiones",
           "El vector compacto de atributos del payload (entropía, momentos, 2-gramas, composicion "
           "lexica) iguala al histograma crudo con 13 veces menos dimensiones. Y al unirlo con Zeek, "
           "'zeek+attrs' iguala o supera a 'zeek+hist': la dilucion era un problema de representacion, "
           "no de la fusion.")
    nota(fig, "Mismo subconjunto en las cinco vistas: seleccion por servicio (DPI), balanceo 1:1, benigno "
              "limpio de la IP atacante, MLP 256->128, 5-Fold CV + test held-out. El día DoS se omite porque "
              "las cinco vistas saturan a 1.000 y no discriminan. Fuente: models/phase3_payload_attrs_*.md.")
    guardar(fig, "F30_atributos_vistas")


# --------------------------------------------------------------------- F31
def f31_atributos_separacion() -> None:
    """Que descriptor separa, y en que direccion, en cada regimen.

    Forma: dumbbell por atributo (media del ataque frente a media del
    benigno). Se ordenan por la magnitud de la diferencia, asi que arriba
    queda lo que de verdad discrimina.
    """
    regimenes = list(R.ATRIBUTOS_MEDIAS)
    fig, axes = nueva(ANCHO_COMPLETO, 4.6, ncols=len(regimenes), sharex=True)
    axes = np.atleast_1d(axes)

    for ax, reg in zip(axes, regimenes):
        datos = R.ATRIBUTOS_MEDIAS[reg]
        # ordenados por separacion absoluta: lo que discrimina, arriba
        orden = sorted(datos, key=lambda k: abs(datos[k][0] - datos[k][1]),
                       reverse=True)
        for i, attr in enumerate(orden):
            atk, ben = datos[attr]
            ax.plot([ben, atk], [i, i], color=APAGADO, lw=1.4, zorder=1,
                    solid_capstyle="round")
            ax.scatter([ben], [i], s=34, color=AZUL, zorder=3,
                       edgecolors="#fcfcfb", linewidths=1.0,
                       label="Benigno" if i == 0 else None)
            ax.scatter([atk], [i], s=34, color=NARANJA, zorder=3,
                       edgecolors="#fcfcfb", linewidths=1.0,
                       label="Ataque" if i == 0 else None)
        ax.set_yticks(range(len(orden)), orden, fontsize=6.8,
                      family="monospace")
        ax.invert_yaxis()
        ax.set_xlim(-0.05, 1.05)
        ax.set_xticks([0, 0.5, 1.0], ["0", "0.5", "1"])
        limpiar_ejes(ax, rejilla="x")
        ax.set_title(envolver(reg, 24), loc="left", fontsize=8.5, color=TINTA)

    axes[0].legend(loc="lower right", fontsize=7.5)
    axes[0].set_xlabel("valor medio del descriptor (normalizado)")

    titulo_figura(
        fig, "Que mira cada regimen: los descriptores que separan no son los mismos",
        "Media de cada descriptor por clase, ordenados por separacion. En el SSH cifrado manda la "
        "aleatoriedad (l1_uniform, entropía, riqueza de bytes); en el web en claro manda la "
        "composicion lexica del texto (distinct_ratio, l1_uniform, high_ratio).",
        top=0.86, ancho_sub=118)
    nota(fig, "Descriptores normalizados a [0.1], calculados por scripts/zeek/payload_features.py sobre el "
              "payload agregado de cada conexión. Origen bibliografico de cada familia (PAYL, Anagram, "
              "Lyda & Hamrock) documentado en el modulo. Fuente: models/phase3_payload_attrs_*.md.", y=-0.02)
    guardar(fig, "F31_atributos_separacion", apretar=False)


# --------------------------------------------------------------------- F32
def f32_importancia_permutacion() -> None:
    """La prueba de que la union payload + Zeek no es decorativa: al permutar
    cada atributo, los que más dano hacen vienen de AMBAS familias
    alternadas. El modelo usa las dos vistas, no una con la otra de adorno.
    """
    datos = R.IMPORTANCIA_PERMUTACION_WEB
    nombres = [d[0] for d in datos]
    vals = [d[1] for d in datos]
    errs = [d[2] for d in datos]
    familias = [d[3] for d in datos]
    colores = [NARANJA if f == "zeek" else AZUL for f in familias]

    fig, ax = nueva(ANCHO_COMPLETO, 3.4)
    y = np.arange(len(nombres))
    b = ax.barh(y, vals, xerr=errs, color=colores, height=0.62,
                error_kw=dict(ecolor=APAGADO, lw=1, capsize=2))
    ax.set_yticks(y, nombres, fontsize=7.5, family="monospace")
    ax.invert_yaxis()
    ax.set_xlim(0, max(vals) * 1.28)
    ax.set_xlabel("caida de accuracy al permutar el atributo")
    limpiar_ejes(ax, rejilla="x")

    for i, (v, e) in enumerate(zip(vals, errs)):
        ax.text(v + e + 0.002, i, f"{v:+.4f}", va="center", fontsize=7,
                color=TINTA_2)

    # leyenda por familia (identidad, no ranking)
    ax.barh([], [], color=NARANJA, label="caracteristicas de Zeek (flujo y ráfaga)")
    ax.barh([], [], color=AZUL, label="atributos del payload (literatura)")
    leyenda_abajo(ax, ncols=2, dy=-0.13)

    titulo(ax, "La union payload + Zeek usa de verdad las dos familias",
           "Importancia por permutacion sobre la vista 'zeek+attrs' en el día web. Las dos familias "
           "se alternan en la cabeza del ranking: ni el payload es un adorno sobre los metadatos ni "
           "al reves. Es la respuesta medida a la petición del tutor de unir ambos conjuntos.")
    nota(fig, "Caida media de accuracy en el test held-out sobre 5 repeticiones (barras de error = desviacion). "
              "Vista zeek+attrs = 7 caracteristicas de Zeek + 19 descriptores del payload. "
              "Fuente: models/phase3_payload_attrs_Thursday-22-02-2018_http.md.")
    guardar(fig, "F32_importancia_permutacion")


def generar_todo() -> None:
    print("Bloque 7 - Atributos del payload")
    f30_atributos_vistas()
    f31_atributos_separacion()
    f32_importancia_permutacion()


if __name__ == "__main__":
    generar_todo()

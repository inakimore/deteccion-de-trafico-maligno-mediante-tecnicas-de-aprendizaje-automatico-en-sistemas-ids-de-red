#!/usr/bin/env python
"""Estilo compartido para todas las figuras de la memoria.

Define la paleta, los parametros de matplotlib y los helpers de guardado.
Todas las figuras del TFG se generan a traves de este modulo para que el
resultado sea visualmente homogeneo en la memoria y en la presentacion.

PALETA
------
Se usa una paleta categorica validada para daltonismo (deuteranopia,
protanopia, tritanopia) y para contraste sobre fondo claro. Los tres
primeros slots (azul / naranja / aqua) superan los umbrales en TODOS los
pares, no solo en los adyacentes, por lo que valen tambien para dispersion
y small multiples:

    worst all-pairs CVD deltaE 9.2 (>= 8)   worst normal-vision 24.0 (>= 15)

El aqua queda por debajo de 3:1 de contraste sobre el fondo, asi que las
series en aqua SIEMPRE llevan etiqueta directa (regla de relieve). Los
helpers `etiquetar_barras*` de este modulo lo garantizan.

ROLES SEMANTICOS FIJOS (no cambiar entre figuras: el color identifica a la
entidad, no a su posicion en el ranking)
----------------------------------------
    payload / bytes ............ AZUL
    metadatos / conducta ....... NARANJA
    hibrido (ambas vistas) ..... AQUA
    Benigno .................... AZUL
    Ataque ..................... NARANJA
    contexto / descartado ...... GRIS

SALIDA
------
Cada figura se guarda dos veces:
    figuras/pdf/<nombre>.pdf   vectorial, para \\includegraphics en LaTeX
    figuras/png/<nombre>.png   200 dpi, para la presentacion y la revision
"""

from __future__ import annotations

from pathlib import Path

import os
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --------------------------------------------------------------------------- rutas

RAIZ = Path(__file__).resolve().parents[2]
DIR_FIG = RAIZ / "figuras"
DIR_PDF = DIR_FIG / "pdf"
DIR_PNG = DIR_FIG / "png"
DIR_MEMORIA = DIR_PDF.parent / "memoria"
DIR_TAB = DIR_FIG / "tablas"
DIR_CACHE = DIR_FIG / "cache"
DIR_DATOS = RAIZ / "data" / "processed" / "zeek"

for _d in (DIR_PDF, DIR_PNG, DIR_TAB, DIR_CACHE):
    _d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- paleta

AZUL = "#2a78d6"      # slot 1  - payload / bytes / Benigno
NARANJA = "#eb6834"   # slot 2  - metadatos / conducta / Ataque
AQUA = "#1baf7a"      # slot 3  - hibrido / union de vistas
AMARILLO = "#eda100"  # slot 4  - solo cuando hacen falta 4 categorias
VIOLETA = "#4a3aa7"   # slot 7  - series adicionales en tablas de servicios
MAGENTA = "#e87ba4"   # slot 5

TINTA = "#0b0b0b"        # texto principal
TINTA_2 = "#52514e"      # texto secundario
APAGADO = "#898781"      # ejes, etiquetas, series de contexto
REJILLA = "#e1e0d9"      # lineas de rejilla
LINEA_BASE = "#c3c2b7"   # eje / linea base
SUPERFICIE = "#fcfcfb"   # fondo del grafico

# Estados (reservados: nunca se usan como "una serie mas")
BUENO = "#0ca30c"
CRITICO = "#d03b3b"
AVISO = "#fab219"

# Ramp secuencial azul (magnitud continua: heatmaps)
RAMPA_AZUL = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec",
              "#5598e7", "#3987e5", "#2a78d6", "#256abf", "#1c5cab",
              "#184f95", "#104281", "#0d366b"]

# Roles con nombre, para que las figuras no citen hex sueltos
COLOR_VISTA = {
    "payload": AZUL,
    "payload-hist": AZUL,
    "payload-attrs": AZUL,
    "payload-seq": AZUL,
    "byte-CNN": AZUL,
    "metadatos": NARANJA,
    "meta-basica": NARANJA,
    "conducta": NARANJA,
    "meta+rafaga": NARANJA,
    "meta-rica": NARANJA,
    "hibrido": AQUA,
    "zeek+attrs": AQUA,
}
COLOR_CLASE = {"Benigno": AZUL, "Benign": AZUL, "Ataque": NARANJA, "Attack": NARANJA}

# --------------------------------------------------------------------------- rcParams

ANCHO_COMPLETO = 6.0   # pulgadas: ancho de caja de una memoria A4 estandar
ANCHO_MEDIO = 3.05     # dos figuras por fila


def aplicar_estilo() -> None:
    """Fija los rcParams comunes. Idempotente."""
    plt.rcParams.update({
        "figure.facecolor": SUPERFICIE,
        "axes.facecolor": SUPERFICIE,
        "savefig.facecolor": SUPERFICIE,
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Segoe UI", "Arial"],
        "font.size": 9,
        "axes.titlesize": 10,
        "axes.titleweight": "bold",
        "axes.titlecolor": TINTA,
        "axes.titlepad": 9,
        "axes.labelsize": 9,
        "axes.labelcolor": TINTA_2,
        "axes.edgecolor": LINEA_BASE,
        "axes.linewidth": 0.8,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": REJILLA,
        "grid.linewidth": 0.7,
        "xtick.color": APAGADO,
        "ytick.color": APAGADO,
        "xtick.labelcolor": TINTA_2,
        "ytick.labelcolor": TINTA_2,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "xtick.major.size": 0,
        "ytick.major.size": 0,
        "legend.frameon": False,
        "legend.fontsize": 8,
        "legend.labelcolor": TINTA_2,
        "lines.linewidth": 2.0,
        "lines.markersize": 5,
        "patch.linewidth": 0,
        "figure.dpi": 110,
        "pdf.fonttype": 42,   # fuentes incrustadas como TrueType (LaTeX-friendly)
        "ps.fonttype": 42,
    })


def limpiar_ejes(ax, *, x=True, y=False, rejilla="y") -> None:
    """Quita el marco y deja solo la rejilla del eje indicado.

    rejilla: "y" | "x" | "ambos" | "ninguna"
    """
    for lado in ("top", "right", "left", "bottom"):
        ax.spines[lado].set_visible(False)
    if x:
        ax.spines["bottom"].set_visible(True)
        ax.spines["bottom"].set_color(LINEA_BASE)
    if y:
        ax.spines["left"].set_visible(True)
        ax.spines["left"].set_color(LINEA_BASE)
    ax.grid(False)
    if rejilla in ("y", "ambos"):
        ax.grid(True, axis="y")
    if rejilla in ("x", "ambos"):
        ax.grid(True, axis="x")


def miles(n) -> str:
    """Separador de miles en espanol: 1.803.160, no 1,803,160."""
    return f"{n:,.0f}".replace(",", ".")


def num(valor, fmt="{:.3f}") -> str:
    """Formatea un numero con PUNTO decimal, como el resto de la memoria.

    La memoria usa punto decimal por decision del autor (31-ago): la coma
    decimal chocaba con la de la frase, "0,97, de modo que...". Las figuras
    siguen la misma convencion para que no convivan las dos.
    """
    return fmt.format(valor)


def envolver(texto: str, ancho: int) -> str:
    """Parte un texto en lineas de `ancho` caracteres.

    Imprescindible: al guardar con bbox_inches='tight' una linea de texto
    larga ENSANCHA el lienzo y deja el grafico comprimido en una esquina.
    Todo texto libre de las figuras pasa por aquí.
    """
    import textwrap
    return "\n".join(textwrap.wrap(texto, ancho)) if texto else texto


# ---------------------------------------------------------------------------
# MODO MEMORIA
# ---------------------------------------------------------------------------
# Con FIGURAS_MEMORIA=1 los helpers de titulo, subtitulo y nota no dibujan nada.
# La figura sale solo con datos y ejes, y la explicacion va en el \caption del
# .tex, que es donde la espera el lector de una memoria y lo que recoge el
# indice de figuras. Sin la variable, las figuras salen como siempre: con su
# titulo y su nota horneados, que es lo que necesitan para leerse sueltas en el
# README o en una presentacion.
MODO_MEMORIA = os.environ.get("FIGURAS_MEMORIA", "") == "1"


def titulo(ax, texto: str, subtitulo: str | None = None, ancho_sub: int = 96) -> None:
    """Titulo en negrita + subtitulo explicativo en tinta secundaria.

    El subtitulo es donde va la LECTURA de la figura (que hay que ver), no la
    descripcion de los ejes.
    """
    if MODO_MEMORIA:
        return
    sub = envolver(subtitulo, ancho_sub) if subtitulo else None
    n_lineas = sub.count("\n") + 1 if sub else 0
    ax.set_title(texto, loc="left", pad=10 + 11 * n_lineas)
    if sub:
        ax.text(0.0, 1.0, sub, transform=ax.transAxes,
                fontsize=8, color=TINTA_2, va="bottom", ha="left",
                linespacing=1.35)


def titulo_figura(fig, texto: str, subtitulo: str | None = None,
                  top: float = 0.84, ancho_sub: int = 112) -> None:
    """Titulo/subtitulo a nivel de FIGURA, para las de varios paneles.

    Reserva el espacio superior con tight_layout(rect=...) para que el titulo
    nunca pise a los paneles.
    """
    if MODO_MEMORIA:
        # Sin titulo no hay que reservar espacio arriba: los paneles ocupan
        # todo el alto disponible.
        fig.tight_layout()
        return
    fig.text(0.0, 1.0, texto, fontsize=10, fontweight="bold", color=TINTA,
             va="top", ha="left")
    if subtitulo:
        fig.text(0.0, 0.945, envolver(subtitulo, ancho_sub), fontsize=8,
                 color=TINTA_2, va="top", ha="left", linespacing=1.35)
    fig.tight_layout(rect=(0, 0, 1, top))


def etiquetar_barras_h(ax, barras, valores, fmt="{:.3f}", dx=0.006,
                       color=TINTA, negrita=None, dentro=False) -> None:
    """Etiqueta directa al final de cada barra horizontal.

    Obligatorio para las series en aqua (regla de relieve por contraste) y
    recomendable siempre: evita que el lector tenga que ir al eje.

    `dentro=True` escribe la etiqueta DENTRO de la barra, alineada a la
    derecha. Es lo que hay que usar cuando las barras llegan casi al borde
    del eje y una etiqueta exterior se saldria del lienzo.
    """
    for i, (b, v) in enumerate(zip(barras, valores)):
        peso = "bold" if (negrita is not None and negrita[i]) else "normal"
        x = b.get_width() - abs(dx) if dentro else b.get_width() + dx
        ax.text(x, b.get_y() + b.get_height() / 2, num(v, fmt),
                va="center", ha="right" if dentro else "left", fontsize=8,
                color=color, fontweight=peso)


def etiquetar_barras_v(ax, barras, valores, fmt="{:.3f}", dy=0.008,
                       color=TINTA, negrita=None) -> None:
    """Etiqueta directa encima de cada barra vertical."""
    for i, (b, v) in enumerate(zip(barras, valores)):
        peso = "bold" if (negrita is not None and negrita[i]) else "normal"
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + dy,
                num(v, fmt), va="bottom", ha="center", fontsize=8,
                color=color, fontweight=peso)


def leyenda_abajo(ax, ncols=2, dy=-0.16, **kw) -> None:
    """Leyenda bajo el eje x.

    En las figuras de barras casi llenas (accuracy cerca de 1) no queda hueco
    interior libre: cualquier `loc` interno acaba tapando datos.
    """
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, dy), ncols=ncols, **kw)


def linea_azar(ax, y=0.5, texto="azar (0.5)", horizontal=True) -> None:
    """Marca el nivel de azar. Imprescindible en las figuras de accuracy:
    sin ella, 0.57 parece 'algo' cuando en realidad no es nada."""
    if horizontal:
        ax.axhline(y, color=APAGADO, lw=1.0, ls=(0, (4, 3)), zorder=1)
        ax.text(ax.get_xlim()[1], y, f" {texto}", va="center", ha="left",
                fontsize=7.5, color=APAGADO)
    else:
        ax.axvline(y, color=APAGADO, lw=1.0, ls=(0, (4, 3)), zorder=1)
        ax.text(y, ax.get_ylim()[1], f" {texto}", va="bottom", ha="center",
                fontsize=7.5, color=APAGADO)


def nota(fig, texto: str, y=-0.005, ancho: int = 132) -> None:
    """Nota al pie de la figura: fuente del dato y protocolo de evaluacion.

    Toda figura de resultados lleva una: es lo que permite al tribunal saber
    sobre que particion, con que balanceo y desde que fichero se midio. En modo
    memoria esa informacion pasa al \\caption, asi que aquí no se dibuja.
    """
    if MODO_MEMORIA:
        return
    fig.text(0.0, y, envolver(texto, ancho), fontsize=6.8, color=APAGADO,
             va="top", ha="left", linespacing=1.4)


def _punto_en_ejes(fig) -> None:
    """Pone punto decimal en los ejes NUMERICOS de la figura.

    Solo se toca lo que lleva un ScalarFormatter, que es el formateador por
    defecto de un eje numerico. Los ejes categoricos -- nombres de día, de
    vista -- usan FixedFormatter con texto y se dejan como estan.
    """
    from matplotlib.ticker import FuncFormatter, ScalarFormatter

    def punto(x, _pos):
        return "%g" % x

    for ax in fig.get_axes():
        for eje in (ax.xaxis, ax.yaxis):
            if isinstance(eje.get_major_formatter(), ScalarFormatter):
                eje.set_major_formatter(FuncFormatter(punto))


def guardar(fig, nombre: str, *, apretar=True) -> None:
    """Guarda en PDF (LaTeX) y PNG (presentacion) y cierra la figura.

    En modo memoria escribe solo el PDF, y en `figuras/memoria/`, para no pisar
    las versiones anotadas que usan el README y las presentaciones.
    """
    _punto_en_ejes(fig)
    if apretar:
        fig.tight_layout()
    if MODO_MEMORIA:
        DIR_MEMORIA.mkdir(parents=True, exist_ok=True)
        fig.savefig(DIR_MEMORIA / f"{nombre}.pdf", bbox_inches="tight",
                    pad_inches=0.06)
        # PNG de la MISMA variante limpia, para las diapositivas: Canva importa
        # mal el PDF, y las PNG de figuras/png/ llevan titulo, subtitulo y nota
        # incrustados, que es demasiado texto en pantalla.
        #
        # 300 ppp, no menos: una figura a ancho completo ocupa unos 1.690 px en
        # una diapositiva de 1920, y a 220 ppp habria que estirarla un 31 %.
        fig.savefig(DIR_MEMORIA / f"{nombre}.png", bbox_inches="tight",
                    dpi=300, pad_inches=0.06, transparent=False)
        plt.close(fig)
        print(f"  [ok] {nombre} (memoria)")
        return
    for carpeta, ext, dpi in ((DIR_PDF, "pdf", None), (DIR_PNG, "png", 200)):
        fig.savefig(carpeta / f"{nombre}.{ext}", bbox_inches="tight",
                    dpi=dpi, pad_inches=0.06)
    plt.close(fig)
    print(f"  [ok] {nombre}")


def nueva(ancho=ANCHO_COMPLETO, alto=3.2, **kw):
    """Atajo: aplica el estilo y devuelve (fig, ax)."""
    aplicar_estilo()
    return plt.subplots(figsize=(ancho, alto), **kw)

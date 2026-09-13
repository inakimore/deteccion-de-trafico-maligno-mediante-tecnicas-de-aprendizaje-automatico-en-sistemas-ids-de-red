#!/usr/bin/env python
"""Bloque 6 - Robustez: que pasa cuando el atacante colabora menos.

F26 evasión       Camuflar los primeros bytes hunde el payload, no la conducta
F27 anomalia      Sin etiquetas (zero-day): cada regimen esconde su senal en otra vista
F28 rigor         ROC-AUC con intervalos de confianza al 95 %
F29 cruzado       Entrenar en un dataset y detectar en otro
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AQUA, AZUL, CRITICO, NARANJA, RAMPA_AZUL,  # noqa: E402
                    TINTA, TINTA_2, ANCHO_COMPLETO, envolver,
                    etiquetar_barras_v, guardar, leyenda_abajo, limpiar_ejes,
                    linea_azar, nota, nueva, titulo, titulo_figura)


# --------------------------------------------------------------------- F26
def f26_evasion() -> None:
    """La prueba activa: se camuflan los primeros bytes del ataque con los de
    un cliente benigno (coste trivial para el atacante) y se vuelve a medir.

    Forma: dumbbell (antes -> despues por item). Es la forma correcta para
    'valor inicial contra valor final' y hace visible de un vistazo que una
    linea es larga y la otra tiene longitud cero.
    """
    filas = []
    for escenario, vistas in R.EVASION.items():
        for vista, v in vistas.items():
            filas.append((escenario, vista, v["original"], v["evadido"]))

    fig, ax = nueva(ANCHO_COMPLETO, 2.9)
    y = np.arange(len(filas))
    for i, (esc, vista, orig, evad) in enumerate(filas):
        color = AZUL if "payload" in vista else NARANJA
        ax.plot([evad, orig], [i, i], color=color, lw=2.5, alpha=0.35,
                solid_capstyle="round", zorder=1)
        ax.scatter([orig], [i], s=70, color=color, zorder=3,
                   edgecolors="#fcfcfb", linewidths=1.5)
        ax.scatter([evad], [i], s=70, color=color, zorder=3, alpha=0.45,
                   edgecolors="#fcfcfb", linewidths=1.5)
        caida = orig - evad
        if caida > 0.02:
            ax.annotate(f"-{caida:.2f}", xy=((orig + evad) / 2, i + 0.30),
                        ha="center", va="center", fontsize=7.5,
                        color=CRITICO, fontweight="bold")
        else:
            ax.annotate("invariante", xy=(orig - 0.02, i), ha="right",
                        va="center", fontsize=7.5, color=NARANJA,
                        fontweight="bold")
        ax.text(-0.02, i, vista, ha="right", va="center", fontsize=8,
                color=TINTA)

    # separador y titulo de cada escenario
    for i, esc in enumerate(R.EVASION):
        ax.text(1.04, i * 2 + 0.5, envolver(esc, 18), ha="left", va="center",
                fontsize=7.5, color=TINTA_2, linespacing=1.3)
    ax.axhline(1.5, color="#e1e0d9", lw=1)

    ax.set_yticks([])
    ax.set_ylim(-0.7, len(filas) - 0.3)
    ax.set_xlim(0, 1.02)
    ax.invert_yaxis()
    ax.set_xlabel("recall del ataque")
    limpiar_ejes(ax, rejilla="x")

    # leyenda manual: relleno = original, translucido = tras la evasion
    ax.scatter([], [], s=70, color=APAGADO, label="antes de la evasión")
    ax.scatter([], [], s=70, color=APAGADO, alpha=0.45, label="tras camuflar los primeros bytes")
    leyenda_abajo(ax, ncols=2, dy=-0.20)

    titulo(ax, "La firma de bytes se evade; la conductual no",
           "El atacante copia los primeros bytes de un cliente legitimo y no cambia nada más. El "
           "detector de payload pierde la mitad de los ataques; el conductual ni se entera, porque "
           "no mira el contenido sino el numero de conexiones por origen y unidad de tiempo.")
    nota(fig, "Binario Attack vs Benign en el servicio atacado, balanceo 1:1, split 70/30. Se camuflan los "
              "primeros 48 B (SSH) / 200 B (DoS) de cada flujo de ataque. "
              "Fuente: models/phase2_evasion_*.md (scripts/zeek/evasion_test.py).")
    guardar(fig, "F26_evasion")


# --------------------------------------------------------------------- F27
def f27_anomalia() -> None:
    """Sin etiquetas de ataque (escenario zero-day): se entrena solo con
    benigno y se mide si el ataque cae fuera de la normalidad aprendida.

    La tesis se replica sin supervision: cada regimen esconde su senal en una
    vista distinta. Y el volumétrico resulta intrinsecamente dificil, porque
    un GET de Hulk es MÁS normal que el benigno medio.
    """
    regimenes = list(R.ANOMALIA)
    vistas = ["payload-IF", "payload-AE", "meta+rafaga-IF"]
    colores = [AZUL, "#86b6ef", NARANJA]

    x = np.arange(len(regimenes))
    an = 0.25
    fig, ax = nueva(ANCHO_COMPLETO, 3.0)
    for i, (v, c) in enumerate(zip(vistas, colores)):
        vals = [R.ANOMALIA[r][v] for r in regimenes]
        b = ax.bar(x + (i - 1) * an, vals, an * 0.9, color=c, label=v)
        etiquetar_barras_v(ax, b, vals, fmt="{:.2f}", dy=0.012)

    ax.set_xticks(x, [envolver(r, 20) for r in regimenes], fontsize=8)
    ax.set_ylim(0, 1.14)
    ax.set_ylabel("ROC-AUC (no supervisado)")
    limpiar_ejes(ax)
    linea_azar(ax, 0.5, "no distingue (0.5)")
    leyenda_abajo(ax, ncols=3, dy=-0.18)

    titulo(ax, "Sin etiquetas, la tesis se sostiene igual",
           "Modelos entrenados SOLO con tráfico benigno. En el cifrado la conducta lo resuelve "
           "(AUC 1.00) y el payload falla; en claro el payload aporta; en el volumétrico fallan las "
           "dos, porque una petición del flood es más 'normal' que el propio tráfico legitimo.")
    nota(fig, "IF = Isolation Forest, AE = autoencoder. Entrenados solo con benigno; el ataque nunca se ve en "
              "entrenamiento. Fuente: models/phase2_anomaly_*.md (scripts/zeek/anomaly_detection.py). "
              "El día DoS se midio antes del re-etiquetado del 11-ago.")
    guardar(fig, "F27_anomalia")


# --------------------------------------------------------------------- F28
def f28_rigor() -> None:
    """Con clases pequenas (203 flujos de ataque web) un accuracy puntual dice
    poco. Aquí va el ROC-AUC con su intervalo de confianza al 95 % por
    bootstrap: la anchura del intervalo avisa de cuanto N hay detras.
    """
    regimenes = list(R.RIGOR)
    vistas = ["payload byte-CNN", "payload histograma", "conducta meta+rafaga"]
    colores = [AZUL, "#86b6ef", NARANJA]

    fig, axes = nueva(ANCHO_COMPLETO, 2.5, ncols=len(regimenes), sharex=True)
    axes = np.atleast_1d(axes)

    for ax, reg in zip(axes, regimenes):
        for i, (v, c) in enumerate(zip(vistas, colores)):
            val, lo, hi = R.RIGOR[reg][v]
            ax.errorbar(val, i, xerr=[[val - lo], [hi - val]], fmt="o",
                        color=c, markersize=7, capsize=3, lw=1.6,
                        markeredgecolor="#fcfcfb", markeredgewidth=1.2)
            ax.text(lo - 0.004, i, f"{val:.4f}", ha="right", va="center",
                    fontsize=7.5, color=TINTA)
        ax.set_yticks(range(len(vistas)), vistas, fontsize=7.5)
        ax.set_xlim(0.975, 1.004)
        ax.set_xticks([0.98, 1.0], ["0.98", "1.0"])
        ax.invert_yaxis()
        limpiar_ejes(ax, rejilla="x")
        ax.set_title(envolver(reg, 20), loc="left", fontsize=8.5, color=TINTA)
        if ax is not axes[0]:
            ax.set_yticklabels([])
    axes[0].set_xlabel("ROC-AUC [IC 95 %]")

    titulo_figura(
        fig, "Las cifras, con su incertidumbre",
        "ROC-AUC e intervalo de confianza al 95 % por bootstrap (2.000 remuestreos). Los intervalos "
        "son estrechos en los dos regimenes con N suficiente; el día DoS no aparece porque sus "
        "metricas de rigor se calcularon antes de corregir el etiquetado.",
        top=0.76)
    nota(fig, "Out-of-fold 5-Fold, balanceo 1:1 (433 vs 433 en SSH; 203 vs 203 en web). "
              "Fuente: models/phase2_rigor_*.md (scripts/zeek/rigor_metrics.py), que ademas genera las "
              "curvas ROC y Precisión-Recall completas en PNG.", y=-0.05)
    guardar(fig, "F28_rigor", apretar=False)


# --------------------------------------------------------------------- F29
def f29_cruzado() -> None:
    """Entrenar en un dataset (2018) y detectar en otro (2017) con el ataque
    analogo. Es la prueba directa contra el "100 % sospechoso": lo que
    sobrevive al cambio de laboratorio es senal; lo que se desploma a 0.5 era
    memorizacion.

    El matiz honesto: que el payload transfiera no significa que sea robusto.
    Solo el web transfiere por contenido del ataque; SSH y DoS transfieren
    por la huella de la herramienta, que es evadible (F26).
    """
    pares = ["2018 -> 2017 (Web)", "2018 -> 2017 (SSH)", "2018 -> 2017 (DoS)"]
    vistas = ["payload-hist", "metadatos", "byte-CNN"]
    colores = ["#86b6ef", NARANJA, AZUL]

    x = np.arange(len(pares))
    an = 0.25
    fig, ax = nueva(ANCHO_COMPLETO, 3.0)
    for i, (v, c) in enumerate(zip(vistas, colores)):
        vals = [R.CRUZADO[p][v] for p in pares]
        b = ax.bar(x + (i - 1) * an, vals, an * 0.9, color=c, label=v)
        etiquetar_barras_v(ax, b, vals, fmt="{:.2f}", dy=0.012)

    ax.set_xticks(x, ["Web\n(en claro)", "SSH\n(cifrado)", "DoS\n(volumétrico)"])
    # Holgura suficiente para que el motivo de cada grupo quede POR ENCIMA de
    # las etiquetas de las barras, no encima de ellas.
    ax.set_ylim(0, 1.30)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("accuracy en el dataset de destino")
    limpiar_ejes(ax)
    linea_azar(ax, 0.5)
    leyenda_abajo(ax, ncols=3, dy=-0.17)

    # El matiz decisivo: POR QUE transfiere cada uno. Que el payload cruce de
    # dataset no lo hace robusto si lo que cruza es la huella del atacante.
    motivos = ["contenido\nintrinseco", "fingerprint\n(evadible)",
               "fingerprint\n(evadible)"]
    for i, m in enumerate(motivos):
        ax.text(i, 1.16, m, ha="center", va="center", fontsize=7,
                color=TINTA_2 if i == 0 else CRITICO, linespacing=1.3,
                fontweight="bold" if i == 0 else "normal")

    titulo(ax, "El byte-CNN detecta en 2017 lo que aprendio en 2018",
           "La firma del payload no era memorizacion del laboratorio: transfiere entre datasets "
           "distintos, mientras los metadatos per-flujo caen al azar. Pero solo en el ataque web "
           "transfiere por el contenido del ataque; en SSH y DoS transfiere la huella de la herramienta.")
    nota(fig, "Entrenado en el día de 2018 y evaluado en el día analogo de 2017, balanceo 1:1 en ambos "
              "(0.5 = azar). Fuente: models/phase2_crossdataset_*.md (scripts/zeek/cross_dataset_eval.py). "
              "La direccion inversa (2017 -> 2018) se desploma por la menor diversidad del ataque de 2017.")
    guardar(fig, "F29_cruzado")


def generar_todo() -> None:
    print("Bloque 6 - Robustez")
    f26_evasion()
    f27_anomalia()
    f28_rigor()
    f29_cruzado()


if __name__ == "__main__":
    generar_todo()

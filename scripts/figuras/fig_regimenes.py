#!/usr/bin/env python
"""Bloque 4 - Los cuatro regimenes: el nucleo argumental de la memoria.

F16 matriz_regimen_vista   Dentro del día todo satura (figura central)
                           4 filas desde el 22-ago: se anadio la periodicidad
F17 rafaga_distribucion    1 vs 86 conexiones/5 s: la firma conductual
F18 entropia_distribucion  Por que el payload es ciego al tráfico cifrado
F19 inversion_web_ssh      La unica inversion real: los metadatos per-flujo
F20 dos_revisado           El DoS antes y despues de corregir el etiquetado
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AZUL, CRITICO, DIR_CACHE, NARANJA, RAMPA_AZUL,  # noqa: E402
                    TINTA, TINTA_2, ANCHO_COMPLETO, etiquetar_barras_v, guardar,
                    leyenda_abajo, limpiar_ejes, linea_azar, miles, num, nota, nueva, titulo,
                    titulo_figura)


# --------------------------------------------------------------------- F16
def f16_matriz_regimen_vista() -> None:
    """LA figura central, reescrita el 24-ago (HALLAZGO 19).

    Antes afirmaba que ninguna vista gana en los cuatro regimenes. Medidas las
    tres vistas con la misma metrica y el mismo protocolo en los seis días, eso
    es falso: todas saturan. Lo que la figura muestra ahora es justo eso -- una
    rejilla uniformemente oscura, sin contraste que leer -- y la anotacion de
    cada celda revela lo que el numero esconde: cuanto queda de esa vista
    cuando el atacante camufla los primeros bytes.

    El mensaje pasa de "cada regimen tiene su vista" a "dentro del día no se
    distingue nada; la diferencia esta en la robustez".
    """
    dias = ["14-02", "22-02", "16-02", "15-02", "20-02", "02-03"]
    etiquetas_fila = [
        "Cifrado\nSSH-Bruteforce (14-02)",
        "En claro\nWeb BF/XSS/SQLi (22-02)",
        "Volumétrico\nDoS-Hulk (16-02)",
        "Volumétrico\nGoldenEye+Slowloris (15-02)",
        "Volumétrico diluido\nDDoS-LOIC (20-02)",
        "Periodicidad\nBot / Ares (02-03)",
    ]
    cols = ["Payload\n(bytes)", "Metadatos\nper-flujo", "Conducta\n(meta + ráfaga)"]
    claves = ["payload", "metadatos", "conducta"]

    M = np.array([[R.SATURACION_INTRADIA[d][k][0] for k in claves] for d in dias])

    # Recall del payload DESPUES de camuflar los primeros bytes. Es el unico
    # numero que distingue unas celdas de otras, y no esta en la rejilla.
    # Fuentes: EVASION (14-02, 48 B), EVASION_PREFIJO_WEB (22-02, 24 B: el
    # prefijo de 160 B no evadia, DESTRUIA la inyeccion) y EJE_E_EVASION.
    evadido = {
        "14-02": R.EVASION["SSH cifrado (14-02, 48 B)"]["payload (byte-CNN)"]["evadido"],
        "22-02": R.EVASION_PREFIJO_WEB["prefijo_24"][1],
        "16-02": R.EJE_E_EVASION["16-02 DoS-Hulk"]["payload (byte-CNN)"][1],
        "15-02": None,   # no se sometio al test de evasion
        "20-02": R.EJE_E_EVASION["20-02 DDoS-LOIC"]["payload (byte-CNN)"][1],
        "02-03": R.EJE_E_EVASION["02-03 Bot"]["payload (byte-CNN)"][1],
    }

    fig, ax = nueva(ANCHO_COMPLETO, 4.2)
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("azul", RAMPA_AZUL[:9])
    im = ax.imshow(M, cmap=cmap, vmin=0.90, vmax=1.0, aspect="auto")

    for i, dia in enumerate(dias):
        for j in range(len(cols)):
            v = M[i, j]
            col = "#ffffff" if v >= 0.975 else TINTA
            ax.text(j, i - 0.12, f"{v:.4f}", ha="center", va="center",
                    fontsize=9.5, fontweight="bold", color=col)
            if j == 0:
                ev = evadido[dia]
                txt = "no probada" if ev is None else f"tras evasión: {ev:.4f}"
            else:
                txt = "invariante"
            ax.text(j, i + 0.26, txt, ha="center", va="center",
                    fontsize=6.6, color=col, style="italic")

    ax.set_xticks(range(len(cols)), cols, fontsize=8)
    ax.set_yticks(range(len(etiquetas_fila)), etiquetas_fila, fontsize=7.5)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    ax.set_xticks(np.arange(-0.5, len(cols), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(etiquetas_fila), 1), minor=True)
    ax.grid(which="minor", color="#fcfcfb", linewidth=2.5)

    titulo(ax, "Dentro del día no se distingue nada: todo satura",
           "Macro-F1 out-of-fold de las mismas tres vistas, mismo protocolo, en los seis días. "
           "La rejilla es uniformemente alta: ninguna vista se separa de las otras. Lo unico que "
           "las distingue esta escrito debajo de cada celda -- que queda de esa vista cuando el "
           "atacante camufla los primeros bytes.")
    nota(fig, "Macro-F1 out-of-fold (5-Fold estratificado), benigno genuino de terceros, balanceo "
              "1:1 con tope de 5.000 por clase, media de 10 submuestreos. Fuente: "
              "models/phase2_ic_caso_dificil_*.md. Evasión: models/phase2_evasion_*.md y "
              "phase3_interarribo_*.md; en el día web el prefijo es de 24 B, porque con 160 B no "
              "se evade la detección sino que se destruye la inyeccion. La conducta es invariante "
              "por construccion: no mira un solo byte del contenido.")
    guardar(fig, "F16_matriz_regimen_vista")


# --------------------------------------------------------------------- F17
def f17_rafaga_distribucion() -> None:
    """La firma conductual, medida sobre los datos reales.

    El benigno legitimo abre ~1 conexión cada 5 s; el atacante ~86. Es una
    separacion de casi dos ordenes de magnitud, y no depende de un solo byte
    del contenido: por eso sobrevive al cifrado y a la evasión.
    """
    # Los tres regimenes, incluido aquel donde la rafaga NO sirve: el ataque
    # web es de bajo volumen (mediana 1 conn/5 s, por debajo del benigno), asi
    # que la vista conductual es ciega justo donde el payload gana. Ese panel
    # es tan importante como los otros dos: es la otra mitad de la tesis.
    dias = [("14-02", "Cifrado - SSH-Bruteforce"),
            ("16-02", "Volumétrico - DoS-Hulk"),
            ("22-02", "En claro - Web (la ráfaga NO separa)")]
    disponibles = [(d, t) for d, t in dias if (DIR_CACHE / f"rafaga_{d}.npz").exists()]
    if not disponibles:
        print("  [skip] F17: falta cache de ráfaga (ejecuta extraer_datos.py)")
        return

    fig, axes = nueva(ANCHO_COMPLETO, 2.7, ncols=len(disponibles))
    axes = np.atleast_1d(axes)

    for ax, (dia, subt) in zip(axes, disponibles):
        z = np.load(DIR_CACHE / f"rafaga_{dia}.npz")
        atk, ben = z["ataque"], z["benigno_genuino"]
        bins = np.logspace(0, np.log10(max(atk.max(), ben.max(), 10)) + 0.05, 45)
        ax.hist(ben, bins=bins, color=AZUL, alpha=0.85, label="Benigno (terceros)")
        ax.hist(atk, bins=bins, color=NARANJA, alpha=0.85, label="Ataque")
        ax.set_xscale("log")
        ax.set_yscale("log")
        limpiar_ejes(ax, rejilla="y")
        ax.set_xlabel("conexiones / 5 s")
        ax.set_ylabel("flujos")
        m_a, m_b = float(z["mediana_ataque"]), float(z["mediana_benigno"])
        ax.set_title(subt, loc="left", fontsize=8.5, color=TINTA)
        # Etiquetas directas de la mediana, en alturas distintas para que no
        # colisionen cuando ambas medianas caen en el mismo punto (dia web).
        tope = ax.get_ylim()[1]
        ax.annotate(f"mediana benigno: {m_b:.0f}", xy=(1.0, tope * 0.02),
                    xycoords=("axes fraction", "data"), xytext=(0.5, 0.92),
                    textcoords="axes fraction", color=AZUL, fontsize=7,
                    ha="center", fontweight="bold")
        ax.annotate(f"mediana ataque: {miles(m_a)}", xy=(1.0, tope * 0.02),
                    xycoords=("axes fraction", "data"), xytext=(0.5, 0.80),
                    textcoords="axes fraction", color=NARANJA, fontsize=7,
                    ha="center", fontweight="bold")

    # Leyenda a nivel de figura: dentro de un panel taparia las barras.
    manejadores, etiquetas = axes[0].get_legend_handles_labels()
    fig.legend(manejadores, etiquetas, loc="upper right", ncols=2,
               bbox_to_anchor=(1.0, 0.83), fontsize=7.5)
    titulo_figura(
        fig,
        "La ráfaga separa dos regimenes sin mirar un solo byte — y falla en el tercero",
        "Distribucion del nº de conexiones por origen en ventanas causales de 5 s "
        "(ambos ejes en escala logaritmica). En el ataque web, de bajo volumen, la "
        "conducta es ciega: es justo donde el payload gana.",
        top=0.78)
    nota(fig, "Calculado sobre el día completo (todos los origenes) y segmentado despues por clase, "
              "igual que en scripts/zeek/honest_by_service_rich.py. Benigno = solo IPs de terceros.",
         y=-0.02)
    guardar(fig, "F17_rafaga_distribucion", apretar=False)


# --------------------------------------------------------------------- F18
def f18_entropia_distribucion() -> None:
    """Por que el payload es ciego al brute-force cifrado.

    En SSH las dos distribuciones de entropía se solapan casi por completo
    (ambas cerca del máximo de 8 bits/byte): a nivel de byte, ataque y
    tráfico legitimo son el mismo objeto estadistico. En el día web, en
    cambio, se separan.
    """
    dias = [("14-02", "Cifrado - SSH (:22)",
             "mismo rango, cerca del máximo: a nivel de byte son el mismo objeto"),
            ("22-02", "En claro - HTTP (:80)",
             "rangos distintos: el contenido si aporta senal")]
    disponibles = [(d, t, s) for d, t, s in dias
                   if (DIR_CACHE / f"entropia_{d}.npz").exists()]
    if not disponibles:
        print("  [skip] F18: falta cache de entropía")
        return

    fig, axes = nueva(ANCHO_COMPLETO, 2.8, ncols=len(disponibles))
    axes = np.atleast_1d(axes)
    for ax, (dia, subt, lectura) in zip(axes, disponibles):
        z = np.load(DIR_CACHE / f"entropia_{dia}.npz")
        bins = np.linspace(0, 8, 60)
        ax.hist(z["benigno_genuino"], bins=bins, color=AZUL, alpha=0.8,
                density=True, label="Benigno (terceros)")
        ax.hist(z["ataque"], bins=bins, color=NARANJA, alpha=0.8,
                density=True, label="Ataque")
        limpiar_ejes(ax, rejilla="y")
        ax.set_xlabel("entropía de Shannon (bits/byte)")
        ax.set_ylabel("densidad")
        # La lectura va entre el titulo del panel y el grafico, no debajo del
        # eje, donde chocaria con la etiqueta del eje x.
        ax.set_title(subt, loc="left", fontsize=8.5, color=TINTA, pad=16)
        ax.text(0.0, 1.01, lectura, transform=ax.transAxes, fontsize=7,
                color=TINTA_2, style="italic", va="bottom", ha="left")
    axes[0].legend(loc="upper left", fontsize=7.5)

    titulo_figura(
        fig, "El cifrado borra la senal del payload; el texto en claro la conserva",
        "Entropía por flujo dentro del servicio atacado. El máximo teorico es 8 bits/byte: "
        "cuanto más cerca, más indistinguible del ruido.",
        top=0.80)
    nota(fig, "Entropía de Shannon calculada por scripts/zeek/build_dataset.py sobre el payload "
              "agregado de cada conexión TCP (hasta 64 KB). Benigno = solo IPs de terceros.", y=-0.06)
    guardar(fig, "F18_entropia_distribucion", apretar=False)


# --------------------------------------------------------------------- F19
def f19_inversion_web_ssh() -> None:
    """Que cambia de verdad al pasar del regimen cifrado al regimen en claro.

    Reescrita el 24-ago. La version anterior comparaba la vista conductual en
    el lado SSH contra los metadatos basicos en el lado web -- dos conjuntos de
    caracteristicas distintos bajo la misma etiqueta -- porque el día web nunca
    se habia evaluado con la vista conductual. Medidos ambos días con las
    mismas tres vistas, la unica diferencia real, y la unica cuyos intervalos
    de confianza no se solapan, es el desplome de los metadatos per-flujo.
    """
    claves = ["payload", "metadatos", "conducta"]
    vistas = ["Payload\n(histograma)", "Metadatos\nper-flujo",
              "Conducta\n(meta + ráfaga)"]

    def serie(dia):
        v = [R.SATURACION_INTRADIA[dia][k] for k in claves]
        val = [x[0] for x in v]
        hi = [x[2] for x in v]
        err = [[x[0] - x[1] for x in v], [x[2] - x[0] for x in v]]
        return val, err, hi

    ssh, ssh_err, ssh_hi = serie("14-02")
    web, web_err, web_hi = serie("22-02")

    x = np.arange(len(vistas))
    ancho = 0.36
    fig, ax = nueva(ANCHO_COMPLETO, 3.4)
    b1 = ax.bar(x - ancho / 2, ssh, ancho, color=AZUL,
                label="Cifrado (SSH-Bruteforce, 14-02)")
    b2 = ax.bar(x + ancho / 2, web, ancho, color=NARANJA,
                label="En claro (Web BF/XSS/SQLi, 22-02)")
    ax.errorbar(x - ancho / 2, ssh, yerr=ssh_err, fmt="none",
                ecolor=TINTA, elinewidth=1.1, capsize=3, capthick=1.1)
    ax.errorbar(x + ancho / 2, web, yerr=web_err, fmt="none",
                ecolor=TINTA, elinewidth=1.1, capsize=3, capthick=1.1)
    # El valor va sobre el EXTREMO SUPERIOR DEL INTERVALO, no sobre el alto de
    # la barra: el bigote sobresale y el numero se montaba encima.
    for xi, v, h in zip(x - ancho / 2, ssh, ssh_hi):
        ax.text(xi, h + 0.006, num(v), ha="center", va="bottom", fontsize=8.5)
    for xi, v, h in zip(x + ancho / 2, web, web_hi):
        ax.text(xi, h + 0.006, num(v), ha="center", va="bottom", fontsize=8.5)

    ax.set_xticks(x, vistas)
    ax.set_ylim(0.85, 1.03)
    ax.set_ylabel("macro-F1 (out-of-fold)")
    limpiar_ejes(ax)
    leyenda_abajo(ax, ncols=2)

    # Lo unico que se mueve de verdad. Dentro de la propia barra que cae, en
    # blanco: fuera chocaba con el bigote del intervalo.
    ax.text(1 + ancho / 2, 0.883, "-7.2 pts",
            ha="center", va="center", fontsize=8.5, color="#ffffff",
            fontweight="bold")

    titulo(ax, "Lo unico que se invierte son los metadatos per-flujo",
           "Las mismas tres vistas, el mismo protocolo y la misma metrica en los dos "
           "regimenes. El payload y la conducta apenas se mueven y sus intervalos se "
           "solapan. Los metadatos per-flujo se hunden 7.2 puntos al pasar al regimen "
           "en claro, y son la unica diferencia cuyos intervalos NO se solapan.")
    nota(fig, "Macro-F1 out-of-fold (5-Fold estratificado), benigno genuino de terceros, "
              "balanceo 1:1, media de 10 submuestreos. Barras de error: IC 95% por bootstrap "
              "(2.000 remuestreos agrupados). Fuente: models/phase2_ic_caso_dificil_*.md. "
              "El día web tiene solo 203 flujos de ataque, de ahi la anchura de sus intervalos.")
    guardar(fig, "F19_inversion_web_ssh")


# --------------------------------------------------------------------- F20
def f20_dos_revisado() -> None:
    """El DoS antes y despues de corregir el limite de ventana.

    Figura de honestidad metodologica: un resultado publicado en el diario
    (Hallazgo 8) resulto ser un artefacto de comparar ataque contra ataque.
    La conclusion no se borra, se corrige y se explica.
    """
    vistas = ["Payload\n(histograma)", "Metadatos\nper-flujo", "Conducta\n(meta+ráfaga)"]
    antes = [R.DOS_BURST["contaminado (15-jul)"][k]
             for k in ("payload-hist", "meta-basica", "meta+rafaga")]
    despues = [R.DOS_BURST["genuino (11-ago)"][k]
               for k in ("payload-hist", "meta-basica", "meta+rafaga")]

    x = np.arange(len(vistas))
    ancho = 0.36
    fig, ax = nueva(ANCHO_COMPLETO, 3.2)
    b1 = ax.bar(x - ancho / 2, antes, ancho, color=APAGADO,
                label="Benigno contaminado (65.1 % era el propio atacante)")
    b2 = ax.bar(x + ancho / 2, despues, ancho, color=NARANJA,
                label="Benigno genuino (tras corregir la ventana)")
    etiquetar_barras_v(ax, b1, antes, dy=0.008)
    etiquetar_barras_v(ax, b2, despues, dy=0.008)

    ax.set_xticks(x, vistas)
    ax.set_ylim(0, 1.13)
    ax.set_ylabel("macro-F1 (out-of-fold)")
    limpiar_ejes(ax)
    linea_azar(ax, 0.5)
    leyenda_abajo(ax, ncols=2, dy=-0.22, fontsize=7.5)

    titulo(ax, "El 'per-flujo no sirve' del DoS era un artefacto del etiquetado",
           "Comparar ataque contra ataque hundia las tres vistas. Con benigno real, el payload "
           "tambien separa— pero por un fingerprint de herramienta, evadible (Hallazgo 11).")
    nota(fig, "Mismo protocolo en ambas tandas: balanceo 1:1, --cap 4000, out-of-fold 5-Fold, seleccion por servicio. "
              "Fuente: models/phase2_dos_burst_Friday-16-02-2018.md (15-jul vs 11-ago).")
    guardar(fig, "F20_dos_revisado")


def generar_todo() -> None:
    print("Bloque 4 - Los cuatro regimenes")
    f16_matriz_regimen_vista()
    f17_rafaga_distribucion()
    f18_entropia_distribucion()
    f19_inversion_web_ssh()
    f20_dos_revisado()


if __name__ == "__main__":
    generar_todo()

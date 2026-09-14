#!/usr/bin/env python
"""Bloque 3 - Honestidad metodologica: por que casi todo el trabajo consistio
en desmontar sus propios resultados.

F11 fase1_robustez        El 99.99 % de la Fase 1 y el desplome del Slowloris
F12 espejismo             0.9996 de accuracy y 96 % de falsos positivos
F13 balanceo_global       Las tres vistas son identicas: el fallo es del protocolo
F14 benigno_contaminado   El techo de 0.61 era contaminacion, no un limite
                          [NO ENTRA EN LA MEMORIA - ver docstring de la funcion]
F15 composicion_benigno   De que estaba hecho realmente el "tráfico benigno"
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AZUL, CRITICO, NARANJA, TINTA, TINTA_2,  # noqa: E402
                    ANCHO_COMPLETO, etiquetar_barras_h, etiquetar_barras_v, miles,
                    guardar, leyenda_abajo, limpiar_ejes, linea_azar, nota,
                    nueva, rotulo, titulo, titulo_figura)


# --------------------------------------------------------------------- F11
def f11_fase1_robustez() -> None:
    """El cierre de la Fase 1: con las firmas mecanicas del script, tres
    modelos distintos dan ~0.9999; al quitarlas, el ataque sigiloso se cae.

    Forma: emfasis. Las tres barras del benchmark son contexto (gris); lo
    que hay que mirar es la barra que se desploma.
    """
    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 2.9, ncols=2,
                            gridspec_kw={"width_ratios": [1, 1.15]})

    # -- panel izquierdo: el benchmark que "sale perfecto"
    modelos = list(R.FASE1_BENCHMARK)
    medias = [R.FASE1_BENCHMARK[m][0] for m in modelos]
    b = ax1.barh(range(len(modelos)), medias, color=APAGADO, height=0.55)
    # Las barras llegan casi al borde: la etiqueta va dentro, en blanco.
    etiquetar_barras_h(ax1, b, medias, fmt="{:.5f}", dx=0.00003,
                       color="#ffffff", dentro=True)
    ax1.set_yticks(range(len(modelos)), modelos)
    ax1.set_xlim(0.9995, 1.0)
    ax1.set_xticks([0.9995, 1.0], ["0.9995", "1.0"])
    ax1.invert_yaxis()
    limpiar_ejes(ax1, rejilla="x")
    ax1.set_xlabel("accuracy media (5-Fold CV)")
    ax1.set_title("Con las firmas del script", loc="left", fontsize=8.5,
                  color=TINTA, pad=14)
    ax1.text(0.0, 1.01, "tres modelos distintos, el mismo ~0.9999",
             transform=ax1.transAxes, fontsize=7, color=TINTA_2,
             style="italic", va="bottom")

    # -- panel derecho: la prueba de robustez
    clases = list(R.FASE1_ROBUSTEZ)
    prec = [R.FASE1_ROBUSTEZ[c]["precision"] for c in clases]
    colores = [APAGADO, APAGADO, CRITICO]
    bb = ax2.bar(range(len(clases)), prec, color=colores, width=0.55)
    etiquetar_barras_v(ax2, bb, prec, fmt="{:.2f}", dy=0.012)
    ax2.set_xticks(range(len(clases)),
                   [c.replace(" ", "\n") for c in clases], fontsize=8)
    ax2.set_ylim(0, 1.15)
    limpiar_ejes(ax2)
    ax2.set_ylabel("precisión")
    ax2.set_title("Sin las firmas del script", loc="left", fontsize=8.5,
                  color=TINTA, pad=14)
    ax2.text(0.0, 1.01, "el ataque sigiloso se derrumba: 20 % de falsas alarmas",
             transform=ax2.transAxes, fontsize=7, color=CRITICO,
             style="italic", va="bottom")

    titulo_figura(
        fig, "Fase 1: cae el mito del 99.99 %",
        "Al eliminar las variables que memorizan el tamano exacto de los paquetes de la "
        "herramienta de ataque y balancear las clases, el DoS-Slowloris (de baja tasa) "
        "deja de distinguirse del tráfico lento legitimo.",
        top=0.72)
    nota(fig, "Izquierda: 5-Fold CV multiclase sin balancear. Derecha: XGBoost con undersampling "
              "y sin Init_Win_bytes / Fwd Seg Size Min. Fuente: notebooks/02_multiclass_benchmark.ipynb, "
              "README del 27 de abril.", y=-0.04)
    guardar(fig, "F11_fase1_robustez", apretar=False)


# --------------------------------------------------------------------- F12
def f12_espejismo() -> None:
    """El hallazgo que reorienta todo el trabajo: el mismo modelo, medido de
    dos maneras, pasa de 'perfecto' a inservible.

    El 0.9996 se obtiene porque el benigno de evaluacion es 99.9 % de OTROS
    protocolos: el modelo separa el protocolo, no el ataque.
    """
    fig, ax = nueva(ANCHO_COMPLETO, 3.0)

    etiquetas = ["Accuracy global\n(benigno de todos los protocolos)",
                 "Falsos positivos sobre\nSSH benigno real"]
    hist = [R.ESPEJISMO["histograma+entropia"]["test"],
            R.ESPEJISMO["histograma+entropia"]["fp_ssh_benigno"]]
    seq = [R.ESPEJISMO["secuencial"]["test"],
           R.ESPEJISMO["secuencial"]["fp_ssh_benigno"]]

    x = np.arange(2)
    an = 0.34
    b1 = ax.bar(x - an / 2, hist, an, color=[AZUL, CRITICO],
                label="modelo histograma+entropía")
    b2 = ax.bar(x + an / 2, seq, an, color=[AZUL, CRITICO], alpha=0.62,
                label="modelo secuencial")
    # Dos decimales: con uno solo, el 0,9996 se redondea a "100,0 %" y se
    # pierde justo el numero del que habla la figura.
    etiquetar_barras_v(ax, b1, hist, fmt="{:.2%}", dy=0.015)
    etiquetar_barras_v(ax, b2, seq, fmt="{:.2%}", dy=0.015)

    ax.set_xticks(x, etiquetas)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("proporción")
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0 %", "25 %", "50 %", "75 %", "100 %"])
    limpiar_ejes(ax)
    leyenda_abajo(ax, ncols=2, dy=-0.24)

    titulo(ax, "El 99.96 % era un espejismo del desbalanceo de servicios",
           "El modelo parece perfecto porque el tráfico benigno de evaluacion es casi todo de otros "
           "protocolos: lo que aprendio es a reconocer SSH, no a reconocer el ataque. Enfrentado a "
           "usuarios de SSH legitimos, marca como ataque a la inmensa mayoria.")
    nota(fig, "Accuracy: test held-out 20 % sobre el dataset balanceado (185.236 muestras). Falsos positivos: "
              "auditoria sobre los 2.022 flujos benignos reales del puerto 22. "
              "Fuentes: models/phase2_results.md, scripts/zeek/honest_check.py.")
    guardar(fig, "F12_espejismo")


# --------------------------------------------------------------------- F13
def f13_balanceo_global() -> None:
    """Las tres vistas dan exactamente lo mismo. El problema no es la vista,
    es el protocolo de balanceo: mientras el benigno este dominado por otros
    protocolos, ninguna vista aprende a separar el caso dificil.
    """
    vistas = ["payload", "metadatos", "hibrido"]
    acc = [R.BALANCEO_GLOBAL[v][0] for v in vistas]
    fp = [R.BALANCEO_GLOBAL[v][2] for v in vistas]

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 2.7, ncols=2)

    etiq = [rotulo(v) for v in vistas]   # las claves van sin tilde
    b1 = ax1.bar(etiq, acc, color=APAGADO, width=0.5)
    etiquetar_barras_v(ax1, b1, acc, fmt="{:.4f}", dy=0.00004)
    ax1.set_ylim(0.998, 1.0005)
    limpiar_ejes(ax1)
    ax1.set_ylabel("accuracy (5-Fold CV)")
    ax1.set_title("Lo que se publica", loc="left", fontsize=8.5, color=TINTA, pad=14)
    ax1.text(0.0, 1.01, "las tres vistas, indistinguibles", transform=ax1.transAxes,
             fontsize=7, color=TINTA_2, style="italic", va="bottom")

    b2 = ax2.bar(etiq, fp, color=CRITICO, width=0.5)
    etiquetar_barras_v(ax2, b2, fp, fmt="{:.1%}", dy=0.012)
    ax2.set_ylim(0, 1.0)
    ax2.set_yticks([0, 0.25, 0.5, 0.75], ["0 %", "25 %", "50 %", "75 %"])
    limpiar_ejes(ax2)
    ax2.set_ylabel("falsos positivos sobre SSH benigno")
    ax2.set_title("Lo que ocurre en el caso dificil", loc="left", fontsize=8.5,
                  color=TINTA, pad=14)
    ax2.text(0.0, 1.01, "las tres vistas, igual de malas", transform=ax2.transAxes,
             fontsize=7, color=CRITICO, style="italic", va="bottom")

    titulo_figura(
        fig, "Anadir metadatos 'a ciegas' no arregla nada",
        "Con balanceo global por clase, payload, metadatos e hibrido son estadisticamente "
        "equivalentes: las tres aprenden el mismo atajo ('SSH = ataque'). El espejismo es "
        "estructural al protocolo de evaluacion, no exclusivo del payload.",
        top=0.74)
    nota(fig, "Mismos flujos y mismo protocolo en las tres vistas (MLP 256->128, undersampling global, "
              "5-Fold CV + test held-out). Recall del ataque = 100 % en las tres. "
              "Fuente: models/phase2_hybrid_compare.md.", y=-0.05)
    guardar(fig, "F13_balanceo_global", apretar=False)


# --------------------------------------------------------------------- F14
def f14_benigno_contaminado() -> None:
    """El techo de 0.61 no era un limite de los metadatos: era que el 78.6 %
    del 'SSH benigno' resulto ser el propio atacante fuera de la ventana
    etiquetada. Se estaba comparando ataque contra ataque.

    EXCLUIDA DE LA MEMORIA (decision del autor, 24-ago-2026). Dos motivos:

    1. **No es reproducible.** La correccion del limite de ventana reetiqueto
       esos 1.589 flujos como ataque EN EL PROPIO .npz, asi que hoy
       `Benign & IP_atacante` es el conjunto vacio y la barra "contaminado" no
       puede recalcularse. Una figura que no se puede regenerar es un flanco
       innecesario en la defensa.
    2. **Grafica exactitud**, que es lo que midio `honest_by_service_rich.py`
       (scoring="accuracy"), mientras que la memoria declara macro-F1 y dedica
       una seccion a explicar por que la exactitud engana con clases
       desbalanceadas.

    Se conserva la funcion porque documenta un episodio real del trabajo y el
    PNG sigue siendo util para el repositorio. La seccion 4.1 de la memoria
    cuenta el mismo episodio con las cifras de composicion (1.589 flujos del
    atacante frente a 433 de terceros), que es lo que de verdad sostiene el
    argumento y no depende de poder recalcular nada.
    """
    vistas = ["payload", "meta-basica", "meta-rica\n(+ ráfaga)"]
    claves = ["payload", "meta-basica", "meta-rica"]
    cont = [R.CASO_DIFICIL_SSH["contaminado"][k] for k in claves]
    limp = [R.CASO_DIFICIL_SSH["limpio"][k] for k in claves]

    x = np.arange(len(vistas))
    an = 0.36
    fig, ax = nueva(ANCHO_COMPLETO, 3.0)
    b1 = ax.bar(x - an / 2, cont, an, color=APAGADO,
                label="Benigno contaminado (78.6 % era el propio atacante)")
    b2 = ax.bar(x + an / 2, limp, an, color=NARANJA,
                label="Benigno genuino (solo IPs de terceros)")
    etiquetar_barras_v(ax, b1, cont, fmt="{:.3f}", dy=0.012)
    etiquetar_barras_v(ax, b2, limp, fmt="{:.3f}", dy=0.012)

    ax.set_xticks(x, vistas)
    ax.set_ylim(0, 1.16)
    ax.set_ylabel("accuracy (5-Fold CV)")
    limpiar_ejes(ax)
    linea_azar(ax, 0.5)
    leyenda_abajo(ax, ncols=1, dy=-0.16)

    titulo(ax, "El 'techo' de los metadatos era un error de etiquetado",
           "Comparadas contra el benigno contaminado, las tres vistas rozan el azar y parece que el "
           "problema es la vista. Con el benigno genuino, las tres separan— y la conductual llega a 1.000.")
    nota(fig, "Balanceo 1:1 dentro del servicio SSH, MLP 256->128, 5-Fold CV + test held-out. "
              "El benigno contaminado son 2.022 flujos del puerto 22, de los que 1.589 eran del atacante "
              "13.58.98.64 fuera de ventana. Fuente: models/phase2_by_service_rich.md.")
    guardar(fig, "F14_benigno_contaminado")


# --------------------------------------------------------------------- F15
def f15_composicion_benigno() -> None:
    """De que estaba hecho el 'tráfico benigno' en los dos días donde el
    limite de ventana estaba mal fijado. El mismo error, dos veces.
    """
    casos = [("SSH-Bruteforce\n(14-02)", R.CONTAMINACION_SSH),
             ("DoS-Hulk\n(16-02)", R.CONTAMINACION_DOS)]

    fig, ax = nueva(ANCHO_COMPLETO, 2.3)
    y = np.arange(len(casos))
    alto = 0.42
    for i, (nombre, comp) in enumerate(casos):
        # ERRATA (15-sep): esto era sum(comp.values()), que suma tambien las
        # claves que NO son partes -CONTAMINACION_SSH lleva un "total" y
        # CONTAMINACION_DOS una "fraccion_contaminada"-. En el SSH duplicaba el
        # denominador: sacaba 39.3 % + 10.7 % = 50 % en una barra apilada que
        # debe sumar 100. Lo correcto es 78.6 % + 21.4 %.
        atk = comp["del atacante (fuera de ventana)"]
        gen = comp["de terceros (genuino)"]
        total = atk + gen
        ax.barh(i, atk / total, alto, color=CRITICO,
                label="En realidad era el atacante" if i == 0 else None)
        ax.barh(i, gen / total, alto, left=atk / total, color=AZUL,
                label="Benigno genuino (terceros)" if i == 0 else None)
        ax.text(atk / total / 2, i, f"{atk/total:.1%}\n({miles(atk)} flujos)",
                ha="center", va="center", fontsize=7.5, color="#ffffff",
                fontweight="bold", linespacing=1.3)
        ax.text(atk / total + gen / total / 2, i, f"{gen/total:.1%}\n({miles(gen)})",
                ha="center", va="center", fontsize=7.5, color="#ffffff",
                fontweight="bold", linespacing=1.3)

    ax.set_yticks(y, [c[0] for c in casos], fontsize=8)
    ax.set_xlim(0, 1)
    ax.set_xticks([])
    ax.invert_yaxis()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    leyenda_abajo(ax, ncols=2, dy=-0.10)

    titulo(ax, "El mismo error de etiquetado, dos veces",
           "Composicion real del conjunto 'benigno' del servicio atacado antes de corregir la ventana. "
           "La ventana documentada terminaba antes de que el atacante dejara de actuar, asi que su "
           "propia cola quedaba etiquetada como tráfico legitimo.")
    nota(fig, "Verificado sobre el dataset completo: en ambos casos la actividad del atacante es continua "
              "(gap máximo 1 s en SSH, 0.2 s en DoS) y se extiende más alla del fin de ventana documentado. "
              "Corregido en scripts/zeek/attack_metadata.py y re-etiquetado con relabel_dataset.py.")
    guardar(fig, "F15_composicion_benigno")


def generar_todo() -> None:
    print("Bloque 3 - Honestidad metodologica")
    f11_fase1_robustez()
    f12_espejismo()
    f13_balanceo_global()
    f14_benigno_contaminado()
    f15_composicion_benigno()


if __name__ == "__main__":
    generar_todo()

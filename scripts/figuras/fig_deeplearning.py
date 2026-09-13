#!/usr/bin/env python
"""Bloque 5 - Deep learning sobre bytes (Fase 3, ejes A / B / D).

F21 dl_modelos        byte-CNN frente a LSTM y a los baselines shallow
F22 multitipo_web     El tipo de ataque vive en la secuencia, no en el histograma
F23 hibrido_ramas     Fusion tardia de dos ramas vs concatenacion ingenua
F24 saliency          Donde mira el CNN: el banner, no el contenido cifrado
F25 banners           Los bytes reales: un cliente fijo frente a clientes diversos
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AQUA, AZUL, CRITICO, DIR_CACHE, NARANJA,  # noqa: E402
                    REJILLA, TINTA, TINTA_2, ANCHO_COMPLETO, envolver,
                    etiquetar_barras_h, etiquetar_barras_v, guardar,
                    leyenda_abajo, limpiar_ejes, linea_azar, nota, nueva,
                    titulo, titulo_figura)


# --------------------------------------------------------------------- F21
def f21_dl_modelos() -> None:
    """Eje A: modelos profundos sobre la secuencia de bytes frente a los
    baselines de la Fase 2, todos sobre la MISMA particion.

    El byte-CNN gana o empata en las tres tareas; el LSTM se desploma en la
    tarea multiclase con clases muy pequenas (SQLi, 19 flujos).
    """
    tareas = list(R.DL_EJE_A)
    modelos = ["byte-CNN", "byte-LSTM", "mlp-seq", "mlp-hist", "metadatos"]

    # Forma: small multiples horizontales. Con 5 modelos x 3 tareas, un
    # agrupado vertical amontona 15 etiquetas; en horizontal cada barra tiene
    # su valor al lado sin colisiones. Emfasis: el byte-CNN en color, el
    # resto en gris (lo que se compara es "el CNN contra los demas").
    fig, axes = nueva(ANCHO_COMPLETO, 2.6, ncols=len(tareas), sharex=True)
    axes = np.atleast_1d(axes)

    for ax, tarea in zip(axes, tareas):
        vals = [R.DL_EJE_A[tarea][m] for m in modelos]
        colores = [AZUL if m == "byte-CNN" else APAGADO for m in modelos]
        b = ax.barh(range(len(modelos)), vals, color=colores, height=0.6)
        etiquetar_barras_h(ax, b, vals, fmt="{:.3f}", dx=0.015,
                           negrita=[m == "byte-CNN" for m in modelos])
        ax.set_yticks(range(len(modelos)), modelos, fontsize=7.5)
        ax.set_xlim(0, 1.32)
        ax.set_xticks([0, 0.5, 1.0], ["0", "0.5", "1"])
        ax.invert_yaxis()
        limpiar_ejes(ax, rejilla="x")
        ax.set_title(envolver(tarea, 20), loc="left", fontsize=8.5, color=TINTA)
        if ax is not axes[0]:
            ax.set_yticklabels([])

    # El 0.486 del LSTM habla por si solo junto al 0.968 del CNN; una flecha
    # aqui solo chocaria con las etiquetas de las barras vecinas.
    axes[1].set_xlabel("macro-F1 (out-of-fold)")

    titulo_figura(
        fig, "El byte-CNN es el modelo más fuerte sobre la secuencia de bytes",
        "La convolucion multi-kernel aprende n-gramas de bytes (los tokens del ataque). En binario "
        "casi todo empata; la diferencia aparece al identificar el TIPO de ataque, donde el LSTM se "
        "hunde y los baselines shallow se quedan atras.",
        top=0.76)
    nota(fig, "Predicciones out-of-fold (5-Fold estratificado) sobre la misma particion para los cinco modelos. "
              "PyTorch en CPU. Fuente: models/phase2_dl_<día>_<tarea>.md (scripts/zeek/train_dl_payload.py). "
              "El día DoS se excluye: sus cifras del 15-jul quedaron invalidadas por el re-etiquetado del 11-ago.",
         y=-0.05)
    guardar(fig, "F21_dl_modelos", apretar=False)


# --------------------------------------------------------------------- F22
def f22_multitipo_web() -> None:
    """Para identificar el TIPO de ataque no basta con que el payload este en
    claro: hace falta la representacion adecuada. El histograma difumina los
    tokens (`<script>` y `union select` tienen distribuciones de bytes
    parecidas); solo la secuencia los conserva.
    """
    vistas = ["payload-hist", "payload-seq", "metadatos"]
    macro = [R.MULTITIPO_WEB[v] for v in vistas]
    sqli = [R.MULTITIPO_WEB_RECALL_SQLI[v] for v in vistas]

    x = np.arange(len(vistas))
    an = 0.34
    fig, ax = nueva(ANCHO_COMPLETO, 3.0)
    b1 = ax.bar(x - an / 2, macro, an, color=APAGADO, label="macro-F1 (3 clases)")
    b2 = ax.bar(x + an / 2, sqli, an, color=AZUL,
                label="recall de SQL Injection (19 flujos)")
    etiquetar_barras_v(ax, b1, macro, fmt="{:.3f}", dy=0.012)
    etiquetar_barras_v(ax, b2, sqli, fmt="{:.3f}", dy=0.012)

    ax.set_xticks(x, ["payload\nhistograma", "payload\nsecuencia", "metadatos\nde flujo"])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("puntuacion")
    limpiar_ejes(ax)
    leyenda_abajo(ax, ncols=2, dy=-0.17)

    titulo(ax, "El tipo de ataque vive en la secuencia, no en el histograma",
           "Clasificacion de los 203 flujos de ataque web en sus tres tipos. El histograma y los "
           "metadatos aciertan el tipo mayoritario pero fallan la inyeccion SQL: solo la secuencia "
           "de bytes conserva los tokens que la identifican.")
    nota(fig, "Predicciones out-of-fold (5-Fold estratificado). Clases: 142 Brute Force -Web, 42 XSS, "
              "19 SQL Injection. Fuente: models/phase2_multitype_web.md (scripts/zeek/multitype_web.py).")
    guardar(fig, "F22_multitipo_web")


# --------------------------------------------------------------------- F23
def f23_hibrido_ramas() -> None:
    """Eje B: la fusion importa tanto como las vistas.

    Concatenar las features crudas (fusion ingenua) DILUYE los pocos escalares
    utiles entre cientos de dimensiones de payload. Entrenar una rama por
    vista y fusionar los embeddings evita esa dilucion.
    """
    tareas = list(R.HIBRIDO)
    modelos = ["solo-payload (byte-CNN)", "solo-metadatos (MLP)",
               "fusion ingenua (concat)", "hibrido 2 ramas"]
    colores = [AZUL, NARANJA, APAGADO, AQUA]

    x = np.arange(len(tareas))
    an = 0.19
    fig, ax = nueva(ANCHO_COMPLETO, 3.1)
    for i, (m, c) in enumerate(zip(modelos, colores)):
        vals = [R.HIBRIDO[t][m] for t in tareas]
        desp = (i - (len(modelos) - 1) / 2) * an
        b = ax.bar(x + desp, vals, an * 0.9, color=c, label=m)
        # Etiquetado SELECTIVO. En la tarea binaria del SSH los cuatro valores
        # son ~1.0 y sus etiquetas se pisarian; lo que hay que comparar es la
        # fusion ingenua contra el hibrido, asi que solo se rotulan esas dos.
        # (El hibrido va en aqua, que exige etiqueta directa por contraste.)
        if m in ("hibrido 2 ramas", "fusion ingenua (concat)"):
            etiquetar_barras_v(ax, b, vals, fmt="{:.3f}", dy=0.008,
                               negrita=[m == "hibrido 2 ramas"] * len(vals))

    ax.set_xticks(x, [envolver(t, 22) for t in tareas], fontsize=8)
    ax.set_ylim(0.70, 1.06)
    ax.set_ylabel("macro-F1 (out-of-fold)")
    limpiar_ejes(ax)
    leyenda_abajo(ax, ncols=2, dy=-0.20)

    titulo(ax, "La fusion bien hecha es robusta en los dos regimenes",
           "Cada vista suelta gana en su regimen y pierde en el otro. La fusion ingenua (concatenar "
           "features crudas) queda por debajo en las tres tareas; el hibrido de dos ramas con fusion "
           "tardia se mantiene arriba en todas.")
    nota(fig, "Predicciones out-of-fold (5-Fold estratificado). El hibrido entrena una rama CNN sobre el payload "
              "y una MLP sobre los metadatos, y fusiona los embeddings antes del clasificador. "
              "Fuente: models/phase2_dlhybrid_*.md (scripts/zeek/train_dl_hybrid.py).")
    guardar(fig, "F23_hibrido_ramas")


# --------------------------------------------------------------------- F24
def f24_saliency() -> None:
    """Eje D: interpretabilidad. El CNN separa el SSH cifrado casi perfecto,
    pero la saliency muestra que decide con la cabecera EN CLARO del
    handshake, no con el cuerpo cifrado.
    """
    frac_pos = 48 / 256          # porcion de las posiciones
    frac_imp = R.SALIENCY["fraccion_importancia_primeros_48B"]

    fig, ax = nueva(ANCHO_COMPLETO, 2.4)
    categorias = ["Primeros 48 bytes\n(banner del handshake, en claro)",
                  "Bytes 48-256\n(cuerpo cifrado)"]
    posiciones = [frac_pos, 1 - frac_pos]
    importancia = [frac_imp, 1 - frac_imp]

    y = np.arange(2)
    alto = 0.34
    b1 = ax.barh(y - alto / 2, posiciones, alto, color=APAGADO,
                 label="% de las posiciones del flujo")
    b2 = ax.barh(y + alto / 2, importancia, alto, color=AZUL,
                 label="% de la importancia (saliency)")
    etiquetar_barras_h(ax, b1, posiciones, fmt="{:.1%}", dx=0.008, color=TINTA_2)
    etiquetar_barras_h(ax, b2, importancia, fmt="{:.1%}", dx=0.008, color=AZUL,
                       negrita=[True, False])

    ax.set_yticks(y, categorias, fontsize=8)
    ax.set_xlim(0, 1.05)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0 %", "25 %", "50 %", "75 %", "100 %"])
    ax.invert_yaxis()
    limpiar_ejes(ax, rejilla="x")
    leyenda_abajo(ax, ncols=2, dy=-0.22)

    titulo(ax, "El modelo no lee el cifrado: lee la cabecera en claro",
           "El 18.8 % inicial del flujo concentra el 31.1 % de la importancia. Es la zona del banner "
           "SSH, que viaja en claro antes de negociar el cifrado: la senal es real, pero es la huella "
           "del cliente del atacante, no una propiedad del ataque.")
    nota(fig, "Saliency = |gradiente| de la salida respecto a la entrada, promediado sobre los flujos de ataque. "
              "Entropía media de ambas clases ~7.4 bits/byte (indistinguibles a nivel de contenido). "
              "Fuente: models/phase2_saliency_ssh.md (scripts/zeek/eval_saliency.py).")
    guardar(fig, "F24_saliency")


# --------------------------------------------------------------------- F25
def f25_banners() -> None:
    """Los bytes reales que decide el modelo, tal cual salen del dataset.

    A la izquierda, flujos del atacante: siempre el mismo cliente. A la
    derecha, flujos legitimos: clientes variados. Esta figura es la prueba
    visual de que la senal es un *fingerprint* de herramienta.
    """
    ruta = DIR_CACHE / "bytes_14-02.npz"
    if not ruta.exists():
        print("  [skip] F25: falta cache de bytes (ejecuta extraer_datos.py)")
        return
    z = np.load(ruta)

    def texto(fila, n=42) -> str:
        """Bytes a texto imprimible; lo no imprimible como punto medio."""
        return "".join(chr(b) if 32 <= b < 127 else "·" for b in fila[:n])

    def unicos(seqs, n=7, primero=None):
        """Muestras distintas; `primero` sube al principio las que contienen
        esa subcadena (el flujo puede empezar por el banner del cliente o por
        el del servidor, segun quien hable antes en la captura)."""
        vistos, salida = set(), []
        for fila in seqs:
            t = texto(fila)
            if t not in vistos:
                vistos.add(t)
                salida.append(t)
        if primero:
            salida.sort(key=lambda t: primero not in t)
        return salida[:n]

    atk = unicos(z["seq_ataque"], primero="paramiko")
    ben = unicos(z["seq_benigno"])

    fig, ax = nueva(ANCHO_COMPLETO, 2.9)
    ax.axis("off")
    n = max(len(atk), len(ben))

    for col, (titulo_col, muestras, color) in enumerate(
            [("Flujos del ATACANTE", atk, NARANJA),
             ("Flujos BENIGNOS (terceros)", ben, AZUL)]):
        x = 0.02 + col * 0.51
        ax.text(x, 1.0, titulo_col, transform=ax.transAxes, fontsize=8.5,
                fontweight="bold", color=color, va="top")
        for i, t in enumerate(muestras):
            ax.text(x, 0.87 - i * 0.115, t, transform=ax.transAxes,
                    fontsize=6.6, family="monospace", color=TINTA, va="top")
        # El hueco de la columna del atacante ES el dato: no hay mas variedad.
        if col == 0 and len(muestras) < n:
            ax.text(x, 0.87 - len(muestras) * 0.115 - 0.02,
                    "(no hay más: el atacante repite\nsiempre el mismo cliente)",
                    transform=ax.transAxes, fontsize=7, color=TINTA_2,
                    style="italic", va="top", linespacing=1.4)
        ax.text(x, 0.87 - n * 0.115 - 0.06,
                f"{R.SALIENCY['n_banners_ataque']} banners distintos en todo el ataque"
                if col == 0 else
                f"{R.SALIENCY['n_banners_benignos']} banners distintos en el tráfico legitimo",
                transform=ax.transAxes, fontsize=7.5, color=color,
                fontweight="bold", va="top")

    ax.plot([0.495, 0.495], [0.02, 1.02], transform=ax.transAxes,
            color=REJILLA, lw=1)

    titulo(ax, "La 'senal' del payload en SSH es un unico cliente",
           "Primeros 42 bytes de conexiones reales del dataset (los no imprimibles se muestran como ·). "
           "El atacante usa siempre paramiko; el tráfico legitimo trae PuTTY, libssh2, OpenSSH... "
           "Falsear el banner anula la detección, y eso es exactamente lo que mide el Hallazgo 11.")
    nota(fig, "Muestras tomadas de dataset_Wednesday-14-02-2018.npz (X_seq, servicio SSH), benigno solo de "
              "IPs de terceros. Recuento de banners distintos: models/phase2_by_service_rich.md.")
    guardar(fig, "F25_banners")


def generar_todo() -> None:
    print("Bloque 5 - Deep learning")
    f21_dl_modelos()
    f22_multitipo_web()
    f23_hibrido_ramas()
    f24_saliency()
    f25_banners()


if __name__ == "__main__":
    generar_todo()

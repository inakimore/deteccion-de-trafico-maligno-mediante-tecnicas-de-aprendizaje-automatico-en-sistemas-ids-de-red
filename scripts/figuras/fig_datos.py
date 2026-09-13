#!/usr/bin/env python
"""Bloque 1 - Los datos: que hay dentro del dataset y como se etiqueto.

F06 composicion_clases   El desbalanceo real: 203 ataques entre 2.7 M de flujos
F07 servicios_por_dia    Que protocolos hay en cada día, identificados por contenido
F08 servicio_vs_puerto   Lo que la seleccion por puerto se dejaba fuera
F09 error_ventana        Actividad del atacante frente a la ventana etiquetada
F10 volumen_procesado    Escala del trabajo: capturas, GB y flujos
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (AMARILLO, APAGADO, AQUA, AZUL, CRITICO, DIR_CACHE,  # noqa: E402
                    MAGENTA, NARANJA, TINTA, TINTA_2, VIOLETA, ANCHO_COMPLETO,
                    envolver, etiquetar_barras_h, guardar, leyenda_abajo, limpiar_ejes, miles,
                    nota, nueva, titulo, titulo_figura)


def _hhmm(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M")


# --------------------------------------------------------------------- F06
def f06_composicion_clases() -> None:
    """El desbalanceo con el que hay que lidiar. En el día web hay 203 flujos
    de ataque entre 2.7 millones: una parte en 13.684. Cualquier accuracy
    global sobre datos sin balancear es, por construccion, un numero vacio.
    """
    dias = ["Wednesday-14-02-2018", "Thursday-22-02-2018", "Friday-16-02-2018"]
    cortos = {"Wednesday-14-02-2018": "SSH-Bruteforce",
              "Thursday-22-02-2018": "Web BF/XSS/SQLi",
              "Friday-16-02-2018": "DoS-Hulk"}
    nombres, benignos, ataques, etiquetas_atk = [], [], [], []
    for d in dias:
        inf = R.DIAS[d]
        nombres.append(f"{inf['corto']}\n{cortos[d]}")
        ataques.append(inf["flujos_ataque"])
        benignos.append(inf["flujos_total"] - inf["flujos_ataque"])
        prop = inf["flujos_total"] / inf["flujos_ataque"]
        etiquetas_atk.append(
            f"{miles(inf['flujos_ataque'])}\n(1 de cada {miles(prop)})")

    y = np.arange(len(dias))
    alto = 0.38
    fig, ax = nueva(ANCHO_COMPLETO, 2.8)
    b1 = ax.barh(y - alto / 2, benignos, alto, color=AZUL, label="Benigno")
    b2 = ax.barh(y + alto / 2, ataques, alto, color=NARANJA, label="Ataque")
    ax.set_xscale("log")

    for barra, val in zip(b1, benignos):
        ax.text(val * 1.15, barra.get_y() + barra.get_height() / 2, miles(val),
                va="center", fontsize=7.5, color=TINTA_2)
    for barra, txt in zip(b2, etiquetas_atk):
        ax.text(barra.get_width() * 1.15, barra.get_y() + barra.get_height() / 2,
                txt, va="center", fontsize=7.5, color=NARANJA,
                fontweight="bold", linespacing=1.3)

    ax.set_yticks(y, nombres, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlim(50, 5e8)
    ax.set_xlabel("flujos TCP con payload (escala logaritmica)")
    limpiar_ejes(ax, rejilla="x")
    leyenda_abajo(ax, ncols=2, dy=-0.20)

    titulo(ax, "El desbalanceo real del dataset",
           "Numero de conexiones TCP con payload por día y clase. El ataque web es tres ordenes de "
           "magnitud más raro que el volumétrico: la misma metrica no significa lo mismo en los dos.")
    nota(fig, "Recuento sobre los dataset_<día>.npz ya vectorizados, tras las correcciones de etiquetado "
              "de junio y agosto. Cada flujo es una conexión TCP identificada por el uid de Zeek.")
    guardar(fig, "F06_composicion_clases")


# --------------------------------------------------------------------- F07
def f07_servicios_por_dia() -> None:
    """Composicion de protocolos de cada día, identificados por el CONTENIDO
    (no por el puerto). Justifica por que el balanceo global era enganoso: el
    servicio atacado es una fraccion minuscula del tráfico total.
    """
    dias = list(R.SERVICIOS_POR_DIA)
    servicios = ["http", "rdp", "ssl", "smb", "ssh", "other"]
    colores = {"http": AZUL, "rdp": NARANJA, "ssl": AQUA, "smb": AMARILLO,
               "ssh": VIOLETA, "other": APAGADO}

    fig, ax = nueva(ANCHO_COMPLETO, 2.5)
    izq = np.zeros(len(dias))
    for s in servicios:
        vals = np.array([R.SERVICIOS_POR_DIA[d].get(s, 0.0) for d in dias])
        ax.barh(dias, vals, left=izq, color=colores[s], height=0.5, label=s)
        for i, (v, l) in enumerate(zip(vals, izq)):
            if v >= 6:      # solo se etiqueta lo que cabe
                ax.text(l + v / 2, i, f"{s}\n{v:.0f} %", ha="center", va="center",
                        fontsize=7, color="#ffffff", fontweight="bold",
                        linespacing=1.2)
        izq += vals

    ax.set_xlim(0, 100)
    ax.set_xlabel("% de los flujos del día")
    ax.invert_yaxis()
    limpiar_ejes(ax, rejilla="x")
    leyenda_abajo(ax, ncols=6, dy=-0.24)

    titulo(ax, "El servicio atacado es una minoria del tráfico del día",
           "Servicios identificados por las firmas de contenido de Zeek. El SSH del 14-02 es el 4.3 % "
           "de los flujos y el HTTP atacado del 22-02 el 16.6 %: por eso un balanceo global por clase "
           "acaba midiendo la separacion entre protocolos y no la detección del ataque.")
    nota(fig, "Fuente: models/phase3_service_id_<día>.md (scripts/zeek/service_id.py). Identificacion por "
              "banner SSH, metodos HTTP, record TLS, NBSS/SMB, TPKT/X.224 de RDP y saludos SMTP/FTP/POP3/IMAP.")
    guardar(fig, "F07_servicios_por_dia")


# --------------------------------------------------------------------- F08
def f08_servicio_vs_puerto() -> None:
    """Correccion del tutor: el puerto no puede definir el servicio.

    En un laboratorio controlado puerto y contenido coinciden al 99.9 %, asi
    que ningun resultado previo cambia. Lo que la figura muestra es el
    tamano del desacuerdo — pequeno aquí, pero no en una red real.
    """
    dias = list(R.SERVICIO_VS_PUERTO)
    contra = [R.SERVICIO_VS_PUERTO[d][2] for d in dias]
    pct = [100 * R.SERVICIO_VS_PUERTO[d][1] / R.SERVICIO_VS_PUERTO[d][0]
           for d in dias]

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 2.9, ncols=2,
                            gridspec_kw={"width_ratios": [1.1, 1]})

    b = ax1.barh(range(len(dias)), pct, color=AZUL, height=0.55)
    etiquetar_barras_h(ax1, b, pct, fmt="{:.2f} %", dx=0.05, color="#ffffff",
                       dentro=True)
    ax1.set_yticks(range(len(dias)), dias, fontsize=7.5)
    ax1.set_xlim(99.0, 100.0)
    ax1.set_xticks([99.0, 99.5, 100.0], ["99.0", "99.5", "100"])
    ax1.invert_yaxis()
    limpiar_ejes(ax1, rejilla="x")
    # Etiquetas cortas: a dos paneles, las largas se tocan en el centro.
    ax1.set_xlabel("% que el contenido confirma")
    ax1.set_title("En laboratorio, coinciden", loc="left", fontsize=8.5,
                  color=TINTA, pad=14)
    ax1.text(0.0, 1.01, "por eso ningun resultado previo cambia",
             transform=ax1.transAxes, fontsize=7, color=TINTA_2,
             style="italic", va="bottom")

    b2 = ax2.barh(range(len(dias)), contra, color=NARANJA, height=0.55)
    # Separador de miles en espanol (punto), no el de matplotlib (coma).
    for barra, v in zip(b2, contra):
        ax2.text(barra.get_width() + 20, barra.get_y() + barra.get_height() / 2,
                 f"{v:,}".replace(",", "."), va="center", ha="left",
                 fontsize=8, color=TINTA)
    ax2.set_yticks(range(len(dias)), [""] * len(dias))
    ax2.set_xlim(0, max(contra) * 1.35)
    ax2.invert_yaxis()
    limpiar_ejes(ax2, rejilla="x")
    ax2.set_xlabel("flujos que lo contradicen")
    ax2.set_title("Pero no siempre", loc="left", fontsize=8.5, color=TINTA, pad=14)
    ax2.text(0.0, 1.01, "en una red real, esto dejaria de ser marginal",
             transform=ax2.transAxes, fontsize=7, color=NARANJA,
             style="italic", va="bottom")

    titulo_figura(
        fig, "El servicio se identifica por el contenido, no por el puerto",
        "El puerto, como la IP, depende de la configuracion de cada red: no es un atributo "
        "independiente del contexto. Un modelo que lo use no generaliza a una red donde los "
        "servicios escuchen en otros puertos.",
        top=0.74)
    nota(fig, "Fuente: models/phase3_service_id_<día>.md. Ejemplos concretos del desacuerdo: 99 flujos HTTP "
              "fuera del puerto 80 el 22-02, y 75 flujos del puerto 22 que no son SSH el 14-02 (que salen "
              "del conjunto benigno: 433 -> 358).", y=-0.05)
    guardar(fig, "F08_servicio_vs_puerto", apretar=False)


# --------------------------------------------------------------------- F09
def f09_error_ventana() -> None:
    """LA figura de la leccion metodologica.

    Se dibuja la actividad real del atacante minuto a minuto y encima el
    limite de la ventana documentada. Se ve que el atacante seguia actuando
    despues del corte, y que todo ese tramo quedaba etiquetado como benigno.
    """
    casos = [("14-02", "SSH-Bruteforce (14-02)", "SSH-Bruteforce"),
             ("16-02", "DoS-Hulk (16-02)", "DoS-Hulk")]
    disponibles = [(d, k, n) for d, k, n in casos
                   if (DIR_CACHE / f"timeline_{d}.npz").exists()]
    if not disponibles:
        print("  [skip] F09: falta cache de timeline")
        return

    fig, axes = nueva(ANCHO_COMPLETO, 3.4, nrows=len(disponibles))
    axes = np.atleast_1d(axes)

    for ax, (dia, clave, nombre) in zip(axes, disponibles):
        z = np.load(DIR_CACHE / f"timeline_{dia}.npz")
        bordes, cuenta, cuenta_mal = z["bordes"], z["cuenta"], z["cuenta_mal"]
        centros = (bordes[:-1] + bordes[1:]) / 2
        t_corte = float(z["t_ventana_fin_orig"])
        t_corr = float(z["t_ventana_fin_corr"])
        n_mal = int(z["flujos_reetiquetados"])

        # El dataset en disco YA esta corregido, asi que `cuenta_mal` es cero:
        # para ilustrar el error hay que reconstruir lo que caia fuera de la
        # ventana original, que es exactamente la cola posterior al corte.
        cuenta_antes = np.where(centros > t_corte, cuenta, 0)

        ax.fill_between(centros, cuenta, step="mid", color=AZUL, alpha=0.9,
                        label="Flujos del atacante")
        ax.fill_between(centros, cuenta_antes, step="mid", color=CRITICO,
                        label="Quedaban etiquetados como BENIGNO (antes de corregir)")

        ax.axvline(t_corte, color=TINTA, lw=1.4, ls="--")
        ax.annotate(f"fin de ventana\ndocumentado\n{_hhmm(t_corte)}",
                    xy=(t_corte, ax.get_ylim()[1] * 0.98),
                    xytext=(-6, 0), textcoords="offset points",
                    ha="right", va="top", fontsize=7, color=TINTA,
                    fontweight="bold", linespacing=1.3)
        ax.axvline(t_corr, color=AQUA, lw=1.4, ls=":")
        ax.annotate(f"corregido a\n{_hhmm(t_corr)}",
                    xy=(t_corr, ax.get_ylim()[1] * 0.98),
                    xytext=(6, 0), textcoords="offset points",
                    ha="left", va="top", fontsize=7, color="#0f7a55",
                    fontweight="bold", linespacing=1.3)

        # eje x en horas:minutos UTC
        ticks = np.linspace(bordes[0], bordes[-1], 7)
        ax.set_xticks(ticks, [_hhmm(t) for t in ticks])
        ax.set_ylabel("flujos / 10 s")
        limpiar_ejes(ax, rejilla="y")
        ax.set_title(f"{nombre}: {miles(n_mal)} flujos mal etiquetados",
                     loc="left", fontsize=8.5, color=TINTA)

    axes[-1].set_xlabel("hora UTC")
    manejadores, etiquetas = axes[0].get_legend_handles_labels()
    fig.legend(manejadores, etiquetas, loc="upper right", ncols=1,
               bbox_to_anchor=(1.0, 0.855), fontsize=7.5)

    titulo_figura(
        fig, "El atacante seguia actuando despues del fin de ventana documentado",
        "Actividad del atacante sobre el servicio atacado, en tramos de 10 s. Todo lo que queda a la "
        "derecha del corte se etiquetaba como tráfico legitimo, contaminando el conjunto benigno con "
        "el propio ataque. Ocurrio en dos días distintos.",
        top=0.80)
    nota(fig, "Verificado sobre el dataset completo (no sobre una sola captura): la actividad del atacante "
              "es continua, con gap máximo de 1 s en SSH y 0.2 s en DoS. Corregido en attack_metadata.py "
              "y re-etiquetado con relabel_dataset.py sin reprocesar los PCAP.", y=-0.03)
    guardar(fig, "F09_error_ventana", apretar=False)


# --------------------------------------------------------------------- F10
def f10_volumen_procesado() -> None:
    """Escala del trabajo, en forma de fichas: son cifras sueltas, no una
    serie, asi que un grafico de barras seria peor que unos numeros grandes.
    """
    fichas = [
        ("6", "días procesados", "3 de CSE-CIC-IDS2018 + 3 de CIC-IDS2017"),
        ("~150 GB", "de capturas PCAP", "saneadas y procesadas con Zeek en Docker"),
        ("9.4 M", "flujos TCP vectorizados", "histograma, entropía y secuencia por conexión"),
        ("3", "regimenes de firma", "cifrado, en claro y volumétrico"),
    ]
    fig, ax = nueva(ANCHO_COMPLETO, 1.7)
    ax.axis("off")
    # Cada ficha ocupa 1/4 del ancho (~1,5 pulgadas): el texto se envuelve a
    # esa medida o invade la columna siguiente.
    for i, (valor, etiqueta, pie) in enumerate(fichas):
        x = i / len(fichas) + 0.010
        ax.text(x, 0.92, valor, fontsize=17, fontweight="bold", color=AZUL,
                transform=ax.transAxes, va="top", ha="left")
        ax.text(x, 0.55, envolver(etiqueta, 22), fontsize=8, color=TINTA,
                transform=ax.transAxes, va="top", ha="left", fontweight="bold",
                linespacing=1.3)
        ax.text(x, 0.28, envolver(pie, 27), fontsize=6.5, color=TINTA_2,
                transform=ax.transAxes, va="top", ha="left", linespacing=1.45)
        if i:   # separador vertical entre fichas
            ax.plot([i / len(fichas) - 0.008] * 2, [0.05, 0.95],
                    transform=ax.transAxes, color="#e1e0d9", lw=1)

    titulo(ax, "Escala del trabajo experimental", None)
    nota(fig, "Los PCAP y TSV intermedios se borran tras vectorizar cada día (son re-derivables desde S3); "
              "se conservan los dataset_<día>.npz autocontenidos, 5.4 GB en total.", y=0.02)
    guardar(fig, "F10_volumen_procesado")


def generar_todo() -> None:
    print("Bloque 1 - Los datos")
    f06_composicion_clases()
    f07_servicios_por_dia()
    f08_servicio_vs_puerto()
    f09_error_ventana()
    f10_volumen_procesado()


if __name__ == "__main__":
    generar_todo()

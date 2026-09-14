#!/usr/bin/env python
"""Bloque 8 - Generalizacion entre días y los limites del enfoque (19-22 agosto).

F33 cruzado_entre_dias     El byte-CNN es fragil: transfiere del todo o nada
F34 perfiles_temporales    Beaconing del Bot frente a los floods (Hallazgo 15)
F35 ceguera_infiltracion   El 94.4% del ataque no tiene payload (Hallazgo 16)
F36 rafaga_diluida         El contraste de ráfaga cae 3 ordenes de magnitud
F37 interarribo_beacon     El beacon MEDIDO: dos modas contra una curva suave
F38 calibracion_cruzada    El colapso del byte-CNN es de UMBRAL, no de saber
F39 evasion_interarribo    Que vista sobrevive al camuflaje de los bytes
F40 fuga_ips               La fuga de IPs sobrevive al cruzado entre días
F41 recalibracion          Recalibrar cuesta 25 etiquetas del día nuevo
F42 arquitecturas          Lo nuestro vs el SOTA, a igualdad de presupuesto

Las cuatro salen de `resultados.py` salvo F34, que usa `figuras/cache/perfil_*.npz`
(lo produce `extraer_datos.py`). Ninguna calcula nada nuevo.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import (APAGADO, AQUA, AZUL, CRITICO, DIR_CACHE, NARANJA,  # noqa: E402
                    RAMPA_AZUL, REJILLA, TINTA, TINTA_2, ANCHO_COMPLETO,
                    etiquetar_barras_v, guardar, leyenda_abajo, limpiar_ejes,
                    linea_azar, miles, nota, nueva, titulo, titulo_figura)


# --------------------------------------------------------------------- F33
def f33_cruzado_entre_dias() -> None:
    """La figura del HALLAZGO 14. Seis pares dirigidos x tres vistas.

    Forma: heatmap, porque lo que hay que ver de un vistazo NO son los valores
    sueltos sino la TEXTURA de cada columna: la del byte-CNN es bimodal (o casi
    negro o el gris del 0.5) y la del histograma es un degradado. El contraste
    binario-frente-a-continuo ES el hallazgo, y una tabla de numeros lo esconde.
    """
    pares = list(R.CRUZADO_DIAS)
    vistas = ["payload-hist", "metadatos", "byte-CNN"]
    M = np.array([[R.CRUZADO_DIAS[p][v][0] for v in vistas] for p in pares])
    REC = np.array([[R.CRUZADO_DIAS[p][v][1] for v in vistas] for p in pares])

    fig, ax = nueva(ANCHO_COMPLETO, 3.5)
    from matplotlib.colors import LinearSegmentedColormap
    cmap = LinearSegmentedColormap.from_list("azul", RAMPA_AZUL[:9])
    ax.imshow(M, cmap=cmap, vmin=0.5, vmax=1.0, aspect="auto")

    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v, r = M[i, j], REC[i, j]
            col = "#ffffff" if v >= 0.93 else TINTA
            ax.text(j, i - 0.10, f"{v:.4f}", ha="center", va="center",
                    fontsize=9.5, fontweight="bold", color=col)
            # El recall nulo es lo que convierte un 0.5 en "no detecta NADA".
            if r == 0.0:
                ax.text(j, i + 0.26, "recall 0: no detecta nada", ha="center",
                        va="center", fontsize=6.6, color=CRITICO,
                        fontweight="bold")
            elif r < 0.75:
                ax.text(j, i + 0.26, f"recall {r:.2f}", ha="center", va="center",
                        fontsize=6.6, color=col, style="italic")

    ax.set_xticks(range(len(vistas)),
                  ["Payload\n(histograma)", "Metadatos\nper-flujo",
                   "byte-CNN\n(secuencia)"], fontsize=8)
    ax.set_yticks(range(len(pares)), [p.replace("->", "→") for p in pares],
                  fontsize=8)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    ax.set_xticks(np.arange(-0.5, len(vistas), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(pares), 1), minor=True)
    ax.grid(which="minor", color="#fcfcfb", linewidth=2.5)

    titulo(ax, "El byte-CNN transfiere del todo o nada; el histograma se degrada",
           "Entrenar en un día y testear en OTRO del mismo regimen (los tres días "
           "volumétricos de 2018). El byte-CNN solo toma dos valores -~1.0 o exactamente "
           "0.5 con recall nulo-; el histograma recorre 1.0000 -> 0.7218 sin colapsar.")
    nota(fig, "Accuracy sobre el día de test, balanceo 1:1 en ambos días (0.5 = azar), "
              "seleccion por servicio HTTP, cap 4000 por clase. Fuente: "
              "models/phase2_crossdataset_*_p80.md. El byte-CNN colapsa siempre que el "
              "20-02 (LOIC) esta en un lado y nunca entre 15-02 y 16-02: el patron "
              "sugiere memorizacion de FAMILIA DE HERRAMIENTA (hipotesis no demostrada).")
    guardar(fig, "F33_cruzado_entre_dias")


# --------------------------------------------------------------------- F34
def f34_perfiles_temporales() -> None:
    """La figura del HALLAZGO 15: el beaconing del Bot.

    Honestidad de la figura: el perfil agregado del Bot es plano, pero el del
    DDoS-LOIC TAMBIEN lo es. Lo que separa al beaconing no es la planitud sino
    la ESCALA (17x menos tráfico) sostenida 5.7x más tiempo. Se dibujan los tres
    días juntos, en escala logaritmica, precisamente para que eso se vea y no se
    venda la planitud como si fuera exclusiva del Bot.
    """
    dias = [("16-02", "DoS-Hulk (1 origen)", CRITICO),
            ("20-02", "DDoS-LOIC (10 orígenes)", NARANJA),
            ("02-03", "Bot / Ares (10 bots)", AZUL)]
    datos = {}
    for dia, _, _ in dias:
        f = DIR_CACHE / f"perfil_{dia}.npz"
        if not f.exists():
            print(f"  [salta] F34: falta {f.name} (ejecuta extraer_datos.py)")
            return
        d = np.load(f, allow_pickle=True)
        datos[dia] = (d["minuto_inicio"], d["conteo"])

    fig, ax = nueva(ANCHO_COMPLETO, 3.2)
    for dia, etiqueta, color in dias:
        mins, conteo = datos[dia]
        act = conteo > 0
        ax.plot(mins[act] / 60.0, conteo[act], marker="o", markersize=3.2,
                linewidth=1.6, color=color, label=etiqueta)

    # Anotar la meseta del Bot: es el argumento de la figura.
    mins, conteo = datos["02-03"]
    meseta = conteo[(mins >= 700) & (mins <= 920) & (conteo > 0)]
    meseta = meseta[meseta < 5000]                     # sin los picos de ordenes
    if len(meseta):
        y = float(np.median(meseta))
        ax.annotate(f"meseta plana: {miles(int(y))} flujos/10 min\n"
                    f"constante en +-{int(meseta.max() - meseta.min())} durante ~4 h",
                    xy=(13.0, y), xytext=(13.4, y * 0.16),
                    fontsize=7.2, color=AZUL, ha="left",
                    arrowprops=dict(arrowstyle="->", color=AZUL, lw=1.0))

    ax.set_yscale("log")
    ax.set_xlabel("hora local del día", fontsize=8)
    ax.set_ylabel("flujos de ataque por bloque de 10 min", fontsize=8)
    ax.set_xlim(9.5, 16.5)
    ax.set_xticks(range(10, 17), [f"{h}:00" for h in range(10, 17)], fontsize=8)
    limpiar_ejes(ax, rejilla="y")
    leyenda_abajo(ax, ncols=3, dy=-0.22)

    titulo(ax, "El Bot late; los floods estallan",
           "Perfil temporal del ataque en los tres días. Escala logaritmica: sin ella el "
           "Bot no se ve al lado del Hulk, y esa diferencia de escala es justo el punto.")
    nota(fig, "Flujos etiquetados como ataque por bloque de 10 min, desde los dataset_*.npz "
              "(figuras/cache/perfil_*.npz). MATIZ HONESTO: el perfil del LOIC tambien es "
              "plano, asi que la planitud NO distingue por si sola al beaconing; lo que lo "
              "distingue es mantener una tasa 17 veces menor durante 5.7 veces más tiempo, "
              "con picos puntuales de ordenes (14:20 y 15:30-15:50).")
    guardar(fig, "F34_perfiles_temporales")


# --------------------------------------------------------------------- F35
def f35_ceguera_infiltracion() -> None:
    """La figura del HALLAZGO 16, el resultado NEGATIVO más fuerte del trabajo.

    Dos paneles: cuanto del ataque lleva payload (casi nada) y por que
    (el conn_state dice que son SYN sin respuesta). Es la figura que sostiene
    la tesis desde la EXISTENCIA del dato, no desde la exactitud del modelo.

    El panel izquierdo va en PORCENTAJE, no en valor absoluto: lo que se quiere
    leer es la proporcion, y en absoluto el 5.6% resulta invisible.
    """
    I = R.INFILTRACION_CEGUERA
    tot = I["conexiones_salientes_victima"]
    con, sin = I["con_payload"], I["sin_payload"]
    p_sin, p_con = 100.0 * sin / tot, 100.0 * con / tot

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 3.0, ncols=2,
                            gridspec_kw={"width_ratios": [1.0, 1.15]})

    # --- panel A: proporcion con / sin payload ----------------------------
    ax1.barh([0], [p_sin], color=CRITICO, height=0.42)
    ax1.barh([0], [p_con], left=[p_sin], color=AZUL, height=0.42)
    ax1.text(p_sin / 2, 0, f"SIN payload\n{p_sin:.1f} %\n({miles(sin)} conexiones)",
             ha="center", va="center", fontsize=9, color="#ffffff",
             fontweight="bold", linespacing=1.4)
    ax1.text(100.5, 0, f"con payload\n{p_con:.1f} %\n({miles(con)})",
             ha="left", va="center", fontsize=7.6, color=AZUL, linespacing=1.4)
    ax1.set_xlim(0, 132)
    ax1.set_ylim(-0.5, 0.5)
    ax1.set_yticks([])
    ax1.set_xticks([])
    for sp in ax1.spines.values():
        sp.set_visible(False)
    ax1.grid(False)
    # Los rotulos de panel van DEBAJO: arriba chocan con el subtitulo de figura.
    ax1.set_xlabel(f"de las {miles(tot)} conexiones del escaneo interno",
                   fontsize=8, color=TINTA_2, labelpad=6)

    # --- panel B: por que -> conn_state -----------------------------------
    cs = I["conn_state"]
    nombres = list(cs)
    vals = [cs[k] for k in nombres]
    colores = [CRITICO if k in ("S0", "REJ") else APAGADO for k in nombres]
    ax2.bar(range(len(nombres)), vals, color=colores, width=0.66)
    for i, v in enumerate(vals):
        ax2.text(i, v * 1.25, miles(v), ha="center", va="bottom", fontsize=7.2,
                 color=TINTA)
    ax2.set_xticks(range(len(nombres)), nombres, fontsize=8)
    ax2.set_yscale("log")
    ax2.set_ylim(500, 6e5)
    ax2.set_ylabel("conexiones (escala log)", fontsize=8)
    limpiar_ejes(ax2, rejilla="y")
    # ERRATA (14-sep): en una linea este rotulo sobresale 21 px del panel y
    # "y REJ" se quedaba fuera del recorte. En la memoria entregada se lee
    # "...S0 (SYN sin respuesta)" y ahi se corta.
    ax2.set_xlabel("en rojo, los estados sin diálogo:\nS0 (SYN sin respuesta) y REJ",
                   fontsize=8, color=TINTA_2, labelpad=6)

    titulo_figura(fig, "El payload no detecta peor la Infiltration: no puede verla",
                  "El reconocimiento interno que sigue a la intrusion no transporta "
                  "contenido, asi que no existe el dato sobre el que decidir. Contraste "
                  f"en el mismo día: las {I['c2']['conexiones']} conexiones del canal C2 "
                  f"(puerto {I['c2']['puerto']}) llevan payload el 100 % del tiempo.",
                  top=0.86)
    nota(fig, "Zeek conn.log de la captura del host comprometido 172.31.69.24 "
              "(Wednesday-28-02-2018). Fuente: "
              "models/phase3_infiltration_Wednesday-28-02-2018.md. Este día NO tiene "
              "dataset .npz: no se construyo a proposito, porque solo el 5.6 % del "
              "ataque seria visible y la clase resultante estaria sesgada.")
    guardar(fig, "F35_ceguera_infiltracion")


# --------------------------------------------------------------------- F36
def f36_rafaga_diluida() -> None:
    """Refinamiento del HALLAZGO 8: la ráfaga no resuelve el regimen
    volumétrico, resuelve el regimen volumétrico CONCENTRADO.

    Es la explicacion cuantitativa de por que meta+rafaga gana en el 16-02,
    ayuda en el 15-02 y estorba en el 20-02.
    """
    orden = ["16-02 DoS-Hulk (1 origen)", "14-02 SSH-Bruteforce",
             "15-02 GoldenEye+Slowloris (1+1)", "20-02 DDoS-LOIC (10 origenes)",
             "02-03 Bot (beaconing)", "22-02 Web (BF/XSS/SQLi)"]
    contraste = [R.RAFAGA_MEDIANA[k][2] for k in orden]
    # Etiquetas MUY cortas en tres lineas: con el nombre completo se solapan.
    etiquetas = ["\n".join(t) for t in (
        ("16-02", "DoS-Hulk", "1 origen"),
        ("14-02", "SSH-BF", "1 origen"),
        ("15-02", "GoldenEye", "+Slowloris"),
        ("20-02", "DDoS-LOIC", "10 orígenes"),
        ("02-03", "Bot", "10 bots"),
        ("22-02", "Web", "BF/XSS/SQLi"),
    )]
    colores = [NARANJA] * len(orden)
    colores[-1] = AZUL          # el dia web: alli gana el payload

    fig, ax = nueva(ANCHO_COMPLETO, 3.0)
    b = ax.bar(range(len(orden)), [max(c, 0.6) for c in contraste],
               color=colores, width=0.62)
    for i, c in enumerate(contraste):
        if c:
            ax.text(i, c * 1.25, f"x{miles(c)}", ha="center", va="bottom",
                    fontsize=8.4, fontweight="bold", color=TINTA)
        else:
            # El x0 se escribe ENCIMA de la linea de referencia: dentro de su
            # propia barra queda azul sobre azul, y entre barra y linea no cabe.
            ax.text(i, 1.30, "x0", ha="center", va="bottom", fontsize=8.4,
                    fontweight="bold", color=AZUL)
    ax.axhline(1.0, color=APAGADO, linewidth=1.0, linestyle=(0, (4, 3)))
    ax.text(2.3, 1.30, "sin contraste (ataque = benigno)", fontsize=7,
            color=APAGADO, ha="center", va="bottom")

    ax.set_yscale("log")
    ax.set_ylim(0.35, 12000)
    ax.set_ylabel("contraste de ráfaga\n(mediana ataque / mediana benigno)", fontsize=8)
    ax.set_xticks(range(len(orden)), etiquetas, fontsize=7.0, linespacing=1.35)
    limpiar_ejes(ax, rejilla="y")

    titulo(ax, "La ráfaga sirve cuando el ataque esta CONCENTRADO en un origen",
           "Contraste de conexiones/5 s entre ataque y benigno. Cae tres ordenes de "
           "magnitud segun el ataque se reparte, y en el día web se invierte.")
    nota(fig, "Mediana de conexiones por origen en ventanas de 5 s, calculada sobre los "
              "dataset_*.npz (figuras/cache/rafaga_*.npz). Explica los resultados de "
              "meta+rafaga: gana en el 16-02 (+0.029 sobre metadatos), ayuda en el 15-02 "
              "(+0.038) y ya no aporta en el 20-02 (-0.000). En el 22-02 el ataque tiene "
              "MENOS ráfaga que el tráfico legitimo (contraste x0) y por eso alli gana "
              "el payload. Fuente: models/phase2_dos_burst_*.md.")
    guardar(fig, "F36_rafaga_diluida")


# --------------------------------------------------------------------- F37
def f37_interarribo_beacon() -> None:
    """La figura DEFINITIVA del HALLAZGO 15, y la que justifica el Eje E.

    F34 enseña el perfil agregado, que es ambiguo: el DDoS-LOIC tambien es plano.
    Esta enseña la medida que NO es ambigua -el intervalo entre conexiones
    consecutivas de un mismo origen- y ahi el Bot es inconfundible: dos modas
    discretas que concentran el 91.1% de sus intervalos en dos bandas de 50 ms,
    frente a la curva suave decreciente del tráfico legitimo.

    Se calcula desde los .npz (ts + orig_h), sin conn.log.
    """
    f = DIR_CACHE / "interarribo_02-03.npz"
    if not f.exists():
        print("  [salta] F37: falta interarribo_02-03.npz (ejecuta extraer_datos.py)")
        return
    d = np.load(f)
    bins, atk, ben = d["bins"], d["ataque"], d["benigno"]
    centros = (bins[:-1] + bins[1:]) / 2
    p_atk = 100.0 * atk / atk.sum()
    p_ben = 100.0 * ben / max(ben.sum(), 1)

    fig, ax = nueva(ANCHO_COMPLETO, 3.2)
    ax.fill_between(centros, 0, p_ben, color=AZUL, alpha=0.30, step="mid",
                    label="Benigno del mismo día")
    ax.step(centros, p_ben, where="mid", color=AZUL, linewidth=1.3)
    ax.step(centros, p_atk, where="mid", color=NARANJA, linewidth=1.7,
            label="Bot / Ares (tráfico al C2)")

    # Anotar las dos modas: son el hallazgo. Van a MEDIA ALTURA del pico y a su
    # derecha; encima se meten en el subtitulo de la figura.
    for x, txt in ((0.525, "0.5 s"), (2.025, "2.0 s")):
        i = int(np.argmin(np.abs(centros - x)))
        ax.annotate(f"{txt}\n{p_atk[i]:.0f} % de los\nintervalos",
                    xy=(centros[i] + 0.03, p_atk[i] * 0.80),
                    xytext=(centros[i] + 0.22, p_atk[i] * 0.62),
                    fontsize=7.6, color=NARANJA, fontweight="bold",
                    va="center", linespacing=1.3,
                    arrowprops=dict(arrowstyle="->", color=NARANJA, lw=1.0))

    ax.set_xlabel("intervalo entre conexiones consecutivas del mismo origen (s)",
                  fontsize=8)
    ax.set_ylabel("% de los intervalos", fontsize=8)
    ax.set_xlim(0, 2.6)
    ax.set_ylim(0, 54)
    limpiar_ejes(ax, rejilla="y")
    leyenda_abajo(ax, ncols=2, dy=-0.20)

    titulo(ax, "El beacon medido: el Bot late en dos tiempos exactos",
           "Distribucion del inter-arribo por origen. El Bot concentra el 91 % de sus "
           "intervalos en dos bandas de 50 ms; el tráfico legitimo es una curva suave "
           "sin ninguna moda.")
    nota(fig, "Intervalos entre flujos consecutivos de un mismo origen, sobre "
              "dataset_Friday-02-03-2018.npz (origenes con >=50 flujos; "
              "figuras/cache/interarribo_02-03.npz). En la banda 0.50-0.55 s cae el "
              "41.8 % del ataque frente al 1.3 % del benigno: contraste x32. NINGUNA "
              "vista del trabajo calcula esta caracteristica -ni el payload, ni los "
              "escalares de flujo, ni las ventanas de ráfaga-, y por si sola separaria "
              "el ataque: es el argumento definitivo del Eje E (Hallazgo 15).")
    guardar(fig, "F37_interarribo_beacon")


# --------------------------------------------------------------------- F38
def f38_calibracion_cruzada() -> None:
    """La figura que corrige el HALLAZGO 14 y es la más importante de las nuevas.

    Tres barras por par: lo que da el modelo con el umbral heredado (F1 @0.5), lo
    que daria con el umbral adecuado (F1 optimo) y la calidad del ORDEN (AUC). Si
    las dos primeras difieren mucho pero el AUC es alto, el problema es de
    CALIBRACIÓN y no de que el modelo no sepa. Es exactamente lo que pasa con el
    byte-CNN en cuatro de los seis pares, y lo contrario de lo que sugeria F33.
    """
    pares = list(R.CALIBRACION_CRUZADA)
    n = len(pares)
    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 4.6, nrows=2, sharex=True)

    for ax, vista, tono in ((ax1, "byte-CNN", AZUL), (ax2, "payload-hist", NARANJA)):
        auc = [R.CALIBRACION_CRUZADA[p][vista][0] for p in pares]
        f05 = [R.CALIBRACION_CRUZADA[p][vista][1] for p in pares]
        fop = [R.CALIBRACION_CRUZADA[p][vista][2] for p in pares]
        x = np.arange(n)
        ax.bar(x - 0.26, f05, width=0.25, color=CRITICO, label="F1 con el umbral heredado (0.5)")
        ax.bar(x + 0.00, fop, width=0.25, color=tono, label="F1 con el umbral adecuado")
        ax.bar(x + 0.26, auc, width=0.25, color=APAGADO, label="AUC-ROC (calidad del orden)")
        ax.set_ylim(0, 1.24)
        ax.set_yticks([0, 0.5, 1.0], ["0", "0.5", "1"], fontsize=8)
        ax.axhline(0.5, color=REJILLA, linewidth=1.0)
        limpiar_ejes(ax, rejilla="y")
        ax.set_ylabel(vista, fontsize=8.5, fontweight="bold", color=tono)
        # Marcar los colapsos DONDE OCURREN: la barra roja vale 0 y por eso no
        # se ve; rotularlo arriba amontonaba los textos unos sobre otros.
        for i, (a, f) in enumerate(zip(auc, f05)):
            if f < 0.05 and a > 0.9:
                ax.text(i - 0.26, 0.03, "0", ha="center", va="bottom",
                        fontsize=8, color=CRITICO, fontweight="bold")
            elif a < 0.85:
                ax.text(i, 1.06, "techo real", ha="center", fontsize=6.4,
                        color=TINTA_2, style="italic")

    # etiquetas en dos lineas: en una sola se solapan
    ax2.set_xticks(np.arange(n),
                   [p.replace(" -> ", "\n→ ") for p in pares], fontsize=7.4,
                   linespacing=1.3)
    leyenda_abajo(ax2, ncols=3, dy=-0.30)

    titulo_figura(fig, "El byte-CNN no deja de saber: deja de estar calibrado",
                  "El byte-CNN tiene AUC ≥ 0.97 en los seis pares y aun asi da F1 = 0 "
                  "en cuatro (barra roja ausente). El histograma esta bien calibrado, "
                  "pero su AUC se hunde justo donde el del CNN aguanta.",
                  top=0.80)
    nota(fig, "AUC-ROC y F1 sobre el día de test, balanceo 1:1, servicio HTTP, cap 4000. "
              "El 'umbral adecuado' es el que maximiza F1 conociendo el día de test "
              "(cota superior de lo que daria recalibrar). Fuente: "
              "scripts/zeek/cross_calibration.py -> models/phase3_calibracion_*.json. "
              "LECTURA: un IDS con umbral fijo falla EN SILENCIO ante una herramienta no "
              "vista, aunque el modelo siga ordenando bien (Hallazgo 14, version del 22-ago).")
    guardar(fig, "F38_calibracion_cruzada")


# --------------------------------------------------------------------- F39
def f39_evasion_interarribo() -> None:
    """La figura del HALLAZGO 17 (Eje E) en dos paneles.

    Izquierda: que vista sobrevive cuando el atacante camufla los primeros bytes.
    Derecha: el aviso metodologico, que es la mitad util de la figura -en el día
    web, camuflar 160 bytes no evade la detección, DESTRUYE el ataque; con 24
    bytes el payload aguanta-.
    """
    dias = ["02-03 Bot", "16-02 DoS-Hulk", "20-02 DDoS-LOIC", "22-02 Web"]
    # (clave en resultados.py, etiqueta visible, color): la clave es ASCII y la
    # etiqueta va acentuada, que es lo que se imprime en la memoria.
    vistas = [("payload (byte-CNN)", "payload (byte-CNN)", AZUL),
              ("meta+rafaga", "meta + ráfaga", NARANJA),
              ("inter-arribo solo", "inter-arribo solo", AQUA)]

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 4.1, ncols=2,
                            gridspec_kw={"width_ratios": [1.75, 1.0]})

    x = np.arange(len(dias))
    ancho = 0.26
    for k, (clave, etiq, color) in enumerate(vistas):
        ev = [R.EJE_E_EVASION[d][clave][1] for d in dias]
        b = ax1.bar(x + (k - 1) * ancho, ev, width=ancho, color=color,
                    label=etiq)
        if clave.startswith("payload"):
            # marcar el desplome: la barra casi no se ve, y ese es el punto
            for i, val in enumerate(ev):
                if val < 0.15:
                    ax1.text(i - ancho, val + 0.03, f"{val:.3f}", ha="center",
                             va="bottom", fontsize=6.4, color=CRITICO,
                             fontweight="bold", rotation=90)
    ax1.set_ylim(0, 1.12)
    ax1.set_yticks([0, 0.5, 1.0], ["0", "0.5", "1"], fontsize=8)
    # 6.6 y no 7.4: a 7.4 "DoS-Hulk" y "DDoS-LOIC" se tocan y se leen como una
    # sola palabra. Son cuatro etiquetas en un panel estrecho.
    ax1.set_xticks(x, [d.replace(" ", "\n", 1) for d in dias], fontsize=6.6,
                   linespacing=1.35)
    ax1.set_ylabel("recall del ataque tras camuflar los bytes", fontsize=7.6)
    limpiar_ejes(ax1, rejilla="y")
    # Rotulo de panel ABAJO: arriba choca con el subtitulo de figura (leccion de F35).
    ax1.set_xlabel("solo sobreviven las vistas que no miran el contenido",
                   fontsize=8, color=TINTA_2, labelpad=6)
    leyenda_abajo(ax1, ncols=3, dy=-0.34)

    # --- panel derecho: el aviso del dia web -------------------------------
    w = R.EVASION_PREFIJO_WEB
    etiquetas = ["prefijo\n160 bytes", "prefijo\n24 bytes"]
    vals = [w["prefijo_160"][1], w["prefijo_24"][1]]
    colores = [CRITICO, AZUL]
    b2 = ax2.bar(range(2), vals, color=colores, width=0.55)
    etiquetar_barras_v(ax2, b2, vals, fmt="{:.4f}")
    ax2.axhline(w["prefijo_160"][0], color=APAGADO, linewidth=1.0,
                linestyle=(0, (4, 3)))
    ax2.text(1.45, w["prefijo_160"][0] + 0.02, "sin evasión\n(0.9672)", fontsize=6.6,
             color=APAGADO, ha="right", va="bottom")
    ax2.set_ylim(0, 1.18)
    ax2.set_yticks([0, 0.5, 1.0], ["0", "0.5", "1"], fontsize=8)
    ax2.set_xticks(range(2), etiquetas, fontsize=7.4, linespacing=1.3)
    limpiar_ejes(ax2, rejilla="y")
    # ERRATA (14-sep): en una sola linea este rotulo mide 38 px mas que el panel
    # -que es el estrecho de los dos- y "ataque" se quedaba fuera del recorte.
    # En la memoria entregada se lee "...se borra el". Partido en dos, cabe.
    ax2.set_xlabel("día web: con 160 bytes\nse borra el ataque",
                   fontsize=8, color=TINTA_2, labelpad=6, linespacing=1.35)

    titulo_figura(fig, "La evasión separa la huella de la herramienta del contenido real",
                  "El payload se desploma donde los primeros bytes son la firma de la "
                  "HERRAMIENTA. En el día web esos bytes SON el ataque, y con un prefijo "
                  "que no la toca, aguanta.", top=0.78)
    nota(fig, "Recall del ataque tras sobrescribir los primeros bytes de cada flujo con los "
              "de un cliente benigno; binario 1:1, split 70/30, servicio HTTP, cap 4000. "
              "Fuente: scripts/zeek/interarrival_eval.py -> models/phase3_interarribo_*.md. "
              "Las vistas conductuales son invariantes POR CONSTRUCCION: no miran el "
              "contenido. REGLA: un test de evasión solo vale si el ataque sigue siendo el "
              "ataque despues de la modificacion (Hallazgo 17).", y=-0.13)
    guardar(fig, "F39_evasion_interarribo")


# --------------------------------------------------------------------- F40
def f40_fuga_ips() -> None:
    """La figura del HALLAZGO 18, y un aviso metodologico para cualquier NIDS.

    Compara, en los seis pares entreno->test, lo que da una vista HONESTA con lo
    que da la MISMA vista más las IPs y el puerto de origen. La honesta se hunde
    donde el problema es dificil; la que tiene fuga da 1.0000 en todas partes.

    Lo que hay que leer NO es que la fuga sea buena, sino que la validacion
    cruzada entre días -la que un revisor considera rigurosa- NO la detecta.
    """
    pares = list(R.SOTA_FUGA)
    n = len(pares)
    # vista honesta de referencia: meta+rafaga con XGBoost (el modelo del SOTA)
    honesta = [R.SOTA_CRUZADO[p]["meta+rafaga"]["XGBoost"][0] for p in pares]
    fuga = [R.SOTA_FUGA[p]["XGBoost"] for p in pares]

    fig, ax = nueva(ANCHO_COMPLETO, 3.4)
    x = np.arange(n)
    ax.bar(x - 0.19, honesta, width=0.36, color=AQUA,
           label="vista honesta (meta+ráfaga)")
    ax.bar(x + 0.19, fuga, width=0.36, color=CRITICO,
           label="misma vista + IPs y puerto de origen")
    for i, (h, f) in enumerate(zip(honesta, fuga)):
        ax.text(i - 0.19, h + 0.02, f"{h:.3f}", ha="center", va="bottom",
                fontsize=6.8, color=TINTA)
        ax.text(i + 0.19, f + 0.02, f"{f:.3f}", ha="center", va="bottom",
                fontsize=6.8, color=CRITICO, fontweight="bold")

    ax.set_ylim(0, 1.18)
    ax.set_yticks([0, 0.5, 1.0], ["0", "0.5", "1"], fontsize=8)
    ax.axhline(1 / 3, color=APAGADO, linewidth=1.0, linestyle=(0, (4, 3)))
    ax.text(3.6, 0.355, "F1 de predecir una sola clase", fontsize=6.6,
            color=APAGADO, ha="center", va="bottom")
    ax.set_xticks(x, [p.replace(" -> ", "\n→ ") for p in pares], fontsize=7.4,
                  linespacing=1.3)
    ax.set_ylabel("macro-F1 sobre el día de test", fontsize=8)
    limpiar_ejes(ax, rejilla="y")
    leyenda_abajo(ax, ncols=2, dy=-0.30)

    titulo(ax, "La fuga de IPs no la detecta la validacion entre días",
           "Mismo modelo (XGBoost) y mismos pares entreno→test. Anadir las IPs y el puerto "
           "de origen lleva el macro-F1 a 1.0000 en todas partes, incluso donde la vista "
           "honesta se hunde al nivel de predecir una sola clase.")
    nota(fig, "macro-F1 sobre el día de test, balanceo 1:1, servicio HTTP, cap 4000. Fuente: "
              "scripts/zeek/sota_baselines.py -> models/phase3_sota_cruzado_*.json. MECANISMO: "
              "de las 18 IPs atacantes de los seis días, 15 empiezan por 18.x (el rango AWS "
              "del laboratorio) y las 12 victimas estan en 172.31.69.x, asi que 'origen 18.x "
              "-> ataque' transfiere entre CUALQUIER par de días. Engelen et al. (WTMC2021) "
              "advierten de este atajo; lo que anade este experimento es que la validacion "
              "cruzada ENTRE DÍAS no lo detecta: solo la validacion entre DATASETS lo rompe. "
              "Ninguna vista de este trabajo usa IPs ni puertos como caracteristica.")
    guardar(fig, "F40_fuga_ips")


# --------------------------------------------------------------------- F41
def f41_recalibracion() -> None:
    """El remate del HALLAZGO 14: del diagnostico a la receta.

    Izquierda: F1 antes y despues de Platt scaling con solo 25 etiquetas del día
    nuevo. Derecha: el ECE, que es lo que delata el problema -y que separa los
    pares rotos (~0.499, el máximo posible) de los sanos sin ambiguedad-.
    """
    pares = list(R.RECALIBRACION)
    n = len(pares)
    sin = [R.RECALIBRACION[p]["sin"][0] for p in pares]
    con = [R.RECALIBRACION[p]["n25"][0] for p in pares]
    ece_sin = [R.RECALIBRACION[p]["sin"][2] for p in pares]
    ece_con = [R.RECALIBRACION[p]["n25"][2] for p in pares]

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 4.0, ncols=2,
                            gridspec_kw={"width_ratios": [1.25, 1.0]})
    x = np.arange(n)
    # Compactas: con seis grupos por panel, "16-02 → 20-02" se solapa.
    etiquetas = [p.replace("-02", "").replace(" -> ", "→") for p in pares]

    ax1.bar(x - 0.19, sin, width=0.36, color=CRITICO, label="sin recalibrar")
    ax1.bar(x + 0.19, con, width=0.36, color=AQUA,
            label="tras Platt con 25 etiquetas")
    # El valor va DENTRO de la barra: encima choca con el subtitulo.
    for i, b in enumerate(con):
        ax1.text(i + 0.19, b - 0.04, f"{b:.3f}", ha="center", va="top",
                 fontsize=6.6, color="#ffffff", fontweight="bold", rotation=90)
    ax1.set_ylim(0, 1.16)
    ax1.set_yticks([0, 0.5, 1.0], ["0", "0.5", "1"], fontsize=8)
    # En horizontal las seis se pegan y se leen como una sola cadena
    # ("16→2020→1615→20..."), igual que en el panel derecho.
    ax1.set_xticks(x, etiquetas, fontsize=7.4, rotation=45, ha="right")
    ax1.set_ylabel("macro-F1 sobre el día de test", fontsize=8)
    limpiar_ejes(ax1, rejilla="y")
    # Las etiquetas de eje se recortaban: eran mas anchas que su panel y
    # quedaban cortadas en el borde de la figura (revision IPB, punto 11).
    ax1.set_xlabel("entreno→test; los cuatro primeros colapsaban",
                   fontsize=8, color=TINTA_2, labelpad=6)
    leyenda_abajo(ax1, ncols=2, dy=-0.34)

    ax2.bar(x - 0.19, ece_sin, width=0.36, color=CRITICO)
    ax2.bar(x + 0.19, ece_con, width=0.36, color=AQUA)
    ax2.set_ylim(0, 0.58)
    ax2.set_yticks([0, 0.25, 0.5], ["0", "0.25", "0.5"], fontsize=8)
    # Panel mas estrecho: en horizontal las seis etiquetas se pisan.
    ax2.set_xticks(x, etiquetas, fontsize=7.4, rotation=45, ha="right")
    ax2.set_ylabel("ECE (error de calibración)", fontsize=8)
    limpiar_ejes(ax2, rejilla="y")
    ax2.set_xlabel("el ECE delata el exceso de confianza",
                   fontsize=8, color=TINTA_2, labelpad=6)

    titulo_figura(fig, "El byte-CNN no habia que descartarlo: habia que recalibrarlo",
                  "Platt scaling ajustado con solo 25 flujos etiquetados del día nuevo, y "
                  "medido sobre el resto -que el calibrador no ve-. El F1 pasa de 0.333 a "
                  "más de 0.97 en los cuatro pares colapsados, y el ECE de ~0.499 -el "
                  "máximo posible- a menos de 0.03.", top=0.72)
    nota(fig, "Platt scaling: sigmoide(A*logit(p)+B) ajustada sobre una muestra balanceada "
              "del día de test y aplicada al resto. Fuente: "
              "scripts/zeek/cross_recalibration.py -> models/phase3_recalibracion_*.json. "
              "Más etiquetas apenas mejoran, salvo en el par más dificil (20-02 -> 15-02: "
              "recall 0.9571 con 25 frente a 0.9997 con 1000). Recalibrar NUNCA perjudica: "
              "el par que ya funcionaba pasa de 0.9597 a 0.9999. El trabajo independiente "
              "Cross-Dataset Transformer-IDS (2026) documenta el mismo fenomeno y lo corrige "
              "igual, bajando su ECE de 0.25 a 0.06.", y=-0.13)
    guardar(fig, "F41_recalibracion")


# --------------------------------------------------------------------- F42
def f42_arquitecturas() -> None:
    """Las arquitecturas del estado del arte frente a las de este TFG.

    Dos paneles porque hay DOS ejes que importan y contarlos por separado
    enganaria: el acierto (donde empatan) y el COSTE (donde no). Un grafico solo
    de F1 diria "da igual"; uno solo de tiempo diria "el CNN es mejor" sin
    justificar por que. Juntos dicen lo que hay: misma exactitud, coste dispar.
    """
    dia = "02-03 Bot (4000/clase)"
    modelos = ["byte-CNN (este TFG)", "byte-LSTM (este TFG)", "byte-Transformer (SOTA)"]
    f1 = [R.ARQUITECTURAS_SECUENCIA[dia][m][0] for m in modelos]
    seg = [R.ARQUITECTURAS_SECUENCIA[dia][m][3] for m in modelos]
    # fusion, en el mismo dia
    fus = ["fusion tardia (este TFG)", "atencion cruzada (SOTA)"]
    f1f = [R.ARQUITECTURAS_FUSION["02-03 Bot"][m][0] for m in fus]
    segf = [R.ARQUITECTURAS_FUSION["02-03 Bot"][m][3] for m in fus]

    # Nombres cortos en dos lineas: los completos se solapan con
    # cinco grupos por panel.
    nombres = ["\n".join(t) for t in (
        ("byte", "CNN"), ("byte", "LSTM"), ("byte", "Transf."),
        ("fusión", "tardía"), ("atención", "cruzada"))]
    valores = f1 + f1f
    tiempos = seg + segf
    # azul = nuestro, naranja = del estado del arte
    colores = [AZUL, AZUL, NARANJA, AZUL, NARANJA]

    fig, (ax1, ax2) = nueva(ANCHO_COMPLETO, 3.4, ncols=2)
    x = np.arange(len(nombres))

    ax1.bar(x, valores, width=0.62, color=colores)
    for i, v in enumerate(valores):
        ax1.text(i, v + 0.004, f"{v:.4f}", ha="center", va="bottom", fontsize=7,
                 color=TINTA)
    ax1.set_ylim(0.99, 1.008)
    ax1.set_yticks([0.99, 1.0], ["0.99", "1"], fontsize=8)
    ax1.set_xticks(x, nombres, fontsize=7.2, linespacing=1.3)
    ax1.set_ylabel("macro-F1", fontsize=8)
    limpiar_ejes(ax1, rejilla="y")
    ax1.set_xlabel("acierto: empatan todos", fontsize=8, color=TINTA_2, labelpad=6)

    ax2.bar(x, tiempos, width=0.62, color=colores)
    for i, t in enumerate(tiempos):
        ax2.text(i, t * 1.15, f"{miles(t)}s", ha="center", va="bottom", fontsize=7,
                 color=TINTA, fontweight="bold" if t > 1000 else "normal")
    ax2.set_yscale("log")
    ax2.set_ylim(30, 9000)
    ax2.set_xticks(x, nombres, fontsize=7.2, linespacing=1.3)
    ax2.set_ylabel("segundos de entrenamiento (log)", fontsize=8)
    limpiar_ejes(ax2, rejilla="y")
    ax2.set_xlabel("coste: 49x más caro el Transformer", fontsize=8,
                   color=TINTA_2, labelpad=6)

    titulo_figura(fig, "Las arquitecturas del estado del arte no mejoran: solo cuestan más",
                  "En azul las de este TFG, en naranja las del estado del arte. Mismo día, "
                  "misma particion y presupuesto de parametros comparable (30k-72k). El "
                  "acierto empata; el coste no.", top=0.80)
    nota(fig, "macro-F1 out-of-fold (5-Fold) sobre el día Bot, 4000 flujos por clase, "
              "servicio HTTP. Fuente: scripts/zeek/arquitecturas_eval.py -> "
              "models/phase3_arquitecturas_*.json. En el día web (203 por clase) el "
              "Transformer ademas PIERDE: 0.9778 frente a 0.9975 del byte-CNN. Se contrasta "
              "la ARQUITECTURA, no el preentrenamiento: un ET-BERT preentrenado sobre "
              "millones de trazas es otra cosa y no se ha probado.", y=-0.12)
    guardar(fig, "F42_arquitecturas")


# --------------------------------------------------------------------------
def generar_todo() -> None:
    print("Bloque 8 - Generalizacion y limites del enfoque")
    for f in (f33_cruzado_entre_dias, f34_perfiles_temporales,
              f35_ceguera_infiltracion, f36_rafaga_diluida,
              f37_interarribo_beacon, f38_calibracion_cruzada,
              f39_evasion_interarribo, f40_fuga_ips, f41_recalibracion,
              f42_arquitecturas):
        f()          # guardar() ya imprime el [ok] de cada figura


if __name__ == "__main__":
    generar_todo()

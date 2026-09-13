#!/usr/bin/env python
"""Genera las tablas de la memoria en LaTeX (booktabs) desde resultados.py.

Cada tabla sale a `figuras/tablas/<id>.tex` como un entorno `table` completo,
con su `\\caption` y su `\\label`, listo para incluir:

    \\input{figuras/tablas/T03_resultados_regimen}

Requiere en el preambulo:  \\usepackage{booktabs}

La misma regla que las figuras: aquí no se calcula nada. Los numeros vienen
de resultados.py, que a su vez los toma de los `models/*.md` generados por
los scripts de experimentacion.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402
from estilo import DIR_TAB  # noqa: E402


def escapar(t: str) -> str:
    """Escapa lo que LaTeX interpretaria como marca."""
    for a, b in [("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"),
                 ("_", r"\_"), ("#", r"\#"), ("$", r"\$"), ("{", r"\{"),
                 ("}", r"\}"), ("~", r"\textasciitilde{}"),
                 ("^", r"\textasciicircum{}")]:
        t = t.replace(a, b)
    return t


def escribir(tid: str, caption: str, label: str, cols: str,
             cabecera: list[str], filas: list[list[str]],
             nota: str | None = None, tamano: str | None = None) -> None:
    """Vuelca una tabla booktabs completa a figuras/tablas/<tid>.tex.

    `tamano` acepta "small" o "footnotesize" para las tablas que no caben a
    tamano normal en una caja de ~15 cm (la de la plantilla del TFG). Se
    prefiere reducir el cuerpo a usar \\resizebox: el texto sigue siendo
    seleccionable y el grosor de las lineas de booktabs no se deforma.
    Comprobado compilando cada tabla por separado.
    """
    L = [r"% Generado por scripts/figuras/tablas.py - no editar a mano",
         r"\begin{table}[htbp]", r"  \centering",
         rf"  \caption{{{caption}}}", rf"  \label{{{label}}}"]
    if tamano:
        L.append(rf"  \{tamano}")
    L += [rf"  \begin{{tabular}}{{{cols}}}", r"    \toprule",
          "    " + " & ".join(rf"\textbf{{{c}}}" for c in cabecera) + r" \\",
          r"    \midrule"]
    L += ["    " + " & ".join(f) + r" \\" for f in filas]
    L += [r"    \bottomrule", r"  \end{tabular}"]
    if nota:
        L.append(rf"  \par\smallskip\footnotesize{{{nota}}}")
    L.append(r"\end{table}")
    (DIR_TAB / f"{tid}.tex").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"  [ok] {tid}.tex")


def _n(x: int) -> str:
    """Miles con punto, como se escribe en espanol."""
    return f"{x:,}".replace(",", ".")


def _d(x: float, n=4) -> str:
    return f"{x:.{n}f}"


# ==========================================================================

def t01_dias() -> None:
    filas = []
    # El 28-02 (Infiltration) NO aparece aqui: no tiene .npz a proposito, porque
    # el 94,4% de su ataque no lleva payload (HALLAZGO 16). Si sale en T02.
    for clave in ["Wednesday-14-02-2018", "Thursday-15-02-2018",
                  "Friday-16-02-2018", "Tuesday-20-02-2018",
                  "Thursday-22-02-2018", "Friday-02-03-2018",
                  "Tuesday-04-07-2017", "Wednesday-05-07-2017",
                  "Thursday-06-07-2017"]:
        d = R.DIAS[clave]
        filas.append([
            escapar(d["corto"]),
            escapar(d["dataset"].replace("CSE-CIC-IDS2018", "2018")
                    .replace("CIC-IDS2017", "2017")),
            escapar(d["ataque"]), escapar(d["regimen"]),
            _n(d["flujos_total"]), _n(d["flujos_ataque"]),
        ])
    escribir("T01_dias_dataset",
             "Días procesados, con el numero de conexiones TCP con payload "
             "extraidas de cada uno.",
             "tab:días", "llllrr",
             ["Día", "Dataset", "Ataque", "Regimen", "Flujos", "De ataque"],
             filas, tamano="footnotesize",
             nota="Un flujo es una conexión TCP identificada por el "
                  "\\texttt{uid} de Zeek. Recuentos tras las correcciones de "
                  "etiquetado de junio y agosto de 2026.")


def t02_ground_truth() -> None:
    filas = []
    for clave in ["Wednesday-14-02-2018", "Thursday-15-02-2018",
                  "Friday-16-02-2018", "Tuesday-20-02-2018",
                  "Thursday-22-02-2018", "Friday-02-03-2018",
                  "Wednesday-28-02-2018"]:
        d = R.DIAS[clave]
        filas.append([escapar(d["corto"]), escapar(d["ataque"]),
                      rf"\texttt{{{escapar(d['atacante'])}}}",
                      rf"\texttt{{{escapar(d['victima'])}}}",
                      escapar(d["ventana_local"])])
    escribir("T02_ground_truth",
             "Ground-truth verificada empiricamente sobre las capturas, no "
             "tomada de la documentacion del dataset.",
             "tab:gt", "lllll",
             ["Día", "Ataque", "Atacante", "Victima", "Ventana (local)"],
             filas, tamano="footnotesize",
             nota="Verificada con \\texttt{find\\_attacker.py} y "
                  "\\texttt{find\\_host.py}, salvo el 02-03 (no hay victima "
                  "unica: el C2 se localizo sobre los TSV) y el 28-02 (sobre el "
                  "\\texttt{conn.log}). La documentacion oficial resulto "
                  "incorrecta en el atacante SSH del 14-02, en los limites de "
                  "ventana del 14-02 y el 16-02, y en el 02-03, donde parte el "
                  "Bot en dos franjas siendo continuo. El 28-02 no tiene "
                  "\\texttt{.npz}: el 94.4\\% de su ataque no lleva payload.")


def t03_resultados_regimen() -> None:
    """Los seis días con la MISMA metrica y el MISMO protocolo (HALLAZGO 19).

    La version anterior tenia las cifras cableadas, mezclaba exactitud CV con
    macro-F1 y ponia en negrita "la vista más robusta", que no es lo que la
    columna mide. Ahora sale de SATURACION_INTRADIA y anade la columna que si
    discrimina: que queda del payload tras camuflar los primeros bytes.
    """
    orden = ["14-02", "22-02", "16-02", "15-02", "20-02", "02-03"]
    nombre = {
        "14-02": ("Cifrado", "SSH-Bruteforce"),
        "22-02": ("En claro", "Web BF/XSS/SQLi"),
        "16-02": ("Volumétrico", "DoS-Hulk"),
        "15-02": ("Volumétrico", "GoldenEye+Slowloris"),
        "20-02": ("Volum. distribuido", "DDoS-LOIC (10 orig.)"),
        "02-03": ("Periodicidad", "Bot (Ares)"),
    }
    # Recall del payload tras camuflar los primeros bytes del flujo.
    evad = {
        "14-02": R.EVASION["SSH cifrado (14-02, 48 B)"]["payload (byte-CNN)"]["evadido"],
        "22-02": R.EVASION_PREFIJO_WEB["prefijo_24"][1],
        "16-02": R.EJE_E_EVASION["16-02 DoS-Hulk"]["payload (byte-CNN)"][1],
        "15-02": None,
        "20-02": R.EJE_E_EVASION["20-02 DDoS-LOIC"]["payload (byte-CNN)"][1],
        "02-03": R.EJE_E_EVASION["02-03 Bot"]["payload (byte-CNN)"][1],
    }

    filas = []
    for d in orden:
        reg, atk = nombre[d]
        v = R.SATURACION_INTRADIA[d]
        ev = evad[d]
        filas.append([
            f"{reg} ({d})", atk,
            _d(v["payload"][0]), _d(v["metadatos"][0]), _d(v["conducta"][0]),
            "n.\\,p." if ev is None else _d(ev),
        ])
    filas.append(["Reconocimiento (28-02)", "Infiltration",
                  "---", "---", "---", "---"])

    escribir("T03_resultados_regimen",
             "Las tres vistas en los seis días, con la misma metrica y el "
             "mismo protocolo. La ultima columna es lo unico que las "
             "distingue.",
             "tab:regimenes", "llrrrr",
             ["Regimen", "Ataque", "Payload", "Metadatos", "Conducta",
              "Payload evadido"],
             filas, tamano="small",
             nota="Macro-F1 out-of-fold (5-Fold estratificado), balanceo 1:1 "
                  "con tope de 5.000 por clase dentro del servicio atacado, "
                  "benigno genuino de terceros, media de diez submuestreos. "
                  "Ninguna vista baja de 0.918 y el payload no baja de 0.973: "
                  "la evaluacion intra-día esta SATURADA y no discrimina entre "
                  "vistas, porque con un solo host atacante por día cualquier "
                  "representacion dispone de un atajo suficiente. La ultima "
                  "columna da el recall del payload tras camuflar los primeros "
                  "bytes: ahi si se separan. `n.\\,p.` = no probada. El 28-02 "
                  "no tiene cifras porque el 94.4\\% de su ataque no lleva "
                  "payload y no se construyo su dataset: es el limite del "
                  "enfoque, no un resultado peor.")


def t04_hallazgos() -> None:
    filas = [[str(n), escapar(t), escapar(d)] for n, t, d in R.HALLAZGOS]
    escribir("T04_hallazgos",
             "Hallazgos clave del trabajo.", "tab:hallazgos",
             r"cp{0.26\textwidth}p{0.56\textwidth}",
             ["\\#", "Hallazgo", "Contenido"], filas)


def t05_descriptores() -> None:
    filas = [[rf"\texttt{{{escapar(n)}}}", escapar(d), escapar(o)]
             for n, d, o in R.DESCRIPTORES]
    escribir("T05_descriptores",
             "Los 19 descriptores del payload extraidos de la literatura, "
             "unidos a las caracteristicas de Zeek.",
             "tab:descriptores",
             r"lp{0.38\textwidth}p{0.30\textwidth}",
             ["Atributo", "Que mide", "Origen bibliografico"], filas,
             tamano="small",
             nota="Implementados en "
                  "\\texttt{scripts/zeek/payload\\_features.py}. Responden al "
                  "punto 1b de la revision del tutor del 11 de agosto.")


def t06_servicio_puerto() -> None:
    filas = []
    for dia, (comp, conf, contra) in R.SERVICIO_VS_PUERTO.items():
        filas.append([escapar(dia), _n(comp), _n(conf),
                      _d(100 * conf / comp, 2) + r" \%", _n(contra)])
    escribir("T06_servicio_vs_puerto",
             "Acuerdo entre la convencion de puertos y el servicio "
             "identificado por el contenido del tráfico.",
             "tab:servicio", "lrrrr",
             ["Día", "Comparables", "Confirman", "Acuerdo", "Contradicen"],
             filas,
             nota="Identificacion por las mismas firmas que emplean los "
                  "analizadores de Zeek. En un laboratorio controlado el "
                  "acuerdo es casi total, de modo que ningun resultado previo "
                  "cambia; el valor de la correccion es metodologico.")


def t07_dl() -> None:
    modelos = ["byte-CNN", "byte-LSTM", "mlp-seq", "mlp-hist", "metadatos"]
    tareas = list(R.DL_EJE_A)
    filas = []
    for m in modelos:
        fila = [escapar(m)]
        for t in tareas:
            v = R.DL_EJE_A[t][m]
            mejor = v == max(R.DL_EJE_A[t].values())
            fila.append((r"\textbf{" + _d(v) + "}") if mejor else _d(v))
        filas.append(fila)
    escribir("T07_dl_modelos",
             "Modelos profundos sobre la secuencia de bytes frente a los "
             "baselines, sobre la misma particion (macro-F1 out-of-fold).",
             "tab:dl", "lrrr",
             ["Modelo"] + [escapar(t) for t in tareas], filas,
             tamano="small",
             nota="Validacion cruzada estratificada de 5 particiones, "
                  "predicciones out-of-fold. El día del DoS no se incluye: sus "
                  "cifras quedaron invalidadas por el re-etiquetado del 11 de "
                  "agosto.")


def t08_evasion() -> None:
    # Nombres abreviados: los del diccionario llevan el tamano del camuflaje
    # entre parentesis y hacen que la tabla no quepa a lo ancho.
    corto = {"SSH cifrado (14-02, 48 B)": "SSH cifrado (14-02)",
             "DoS volumétrico (16-02, 200 B)": "DoS volumétrico (16-02)",
             "payload (byte-CNN)": "payload (CNN)",
             "conducta (meta+rafaga)": "conducta (ráfaga)"}
    filas = []
    for esc, vistas in R.EVASION.items():
        for vista, v in vistas.items():
            caida = v["original"] - v["evadido"]
            filas.append([escapar(corto.get(esc, esc)),
                          escapar(corto.get(vista, vista)),
                          _d(v["original"]), _d(v["evadido"]),
                          (r"\textbf{" + _d(caida) + "}") if caida > 0.02
                          else "invariante"])
    escribir("T08_evasion",
             "Recall del ataque antes y despues de camuflar los primeros "
             "bytes con los de un cliente legitimo.",
             "tab:evasión", "llrrr",
             ["Escenario", "Vista", "Original", "Evadido", "Caida"], filas,
             tamano="small",
             nota="Se alteran unicamente los primeros 48 bytes (SSH) o 200 "
                  "bytes (DoS) de cada flujo de ataque; el resto del flujo no "
                  "cambia. La vista conductual no mira el contenido, por lo "
                  "que su recall no varia.")


def t09_cruzado() -> None:
    filas = []
    for par, vistas in R.CRUZADO.items():
        filas.append([escapar(par)] +
                     [_d(vistas[v]) if vistas[v] is not None else "---"
                      for v in ["payload-hist", "metadatos", "byte-CNN"]])
    escribir("T09_cruzado",
             "Generalizacion cruzada entre datasets: entrenar en uno y "
             "evaluar en el otro con el ataque analogo (0.5 = azar).",
             "tab:cruzado", "lrrr",
             ["Origen $\\rightarrow$ destino", "Payload (hist.)", "Metadatos",
              "byte-CNN"], filas,
             nota="Balanceo 1:1 en origen y destino. Por indicacion del tutor "
                  "del 11 de agosto, este bloque se presenta como validacion "
                  "complementaria y trabajo futuro, no como eje central.")


def t10_rigor() -> None:
    filas = []
    for reg, vistas in R.RIGOR.items():
        for vista, (v, lo, hi) in vistas.items():
            filas.append([escapar(reg), escapar(vista), _d(v),
                          f"[{_d(lo)}; {_d(hi)}]"])
    escribir("T10_rigor",
             "ROC-AUC con intervalo de confianza al 95\\,\\% por bootstrap.",
             "tab:rigor", "llrr",
             ["Regimen", "Vista", "ROC-AUC", "IC 95\\,\\%"], filas,
             nota="2.000 remuestreos sobre las predicciones out-of-fold. Con "
                  "clases pequenas, el intervalo es más informativo que un "
                  "accuracy puntual.")


def t11_atributos() -> None:
    # Transpuesta respecto al informe original: con las cinco vistas como
    # columnas la tabla se sale 185 pt de la caja. Como filas caben holgadas
    # y ademas se leen mejor, que es como se comparan las vistas entre si.
    regimenes = list(R.ATRIBUTOS_PAYLOAD)
    filas = []
    for i, vista in enumerate(R.ATRIBUTOS_VISTAS):
        nombre, dims = vista.rsplit(" (", 1)
        filas.append([rf"\texttt{{{escapar(nombre)}}}", dims.rstrip(")")] +
                     [_d(R.ATRIBUTOS_PAYLOAD[r][i]) for r in regimenes])
    escribir("T11_atributos_payload",
             "Atributos interpretables del payload frente al histograma "
             "crudo, solos y unidos a las caracteristicas de Zeek.",
             "tab:atributos", "lrrrr",
             ["Vista", "Dim.", "Cifrado", "En claro", "Volumétrico"], filas,
             nota="Accuracy de validacion cruzada 5-Fold; seleccion por "
                  "servicio, balanceo 1:1 y benigno limpio de la IP atacante. "
                  "El día volumétrico satura a 1.0000 en las cinco vistas y no "
                  "discrimina entre ellas.")


def t12_fase1() -> None:
    filas = [[escapar(m), _d(v, 5), _d(s, 5)]
             for m, (v, s) in R.FASE1_BENCHMARK.items()]
    escribir("T12_fase1_benchmark",
             "Benchmark multiclase de la Fase 1 sobre metadatos de flujo "
             "(validacion cruzada de 5 particiones, sin balancear).",
             "tab:fase1", "lrr",
             ["Modelo", "Accuracy media", "Desviacion tipica"], filas,
             nota="Estas cifras son el punto de partida del trabajo, no un "
                  "resultado: al eliminar las variables que memorizan la "
                  "morfologia de los paquetes de la herramienta de ataque, la "
                  "precisión sobre el DoS-Slowloris cae a 0.80.")


def generar_todo() -> None:
    print("Tablas LaTeX")
    t01_dias()
    t02_ground_truth()
    t03_resultados_regimen()
    t04_hallazgos()
    t05_descriptores()
    t06_servicio_puerto()
    t07_dl()
    t08_evasion()
    t09_cruzado()
    t10_rigor()
    t11_atributos()
    t12_fase1()


if __name__ == "__main__":
    generar_todo()

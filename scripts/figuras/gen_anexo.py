# -*- coding: utf-8 -*-
"""Genera las tablas del anexo de resultados secundarios desde resultados.py.

Se generan y no se escriben a mano por el mismo motivo que el resto de la
memoria: cualquier transcripcion manual es una fuente de desfase.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts/figuras").resolve()))
import resultados as R  # noqa: E402

RAIZ = Path(__file__).resolve().parents[2]
DIR = RAIZ / "DIF_Dissertation_2026/chapters/appendix"

# Una tabla por fichero: si van las cuatro juntas al final, LaTeX las flota
# despues de todo el texto y cada seccion habla de una tabla que aparece
# paginas mas adelante.
TABLAS = []
L = []
A = L.append


def cerrar(nombre: str) -> None:
    """Vuelca la tabla acumulada en su propio fichero y empieza otra."""
    global L, A
    (DIR / f"{nombre}.tex").write_text("\n".join(L) + "\n", encoding="utf-8")
    TABLAS.append(nombre)
    L = []
    A = L.append


# Los identificadores de resultados.py son ASCII; la memoria va acentuada.
def es(t: str) -> str:
    for a, b in (("Volumetrico", "Volumétrico"), ("meta+rafaga", "meta + ráfaga"),
                 ("payload ", "payload "), ("conducta ", "conducta ")):
        t = t.replace(a, b)
    return t

NOMBRE = {
    "14-02": "14-02 cifrado",
    "22-02": "22-02 en claro",
    "16-02": "16-02 volumétrico",
    "15-02": "15-02 volumétrico",
    "20-02": "20-02 vol. diluido",
    "02-03": "02-03 periodicidad",
}

# ------------------------------------------------------------------ B.1
A(r"% @fuente [R.SATURACION_RECALL[d][v][0] for d in DIAS for v in VISTAS]")
A(r"\begin{table}[htbp]")
A(r"  \centering")
A(r"  \caption[Recall intra-día por vista]{\emph{Recall} de la clase de ataque"
  r" en la evaluación intra-día. Complementa la tabla~\ref{tab:saturacion},"
  r" que recoge el macro-F1 de las mismas mediciones.}")
A(r"  \label{tab:anexo-recall}")
A(r"  \begin{tabular}{lccc}")
A(r"    \toprule")
A(r"    \textbf{Día} & \textbf{Payload} & \textbf{Metadatos} & \textbf{Conducta} \\")
A(r"    \midrule")
for d, fila in R.SATURACION_RECALL.items():
    celdas = [f"{fila[v][0]:.4f}" for v in ("payload", "metadatos", "conducta")]
    A(f"    {NOMBRE[d]} & " + " & ".join(celdas) + r" \\")
A(r"    \bottomrule")
A(r"  \end{tabular}")
A(r"\end{table}")
cerrar("tabla_anexo_recall")

# ------------------------------------------------------------------ B.2
A(r"% @fuente [R.RIGOR[r][m][i] for r in R.RIGOR for m in R.RIGOR[r] for i in (0, 1, 2)]")
A(r"\begin{table}[htbp]")
A(r"  \centering")
A(r"  \caption[AUC-ROC con intervalo bootstrap]{Área bajo la curva ROC con"
  r" intervalo de confianza al 95\,\% de 2.000 remuestreos. Es la medida"
  r" independiente del umbral que la sección~\ref{sec:cross-dia} emplea para"
  r" separar el fallo de representación del fallo de umbral.}")
A(r"  \label{tab:anexo-auc}")
A(r"  \begin{tabular}{llc}")
A(r"    \toprule")
A(r"    \textbf{Régimen} & \textbf{Vista} & \textbf{AUC-ROC (IC 95\,\%)} \\")
A(r"    \midrule")
for i, (reg, filas) in enumerate(R.RIGOR.items()):
    if i:
        A(r"    \midrule")
    primera = True
    for modelo, (v, lo, hi) in filas.items():
        etiqueta = reg if primera else ""
        primera = False
        A(f"    {es(etiqueta)} & {es(modelo)} & {v:.4f} [{lo:.4f}, {hi:.4f}] " + r"\\")
A(r"    \bottomrule")
A(r"  \end{tabular}")
A(r"\end{table}")
cerrar("tabla_anexo_auc")

# ------------------------------------------------------------------ B.3
A(r"% @fuente [R.ANOMALIA_DET_5FPR[r][m] for r in R.ANOMALIA_DET_5FPR for m in R.ANOMALIA_DET_5FPR[r]]")
A(r"\begin{table}[htbp]")
A(r"  \centering")
A(r"  \caption[Detección no supervisada al 5\,\% de falsos positivos]{Fracción"
  r" de ataques detectados aceptando un 5\,\% de falsos positivos, entrenando"
  r" únicamente con tráfico benigno. Es la lectura operativa de la"
  r" tabla~\ref{tab:anomalia}, que reporta el área bajo la curva.}")
A(r"  \label{tab:anexo-5fpr}")
A(r"  \begin{tabular}{lccc}")
A(r"    \toprule")
A(r"    \textbf{Régimen} & \textbf{Payload (IF)} & \textbf{Payload (AE)}"
  r" & \textbf{Conducta (IF)} \\")
A(r"    \midrule")
for reg, fila in R.ANOMALIA_DET_5FPR.items():
    A(f"    {es(reg)} & {fila['payload-IF']:.4f} & {fila['payload-AE']:.4f}"
      f" & {fila['meta+rafaga-IF']:.4f} " + r"\\")
A(r"    \bottomrule")
A(r"  \end{tabular}")
A(r"\end{table}")
cerrar("tabla_anexo_5fpr")

# ------------------------------------------------------------------ B.4
C = chr(39)  # comilla simple, para no pelear con la cadena cruda
A(f"% @fuente [R.HIPERPARAMETROS[c][m][k] for c in R.HIPERPARAMETROS"
  f" for m in R.HIPERPARAMETROS[c]"
  f" for k in ({C}por_defecto{C}, {C}mejor{C}, {C}segundos{C})]")
A(r"\begin{table}[htbp]")
A(r"  \centering")
A(r"  \caption[Búsqueda de hiperparámetros]{Búsqueda aleatoria de 30"
  r" configuraciones, validada únicamente dentro del día de entrenamiento."
  r" Macro-F1 con los valores por defecto, con los mejores encontrados, y coste"
  r" de la búsqueda.}")
A(r"  \label{tab:anexo-hiperparametros}")
A(r"  \begin{tabular}{llccc}")
A(r"    \toprule")
A(r"    \textbf{Caso} & \textbf{Modelo} & \textbf{Por defecto}"
  r" & \textbf{Mejor} & \textbf{Segundos} \\")
A(r"    \midrule")
for i, (caso, filas) in enumerate(R.HIPERPARAMETROS.items()):
    if i:
        A(r"    \midrule")
    primera = True
    for modelo, d in filas.items():
        etiqueta = caso if primera else ""
        primera = False
        # Separador de millar, como en el resto de la memoria: 2.624, no 2624.
        seg = f"{d['segundos']:,}".replace(",", ".")
        A(f"    {etiqueta} & {modelo} & {d['por_defecto']:.4f} &"
          f" {d['mejor']:.4f} & {seg} " + r"\\")
A(r"    \bottomrule")
A(r"  \end{tabular}")
A(r"\end{table}")

cerrar("tabla_anexo_hiperparametros")

for t in TABLAS:
    print(f"  {t}.tex")

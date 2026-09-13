#!/usr/bin/env python
"""Compone `figuras/catalogo.pdf`: todas las figuras en un solo documento.

Sirve para dos cosas:

1. **Revisar** el material de un vistazo (y ensenarselo al tutor) sin abrir
   32 ficheros sueltos.
2. **Validar** que los 32 PDF vectoriales se incluyen sin problemas en un
   documento LaTeX real, que es como acabaran en la memoria. Si alguno
   fallara, la compilacion se rompe aqui y no en la entrega.

    conda run -n tfg_ia python scripts/figuras/catalogo_pdf.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from estilo import DIR_FIG, DIR_PDF  # noqa: E402

# Titulo legible de cada bloque, por el prefijo numerico de la figura
BLOQUES = [
    (1, 5, "Bloque 0 --- Diagramas conceptuales"),
    (6, 10, "Bloque 1 --- Los datos"),
    (11, 15, "Bloques 2 y 3 --- Honestidad metodologica"),
    (16, 20, "Bloque 4 --- Los tres regimenes (nucleo de la tesis)"),
    (21, 25, "Bloque 5 --- Deep learning"),
    (26, 29, "Bloque 6 --- Robustez"),
    (30, 32, "Bloque 7 --- Atributos del payload"),
]

CABECERA = r"""\documentclass[a4paper,10pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[spanish]{babel}
\usepackage{graphicx}
\usepackage[margin=1.8cm]{geometry}
\usepackage{parskip}
\setlength{\parindent}{0pt}
\pagestyle{empty}
\begin{document}

\begin{center}
  {\Large\bfseries Catalogo de figuras --- TFG IDS-ML-Payload}\\[2pt]
  {\small Inaki Moreno --- material visual para la memoria y la defensa}\\[2pt]
  {\footnotesize Generado por \texttt{scripts/figuras/catalogo\_pdf.py}.
  Cada figura existe en \texttt{figuras/pdf/} (vectorial, para la memoria)
  y en \texttt{figuras/png/} (para la presentacion).}
\end{center}

\vspace{4pt}
"""


def main() -> None:
    pdfs = sorted(DIR_PDF.glob("F*.pdf"))
    if not pdfs:
        sys.exit("No hay figuras en figuras/pdf/ (ejecuta generar_todo.py)")

    cuerpo = [CABECERA]
    bloque_actual = None
    for p in pdfs:
        n = int(re.match(r"F(\d+)", p.stem).group(1))
        bloque = next((t for a, b, t in BLOQUES if a <= n <= b), "Otras")
        if bloque != bloque_actual:
            cuerpo.append(r"\vspace{6pt}\hrule\vspace{4pt}")
            cuerpo.append(rf"{{\bfseries {bloque}}}\par\vspace{{4pt}}")
            bloque_actual = bloque
        etiqueta = p.stem.replace("_", r"\_")
        cuerpo.append(rf"{{\footnotesize\ttfamily {etiqueta}}}\par")
        cuerpo.append(
            rf"\includegraphics[width=\textwidth,height=0.30\textheight,"
            rf"keepaspectratio]{{{p.as_posix()}}}\par\vspace{{8pt}}")
    cuerpo.append(r"\end{document}")

    tex = DIR_FIG / "catalogo.tex"
    tex.write_text("\n".join(cuerpo), encoding="utf-8")

    if not shutil.which("pdflatex"):
        print(f"[aviso] pdflatex no esta en el PATH; queda el .tex: {tex}")
        return

    for _ in range(2):        # dos pasadas: asienta los saltos de pagina
        r = subprocess.run(
            ["pdflatex", "-interaction=nonstopmode", "catalogo.tex"],
            cwd=DIR_FIG, capture_output=True, text=True)
    if not (DIR_FIG / "catalogo.pdf").exists():
        print(r.stdout[-2500:])
        sys.exit("Fallo la compilacion del catalogo")

    for ext in (".aux", ".log", ".out", ".tex"):
        (DIR_FIG / f"catalogo{ext}").unlink(missing_ok=True)
    print(f"[ok] {DIR_FIG / 'catalogo.pdf'}  ({len(pdfs)} figuras)")


if __name__ == "__main__":
    main()

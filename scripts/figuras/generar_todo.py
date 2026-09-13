#!/usr/bin/env python
"""Regenera TODAS las figuras y tablas de la memoria.

    conda run -n tfg_ia python scripts/figuras/generar_todo.py
    conda run -n tfg_ia python scripts/figuras/generar_todo.py --bloque regimenes

Los datos agregados que necesitan las figuras basadas en datos reales se
extraen aparte y una sola vez:

    conda run -n tfg_ia python scripts/figuras/extraer_datos.py

Si falta la cache, las figuras que dependen de ella se saltan con un aviso
y el resto se genera igual.

Salida:
    figuras/pdf/*.pdf      vectorial, para \\includegraphics en LaTeX
    figuras/png/*.png      200 dpi, para la presentacion y la revision rapida
    figuras/tablas/*.tex   tablas booktabs listas para \\input
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fig_atributos          # noqa: E402
import fig_conceptuales       # noqa: E402
import fig_datos              # noqa: E402
import fig_deeplearning       # noqa: E402
import fig_generalizacion     # noqa: E402
import fig_metodologia        # noqa: E402
import fig_regimenes          # noqa: E402
import fig_robustez           # noqa: E402
import tablas                 # noqa: E402
from estilo import DIR_PDF, DIR_PNG, DIR_TAB  # noqa: E402

BLOQUES = {
    "conceptuales": fig_conceptuales,   # F01-F05
    "datos": fig_datos,                 # F06-F10
    "metodologia": fig_metodologia,     # F11-F15
    "regimenes": fig_regimenes,         # F16-F20
    "deeplearning": fig_deeplearning,   # F21-F25
    "robustez": fig_robustez,           # F26-F29
    "atributos": fig_atributos,         # F30-F32
    "generalizacion": fig_generalizacion,  # F33-F36 (19-22 ago)
    "tablas": tablas,                   # T01-T12
}


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bloque", choices=list(BLOQUES), action="append",
                    help="genera solo estos bloques (por defecto: todos)")
    args = ap.parse_args()

    t0 = time.time()
    for nombre in (args.bloque or BLOQUES):
        BLOQUES[nombre].generar_todo()

    n_pdf = len(list(DIR_PDF.glob("*.pdf")))
    n_png = len(list(DIR_PNG.glob("*.png")))
    n_tex = len(list(DIR_TAB.glob("*.tex")))
    print(f"\n{n_pdf} figuras PDF, {n_png} PNG y {n_tex} tablas LaTeX "
          f"en {time.time() - t0:.1f} s")
    print(f"  {DIR_PDF}\n  {DIR_PNG}\n  {DIR_TAB}")


if __name__ == "__main__":
    main()

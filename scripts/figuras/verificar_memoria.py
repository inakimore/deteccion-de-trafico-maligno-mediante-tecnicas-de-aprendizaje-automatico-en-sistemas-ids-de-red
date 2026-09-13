#!/usr/bin/env python3
"""Audita que las cifras de la memoria coincidan con resultados.py.

POR QUE EXISTE
--------------
Las tablas y la prosa de la memoria llevan cifras escritas a mano. Eso es
deliberado -- se leen mejor y cada una se redacta para su contexto -- pero abre
la puerta a que se desalineen cuando un resultado se recalcula. Ya paso: la
tabla T03 arrastro durante semanas cifras de exactitud presentadas como
macro-F1, contradiciendo al capitulo 4 sin que nadie lo notara.

Este script cierra esa puerta. Recorre los .tex de la memoria y los generados en
figuras/tablas, extrae toda cifra decimal y todo entero con separador de millar,
y comprueba que exista en resultados.py, que es la fuente de verdad.

DOS NIVELES DE COMPROBACION
---------------------------
1. **Existencia** (todo el texto): cada cifra debe existir en resultados.py.
   Barato y amplio, pero no distingue el sitio: si una tabla intercambiase las
   columnas de payload y conducta, ambos numeros seguirian existiendo.

2. **Procedencia** (tablas anotadas): una tabla puede declarar de donde sale,

       % @fuente [R.SATURACION_INTRADIA[d]["payload"][0] for d in DIAS]

   y entonces se exige que la secuencia de cifras de su cuerpo coincida EN ORDEN
   con el resultado de esa expresion. Eso si detecta una transposicion, y obliga
   a que la tabla se actualice cuando cambie resultados.py.

Las tablas sin anotar se listan al final, para que se vea cuales quedan sin
cubrir por el nivel 2. Sigue sin ser un sustituto de leer: comprueba cifras, no
argumentos.

Uso:
    conda run --no-capture-output -n tfg_ia python -u \
        scripts/figuras/verificar_memoria.py
    ... --verbose     lista tambien los ficheros que cuadran
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
MEMORIA = RAIZ / "DIF_Dissertation_2026" / "chapters"
TABLAS = RAIZ / "figuras" / "tablas"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import resultados as R  # noqa: E402

# Cifras ajenas a los resultados: anos, tamanos del protocolo experimental y
# los redondeos que la prosa usa para no cansar al lector.
IGNORAR = {
    "2017", "2018", "2026", "2021", "2004", "2006", "1999",
    "0.5", "1.0", "0.0", "2.0", "7.4", "0.25", "1.48", "31.1", "32.6",
    "95", "99", "96", "24", "48", "64", "25", "256",
    "1.000", "2.000", "4.000", "5.000", "29.000",
    # Razones y aproximaciones del texto, no resultados medidos.
    "2.3", "2.5", "2.7", "2.9", "1.8", "0.2",
}

DECIMALES = (4, 3, 2)

# Plantilla del modelo de TFG, no contenido propio.
PLANTILLA = {"chap1.tex", "chap2.tex", "chap3.tex"}

# Un decimal: parte entera 0, o 4 digitos de fraccion, o 1-2 digitos. Nunca
# pegado a otro digito ni a otro punto, para no morder un grupo de millar.
PATRON_DEC = re.compile(
    r"(?<![\d.])(?:0\.\d{1,4}|\d+\.\d{4}|\d{1,3}\.\d{1,2})(?![\d.])")
# Un millar: grupos de exactamente tres digitos, y lo mismo respecto a vecinos.
PATRON_MILES = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{3})+(?![\d.])")
# Las direcciones IP, puertos y nombres de fichero viven en \texttt{}: sin
# descartarlos, `18.219.193.20` dispara el patron de millares.
PATRON_TEXTTT = re.compile(r"\\texttt\{[^}]*\}")


def valores_de_resultados():
    """Todos los numeros de resultados.py, como cadenas al estilo de la memoria.

    Se recorre el modulo entero en vez de enumerar diccionarios a mano: asi el
    auditor no se queda obsoleto cada vez que se anade un resultado nuevo.
    """
    vistos = set()

    def anotar(v):
        if isinstance(v, bool) or v is None:
            return
        if isinstance(v, (int, float)):
            for d in DECIMALES:
                vistos.add("%%.%df" % d % float(v))
            # Una proporcion se cita a menudo como porcentaje: 0.944 -> 94.4 %.
            if 0 <= float(v) <= 1:
                for d in (0, 1, 2):
                    vistos.add("%%.%df" % d % (float(v) * 100))
            if float(v).is_integer() and abs(v) >= 1000:
                vistos.add("{:,}".format(int(v)).replace(",", "."))

    def recorrer(o, prof=0):
        if prof > 6:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                anotar(k)
                recorrer(v, prof + 1)
        elif isinstance(o, (list, tuple, set)):
            for v in o:
                recorrer(v, prof + 1)
        else:
            anotar(o)

    for nombre in dir(R):
        if not nombre.startswith("_"):
            recorrer(getattr(R, nombre))
    return vistos


def a_float(cadena):
    """Interpreta la cadena aplicando la misma regla que los patrones."""
    try:
        if cadena.count(".") == 1:
            entera, frac = cadena.split(".")
            if entera.lstrip("-") == "0" or len(frac) != 3:
                return float(cadena)
        return float(cadena.replace(".", ""))
    except ValueError:
        return None


def diferencias(conocidas):
    """Diferencias entre pares de valores conocidos del intervalo [0, 1].

    Varias tablas calculan una columna al vuelo -- la caida del recall bajo
    evasion es `original - evadido` -- y ese resultado no esta en resultados.py
    ni tiene por que estarlo. Aceptarlas evita ruido sin relajar el criterio:
    sigue exigiendo que AMBOS operandos esten respaldados.
    """
    nums = sorted({n for n in (a_float(c) for c in conocidas)
                   if n is not None and 0 <= n <= 1})
    dif = {round(a - b, 4) for a in nums for b in nums if a >= b}
    # La memoria expresa algunas diferencias en puntos porcentuales: una caida
    # de 0.0720 se cita como 7.2 puntos.
    return dif | {round(d * 100, 2) for d in dif}


MARCA_IDIOMA = "@idioma en"


def cifras_de(texto):
    """Decimales y enteros con separador de millar, fuera de \\texttt{}.

    Si el fichero contiene la marca `% @idioma en`, se ignora todo lo que venga
    despues: ese bloque usa convenciones inglesas (punto decimal, coma de
    millar) y leerlo con las castellanas produce falsos positivos -- "17,203,272"
    se leeria como el millar "17,203".
    """
    if MARCA_IDIOMA in texto:
        texto = texto[:texto.index(MARCA_IDIOMA)]
    util = "\n".join(l for l in texto.splitlines()
                     if not l.lstrip().startswith("%"))
    util = PATRON_TEXTTT.sub(" ", util)
    return set(PATRON_DEC.findall(util)) | set(PATRON_MILES.findall(util))


# Nombres disponibles dentro de una expresion @fuente, para que la anotacion
# quede corta y legible en el .tex.
DIAS = ["14-02", "22-02", "16-02", "15-02", "20-02", "02-03"]
VISTAS = ["payload", "metadatos", "conducta"]

PATRON_FUENTE = re.compile(r"^\s*%\s*@fuente\s+(.+?)\s*$", re.MULTILINE)
PATRON_TABLA = re.compile(r"\\begin\{tabular\}.*?\\end\{tabular\}", re.DOTALL)


# En el cuerpo de una tabla se aceptan tres formas: entero con separador de
# millar, decimal con coma y entero suelto. El orden importa: 11.626 debe
# reconocerse entero antes de que el patron de enteros sueltos parta el 11.
# El orden importa: primero el decimal de cuatro cifras, porque "0.9842" tambien
# encaja en el patron de millar si se prueba antes.
PATRON_NUM_TABLA = re.compile(
    r"-?\d+\.\d{4}|-?\d{1,3}(?:\.\d{3})+|-?\d+\.\d{1,3}")


def cifras_de_tabla(cuerpo):
    """Cifras del cuerpo de una tabla, en orden de aparicion.

    Normaliza `{,}` -- la coma decimal en modo matematico -- y descarta el
    contenido de \\texttt{}, que son direcciones y no resultados.
    """
    limpio = PATRON_TEXTTT.sub(" ", cuerpo)
    # Las cabeceras van en negrita y a veces llevan cifras que no son datos,
    # como "F1 (umbral 0.5)". Se descartan.
    limpio = re.sub(r"\\textbf\{[^}]*\}", " ", limpio)
    return PATRON_NUM_TABLA.findall(limpio)


def fmt(v):
    """Formatea como la memoria: coma decimal, punto de millar."""
    if isinstance(v, float):
        return "%.4f" % v
    if isinstance(v, int):
        return "{:,}".format(v).replace(",", ".") if abs(v) >= 1000 else str(v)
    return str(v)


def comprobar_procedencia(f, texto):
    """Compara cada tabla anotada con @fuente contra su expresion.

    Devuelve (anotadas, fallos). Un fallo es (linea, esperado, encontrado).
    """
    anotaciones = list(PATRON_FUENTE.finditer(texto))
    if not anotaciones:
        return 0, []

    tablas = list(PATRON_TABLA.finditer(texto))
    # Las comprensiones de lista abren su propio ambito y solo miran a GLOBALS,
    # asi que R y los alias tienen que ir ahi, no en locals.
    ambito = {"__builtins__": {}, "R": R, "DIAS": DIAS, "VISTAS": VISTAS}
    fallos = []
    for m in anotaciones:
        linea = texto[:m.start()].count(chr(10)) + 1
        # La tabla que sigue a la anotacion.
        siguiente = next((t for t in tablas if t.start() > m.end()), None)
        if siguiente is None:
            fallos.append((linea, "(expresion sin tabla debajo)", ""))
            continue
        try:
            crudos = [fmt(v) for v in eval(m.group(1), ambito)]
            # Solo se contrastan las formas inequivocas: decimal con coma y
            # entero con separador de millar. Un entero suelto como "3" no se
            # puede distinguir de un trozo de etiqueta ("14-02" da 14 y 02).
            esperado = [c for c in crudos if PATRON_NUM_TABLA.fullmatch(c)]
        except Exception as e:  # noqa: BLE001 - se reporta, no se traga
            fallos.append((linea, f"(la expresion no evalua: {e})", ""))
            continue
        encontrado = cifras_de_tabla(siguiente.group(0))
        if encontrado != esperado:
            fallos.append((linea, " ".join(esperado), " ".join(encontrado)))
    return len(anotaciones), fallos


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    conocidas = valores_de_resultados()
    derivadas = diferencias(conocidas)
    print(f"resultados.py aporta {len(conocidas)} valores de referencia "
          f"y {len(derivadas)} diferencias admisibles.\n")

    ficheros = [f for f in sorted(MEMORIA.glob("*.tex")) if f.name not in PLANTILLA]
    ficheros += sorted(MEMORIA.glob("appendix/*.tex"))
    ficheros += sorted(TABLAS.glob("*.tex"))

    total_ok = total_ko = total_anotadas = 0
    hay_problemas = False
    for f in ficheros:
        cifras = cifras_de(f.read_text(encoding="utf-8", errors="replace"))
        ko = []
        for c in sorted(cifras):
            if c in conocidas or c in IGNORAR:
                continue
            x = a_float(c)
            if x is not None and round(x, 4) in derivadas:
                continue
            ko.append(c)
        total_ok += len(cifras) - len(ko)
        total_ko += len(ko)
        if ko:
            hay_problemas = True
        n_anot, fallos = comprobar_procedencia(f, f.read_text(encoding="utf-8",
                                                                errors="replace"))
        total_anotadas += n_anot
        if fallos:
            hay_problemas = True
        if args.verbose or ko or fallos:
            marca = "!!" if (ko or fallos) else "ok"
            print(f"[{marca}] {f.relative_to(RAIZ)}: "
                  f"{len(cifras) - len(ko)} cuadran, {len(ko)} sin respaldo, "
                  f"{n_anot} tabla(s) con procedencia")
            for c in ko:
                print(f"        sin respaldo: {c}")
            for linea, esperado, encontrado in fallos:
                print(f"        PROCEDENCIA linea {linea}:")
                print(f"          esperado:   {esperado}")
                print(f"          encontrado: {encontrado}")

    print(f"\nTotal: {total_ok} cifras respaldadas, {total_ko} sin respaldo.")
    print(f"Tablas con procedencia declarada: {total_anotadas}.")
    if hay_problemas:
        print("\nRevisar a mano. Puede ser (a) una cifra desfasada, (b) un valor "
              "derivado que resultados.py no guarda, o (c) un numero ajeno a los "
              "resultados que habria que anadir a IGNORAR.")
        sys.exit(1)
    print("Sin desfases detectados.")


if __name__ == "__main__":
    main()

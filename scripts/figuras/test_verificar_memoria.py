# -*- coding: utf-8 -*-
"""Prueba negativa del auditor: sin esto, "sin desfases" no significa nada.

Intercambia dos cifras de la tabla 4.2 -- exactamente el fallo que el nivel de
existencia NO detectaba, porque ambos numeros siguen existiendo en
resultados.py -- ejecuta el auditor y comprueba que falla. Luego restaura.
"""
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
CAP = RAIZ / "DIF_Dissertation_2026/chapters/04_regimenes.tex"
AUD = [sys.executable, "-u", "scripts/figuras/verificar_memoria.py"]
CWD = str(RAIZ)

ORIGINAL = "    14-02 cifrado       & 0.9842 & 0.9906 & 0.9985 \\\\"
TRANSPUESTA = "    14-02 cifrado       & 0.9985 & 0.9906 & 0.9842 \\\\"


def auditar():
    r = subprocess.run(AUD, cwd=CWD, capture_output=True, text=True)
    return r.returncode, r.stdout


copia = CAP.read_text(encoding="utf-8")
assert copia.count(ORIGINAL) == 1, "no encuentro la fila de la tabla 4.2"

print("1. Estado limpio:")
code, out = auditar()
print(f"   codigo de salida = {code} ({'pasa' if code == 0 else 'falla'})")
if code != 0:
    sys.exit("El auditor ya falla en limpio; la prueba no es concluyente.")

try:
    print("\n2. Inyectando una transposicion: payload <-> conducta en el dia 14-02.")
    print("   Ambas cifras SIGUEN EXISTIENDO en resultados.py, asi que el nivel")
    print("   de existencia por si solo no lo detectaria.")
    CAP.write_text(copia.replace(ORIGINAL, TRANSPUESTA), encoding="utf-8")
    code, out = auditar()
    print(f"   codigo de salida = {code} ({'pasa' if code == 0 else 'FALLA'})")
    for linea in out.splitlines():
        if "PROCEDENCIA" in linea or "esperado" in linea or "encontrado" in linea:
            print("   " + linea.strip()[:150])
    detectado = code != 0
finally:
    CAP.write_text(copia, encoding="utf-8")
    print("\n3. Capitulo restaurado.")

code, _ = auditar()
print(f"   auditor tras restaurar = {code} ({'pasa' if code == 0 else 'falla'})")

print("\nRESULTADO:", "el auditor DETECTA la transposicion."
      if detectado else "el auditor NO la detecta: la comprobacion no sirve.")
sys.exit(0 if detectado and code == 0 else 1)

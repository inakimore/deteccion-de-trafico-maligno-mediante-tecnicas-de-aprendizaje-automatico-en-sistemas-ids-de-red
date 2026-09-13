# -*- coding: utf-8 -*-
"""Pone las tildes que faltan en el TEXTO DIBUJADO de las figuras.

Las figuras se escribieron sin acentos y la memoria va acentuada, asi que en el
PDF conviven "error de calibracion" en el eje y "calibracion" acentuada en el
parrafo de al lado.

DOS CUIDADOS:

  1. Solo se tocan literales de cadena, con tokenize. Por linea seria peligroso:
     hay tuplas como (0,5) y nombres de variable que contienen estas palabras.

  2. Algunas cadenas son CLAVES que indexan resultados.py ("meta+rafaga",
     "Volumetrico (16-02, DoS)"). Acentuarlas romperia la busqueda, asi que se
     protegen: se listan aparte y se restauran despues de sustituir.

La comprobacion real es ejecutar generar_todo.py despues; si una clave se
rompiera, saltaria un KeyError.
"""
import io
import re
import tokenize
from pathlib import Path

DIR = Path(__file__).resolve().parent

# Palabras que en castellano llevan tilde y en las figuras no la llevaban.
# "solo", "mediana", "conexiones" y "posiciones" NO entran: son correctas.
PALABRAS = {
    "rafaga": "ráfaga", "rafagas": "ráfagas",
    "evasion": "evasión",
    "dia": "día", "dias": "días",
    "volumetrico": "volumétrico", "volumetricos": "volumétricos",
    "entropia": "entropía",
    "trafico": "tráfico",
    "conexion": "conexión",
    "precision": "precisión",
    "peticion": "petición", "peticiones": "peticiones",
    "maximo": "máximo", "minimo": "mínimo",
    "deteccion": "detección",
    "calibracion": "calibración",
    "aqui": "aquí",
    "mas": "más",
}

# Claves que indexan resultados.py: NO se pueden acentuar.
PROTEGIDAS = [
    "meta+rafaga", "meta+rafaga-IF", "rafaga sola", "meta + rafaga",
    "Volumetrico (16-02, DoS)", "Cifrado (14-02, SSH)", "En claro (22-02, Web)",
    "payload-hist", "conducta (meta+rafaga)", "conducta meta+rafaga",
]


def con_tilde(m: re.Match) -> str:
    """Sustituye conservando mayuscula inicial y mayusculas completas."""
    p = m.group(0)
    base = PALABRAS[p.lower()]
    if p.isupper():
        return base.upper()
    if p[0].isupper():
        return base[0].upper() + base[1:]
    return base


PAT = re.compile(r"\b(" + "|".join(sorted(PALABRAS, key=len, reverse=True))
                 + r")\b", re.IGNORECASE)


def arreglar(texto: str) -> tuple[str, int]:
    """Acentua el texto, dejando intactas las claves protegidas."""
    marcas = {}
    for i, clave in enumerate(PROTEGIDAS):
        marca = f"\x00{i}\x00"
        if clave in texto:
            texto = texto.replace(clave, marca)
            marcas[marca] = clave
    nuevo, n = PAT.subn(con_tilde, texto)
    for marca, clave in marcas.items():
        nuevo = nuevo.replace(marca, clave)
    return nuevo, n if nuevo != texto or n else 0


def main() -> None:
    total = 0
    for f in sorted(DIR.glob("fig_*.py")) + [DIR / "estilo.py", DIR / "tablas.py"]:
        src = f.read_text(encoding="utf-8")
        salida, n = [], 0
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            t = list(tok)
            if tok.type == tokenize.STRING:
                nuevo, k = arreglar(tok.string)
                if nuevo != tok.string:
                    t[1] = nuevo
                    n += k
            salida.append(tuple(t))
        if n:
            f.write_text(tokenize.untokenize(salida), encoding="utf-8")
            print(f"  {f.name}: {n}")
            total += n
    print(f"total: {total} tildes")


if __name__ == "__main__":
    main()

# Fase 2 - Ventaja hibrida: payload vs metadatos vs hibrido (Wednesday-14-02-2018)

Tres vistas entrenadas sobre los MISMOS flujos (MLP 256->128, balanceo
global por undersampling, 5-Fold CV + test held-out). La columna decisiva
es la **auditoria honesta** sobre el SSH benigno real (puerto 22): el
accuracy global iguala a todas las vistas (~0.9996) porque el benigno
balanceado es casi todo NO-SSH; solo el caso dificil las separa.

| Vista | CV accuracy | Test acc | FP sobre SSH benigno | Recall ataque SSH |
|-------|-------------|----------|----------------------|-------------------|
| payload | 0.99959 ± 0.00007 | 0.99965 | 1596/2022 (78.9%) | 100.0% |
| metadatos | 0.99951 ± 0.00009 | 0.99946 | 1579/2022 (78.1%) | 100.0% |
| hibrido | 0.99958 ± 0.00008 | 0.99965 | 1594/2022 (78.8%) | 100.0% |

**Lectura (resultado honesto, no el esperado):** con balanceo *global por
clase* las TRES vistas se comportan igual: accuracy ~0.9996 y, sobre el SSH
benigno real, ~78% de falsos positivos. Añadir metadatos NO arregla el caso
dificil. La causa no es la vista sino el PROTOCOLO de balanceo: como el
benigno balanceado es 99,9% NO-SSH, ninguna vista aprende a separar
SSH-ataque de SSH-benigno; todas aprenden "SSH/flujo-corto = ataque". El
espejismo del 0.9996 es estructural al balanceo, no exclusivo del payload.
Conclusion: para medir de verdad la aportacion de cada vista hay que
balancear POR SERVICIO (SSH-ataque vs SSH-benigno) -> es el paso 2.

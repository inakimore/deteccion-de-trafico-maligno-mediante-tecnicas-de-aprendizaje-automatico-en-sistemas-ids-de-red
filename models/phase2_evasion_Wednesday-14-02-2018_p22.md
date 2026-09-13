# Punto 3 - Prueba de evasion del fingerprint de payload (Wednesday-14-02-2018, :22)

Binario Attack vs Benign en :22, balanceado 1:1, split train/test (70/30). El atacante camufla los primeros **48 bytes** de cada flujo de ataque con los de un cliente benigno (spoofing trivial del banner/cabecera); el resto del flujo no cambia.

| Vista | Recall ataque (original) | Recall ataque (evadido) | Caida |
|-------|--------------------------|-------------------------|-------|
| payload (byte-CNN) | 1.0000 | 0.3538 | **0.6462** |
| conducta (meta+rafaga) | 1.0000 | 1.0000 | 0.0000 (invariante) |

**Lectura:** camuflando solo los primeros bytes (coste trivial para el atacante), el recall de la deteccion por **payload se desploma** -> la firma de bytes es un *fingerprint* de la herramienta (banner `paramiko` en SSH, User-Agents de Hulk en DoS), EVADIBLE. La vista **conductual (rafaga) es invariante** al spoofing de payload (no depende del contenido, sino del nº de conexiones por origen/tiempo), asi que su recall no cambia: es la firma ROBUSTA. Confirma empiricamente los HALLAZGOS 7/8/10 y la tesis: contra evasion, la deteccion robusta exige la vista conductual, no solo el payload.

# Catálogo de figuras y tablas para la memoria

Material visual del TFG **IDS-ML-Payload**, generado de forma reproducible a
partir de los resultados de `models/*.md` y de los datasets vectorizados.
**42 figuras + 12 tablas**, organizadas en 9 bloques que siguen el orden
natural de la memoria.

> Este documento es el índice de trabajo: dice qué es cada figura, **qué
> hallazgo sostiene**, dónde encaja en la memoria y de qué fichero salen sus
> números. La memoria todavía no está escrita; esto es el material para
> escribirla.

---

## Cómo se usa

Cada figura existe en dos formatos, con el mismo nombre:

| Carpeta | Formato | Para qué |
|---|---|---|
| `figuras/pdf/` | PDF vectorial | la memoria en LaTeX (no pixela al ampliar) |
| `figuras/png/` | PNG a 200 dpi | la presentación y la revisión rápida |
| `figuras/tablas/` | `.tex` (booktabs) | `\input` directo en la memoria |

En LaTeX:

```latex
% preámbulo
\usepackage{graphicx}
\usepackage{booktabs}          % requerido por las tablas

% figura
\begin{figure}[htbp]
  \centering
  \includegraphics[width=\textwidth]{figuras/pdf/F16_matriz_regimen_vista.pdf}
  \caption{...}
  \label{fig:regimenes}
\end{figure}

% tabla (trae ya su caption y su label)
\input{figuras/tablas/T03_resultados_regimen}
```

Las figuras están dimensionadas para una caja de texto de **15 cm** (la de la
plantilla `DIF_Dissertation_2026`), así que `width=\textwidth` las deja a
tamaño nativo, sin reescalar el texto. Las 12 tablas se han compilado una a
una para comprobar que ninguna se sale de la caja.

### Regenerar

```bash
# 1) agregados desde los datasets pesados (una sola vez, ~4 min)
conda run -n tfg_ia python scripts/figuras/extraer_datos.py

# 2) todas las figuras y tablas (~15 s)
conda run -n tfg_ia python scripts/figuras/generar_todo.py

# solo un bloque
conda run -n tfg_ia python scripts/figuras/generar_todo.py --bloque regimenes
```

---

## Bloque 0 — Diagramas conceptuales (F01–F05)

Explican el **método**. Van en Introducción y Metodología; sin ellas el lector
tiene que reconstruir el montaje experimental por su cuenta.

| ID | Figura | Qué muestra | Dónde |
|---|---|---|---|
| **F01** | `F01_pipeline` | De la captura PCAP al resultado, con los dos pasos que costaron un hallazgo: el saneado previo y el etiquetado por ground-truth | Metodología |
| **F02** | `F02_mapa_regimenes` | Los tres regímenes y dónde vive la firma en cada uno | Introducción · **portada de la defensa** |
| **F03** | `F03_arquitectura` | El híbrido de dos ramas y por qué la fusión es tardía | Fase 3 |
| **F04** | `F04_anatomia_flujo` | Qué es exactamente un ejemplo del dataset: la conexión TCP y sus cuatro vistas | Metodología |
| **F05** | `F05_cronologia` | Las tres fases y los seis hitos, que son correcciones de resultados propios | Introducción |

## Bloque 1 — Los datos (F06–F10)

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F06** | `F06_composicion_clases` | El desbalanceo real: 203 ataques web entre 2,7 M de flujos (1 de cada 13.684) | — |
| **F07** | `F07_servicios_por_dia` | Composición de protocolos por día, identificados por contenido | justifica H3 |
| **F08** | `F08_servicio_vs_puerto` | Puerto y contenido coinciden al 99,9 % en laboratorio, pero no siempre | corrección del tutor |
| **F09** ★ | `F09_error_ventana` | El atacante seguía actuando **después** del fin de ventana documentado, en dos días distintos | lección metodológica |
| **F10** | `F10_volumen_procesado` | Escala del trabajo: 6 días, ~150 GB, 9,4 M de flujos | — |

## Bloque 2 y 3 — Honestidad metodológica (F11–F15)

El bloque que da al trabajo su carácter. Cada figura desmonta un resultado
propio que parecía bueno.

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F11** | `F11_fase1_robustez` | El 99,99 % de la Fase 1 y el desplome del Slowloris a 0,80 al quitar las firmas mecánicas | cierre de Fase 1 |
| **F12** ★ | `F12_espejismo` | 99,96 % de accuracy **y** 96 % de falsos positivos sobre SSH legítimo: el mismo modelo, dos medidas | **H3** |
| **F13** | `F13_balanceo_global` | Las tres vistas son idénticas bajo balanceo global: el fallo es del protocolo, no de la vista | H3 |
| **F14** ★ | `F14_benigno_contaminado` | El «techo» de 0,61 era contaminación del benigno, no un límite de los metadatos | 17-jun |
| **F15** | `F15_composicion_benigno` | De qué estaba hecho el «benigno»: 78,6 % y 65,1 % era el propio atacante | lección metodológica |

## Bloque 4 — Los cuatro regímenes (F16–F20) · **núcleo de la tesis**

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F16** ★★ | `F16_matriz_regimen_vista` | **La figura central**: matriz régimen × vista. Ninguna vista gana en las tres filas | tesis completa |
| **F17** ★ | `F17_rafaga_distribucion` | La ráfaga separa 2 de 3 regímenes sin mirar un byte — y es ciega en el tercero | H8 · datos reales |
| **F18** | `F18_entropia_distribucion` | Por qué el payload es ciego al tráfico cifrado, medido sobre los datos | H3 · datos reales |
| **F19** ★ | `F19_inversion_web_ssh` | La inversión: los metadatos pierden 7 puntos al pasar al régimen en claro | **H4** |
| **F20** | `F20_dos_revisado` | El DoS antes y después de corregir el etiquetado | **H8 revisado** |

## Bloque 5 — Deep learning (F21–F25)

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F21** | `F21_dl_modelos` | byte-CNN frente a LSTM y a los baselines; la diferencia aparece en la tarea multiclase | **H5** |
| **F22** | `F22_multitipo_web` | El tipo de ataque vive en la secuencia: SQLi con recall 0,84 frente a 0,26 | 8-jul |
| **F23** | `F23_hibrido_ramas` | Fusión tardía de dos ramas frente a concatenación ingenua | **H6** |
| **F24** | `F24_saliency` | El 18,8 % inicial del flujo concentra el 31,1 % de la importancia: lee el banner, no el cifrado | **H7** |
| **F25** ★ | `F25_banners` | Los bytes reales: 2 banners en todo el ataque frente a 81 en el tráfico legítimo | **H7** · datos reales |

## Bloque 6 — Robustez (F26–F29)

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F26** ★ | `F26_evasion` | Camuflar los primeros bytes hunde el payload (1,00 → 0,35) y no afecta a la conducta | **H11** |
| **F27** | `F27_anomalia` | Sin etiquetas (zero-day), cada régimen esconde su señal en otra vista | **H12** |
| **F28** | `F28_rigor` | ROC-AUC con intervalos de confianza al 95 % por bootstrap | rigor |
| **F29** | `F29_cruzado` | El byte-CNN entrenado en 2018 detecta en 2017; los metadatos caen al azar | **H9 · H10** |

## Bloque 7 — Atributos del payload (F30–F32) · revisión del tutor

| ID | Figura | Qué muestra | Hallazgo |
|---|---|---|---|
| **F30** | `F30_atributos_vistas` | 19 descriptores interpretables valen lo que 257 dimensiones de histograma | **H13** |
| **F31** | `F31_atributos_separacion` | Qué descriptor separa en cada régimen, y por qué no son los mismos | H13 |
| **F32** | `F32_importancia_permutacion` | La unión payload + Zeek usa **de verdad** las dos familias | H13 |

★ = figura de alto impacto, recomendada también para la presentación.

---

## Bloque 8 — Generalización y límites del enfoque (F33–F36) · añadido el 22-ago

Las cuatro figuras de los hallazgos del 19-22 de agosto. Las genera
`fig_generalizacion.py`; todas leen de `resultados.py` salvo F34, que usa
`figuras/cache/perfil_*.npz`.

| Figura | Qué enseña | Hallazgo que sostiene |
|---|---|---|
| **F33** `cruzado_entre_dias` | *Heatmap* 6×3: entrenar en un día y testear en otro del mismo régimen. La columna del byte-CNN es **bimodal** (casi 1,0 o exactamente 0,5 con recall nulo); la del histograma es un **degradado** | **HALLAZGO 14** |
| **F34** `perfiles_temporales` | Perfil temporal de los tres días en escala log: el Hulk estalla, el LOIC mantiene una meseta alta y corta, el Bot late bajo durante 4 h con picos de órdenes | **HALLAZGO 15** |
| **F35** `ceguera_infiltracion` | Dos paneles: el 94,4 % del escaneo no lleva payload, y el `conn_state` explica por qué (82 % de `S0`) | **HALLAZGO 16** |
| **F36** `rafaga_diluida` | El contraste de ráfaga cae tres órdenes de magnitud según se reparte el ataque (×3.875 → ×5), y se invierte en el día web (×0) | Refinamiento del **HALLAZGO 8** |
| **F42** `arquitecturas` | Las arquitecturas del estado del arte (Transformer, atención cruzada) frente a las de este TFG: **el acierto empata, el coste no** (hasta 49×) | El componente de IA (24-ago) |
| **F41** `recalibracion` | Platt scaling con **25 etiquetas** del día nuevo: el F1 pasa de 0,333 a >0,97 en los cuatro pares colapsados y el ECE de ~0,499 a <0,03 | **HALLAZGO 14**, del diagnóstico a la receta |
| **F40** `fuga_ips` | Mismo modelo y mismos pares: añadir IPs y puerto de origen lleva el macro-F1 a **1,0000 en todas partes**, incluso donde la vista honesta se hunde | **HALLAZGO 18** (estado del arte) |
| **F39** `evasion_interarribo` | Qué vista sobrevive al camuflaje de los primeros bytes, y el aviso del día web: con 160 bytes no se evade, **se borra el ataque** | **HALLAZGO 17** (Eje E) |
| **F38** `calibracion_cruzada` | Por par entreno→test: F1 con el umbral heredado, F1 con el adecuado y AUC. El byte-CNN tiene AUC ≥ 0,97 en los seis pares y aun así da F1 = 0 en cuatro | **HALLAZGO 14**, versión final |
| **F37** `interarribo_beacon` | El beacon **medido**: dos modas de 50 ms concentran el 91 % de los intervalos del Bot, frente a la curva suave del benigno (×32 en la banda 0,50–0,55 s) | **HALLAZGO 15**, y el argumento definitivo del **Eje E** |

> **Nota de honestidad en F34.** El perfil agregado del Bot es plano, pero el del
> DDoS-LOIC **también**. La planitud no distingue por sí sola al *beaconing*: lo
> que lo distingue es sostener una tasa 17 veces menor durante 5,7 veces más
> tiempo. La figura dibuja los tres días juntos precisamente para no vender la
> planitud como si fuera exclusiva del Bot, y la nota al pie lo dice.

## Tablas (T01–T12)

| ID | Tabla | Contenido | Capítulo |
|---|---|---|---|
| **T01** | `T01_dias_dataset` | Los 6 días procesados, con flujos totales y de ataque | Datos |
| **T02** | `T02_ground_truth` | Ground-truth verificada empíricamente (atacante, víctima, ventana) | Datos |
| **T03** ★ | `T03_resultados_regimen` | **Tabla central**: cada vista en cada régimen | Resultados |
| **T04** | `T04_hallazgos` | Los 13 hallazgos clave | Conclusiones |
| **T05** | `T05_descriptores` | Los 19 descriptores del payload con su origen bibliográfico | Fase 3 |
| **T06** | `T06_servicio_vs_puerto` | Acuerdo entre puerto y contenido en los 6 días | Metodología |
| **T07** | `T07_dl_modelos` | Modelos profundos frente a baselines | Fase 3 |
| **T08** | `T08_evasion` | Recall antes y después de la evasión | Robustez |
| **T09** | `T09_cruzado` | Generalización cruzada entre datasets | Trabajo futuro |
| **T10** | `T10_rigor` | ROC-AUC con IC 95 % | Resultados |
| **T11** | `T11_atributos_payload` | Las 5 vistas de atributos en los 3 regímenes | Fase 3 |
| **T12** | `T12_fase1_benchmark` | Benchmark multiclase de la Fase 1 | Fase 1 |

---

## Cómo está hecho (para el capítulo de reproducibilidad)

```
scripts/figuras/
├── estilo.py            paleta, rcParams y helpers comunes
├── resultados.py        TODOS los números, con su fichero de procedencia
├── extraer_datos.py     recorre los .npz/.csv pesados y deja agregados en cache
├── fig_conceptuales.py  F01-F05      ├── fig_deeplearning.py  F21-F25
├── fig_datos.py         F06-F10      ├── fig_robustez.py      F26-F29
├── fig_metodologia.py   F11-F15      ├── fig_atributos.py     F30-F32
├── fig_regimenes.py     F16-F20      ├── tablas.py            T01-T12
└── generar_todo.py      orquestador
```

**Principio de diseño:** las figuras no calculan nada. Todos los números viven
en `resultados.py`, cada bloque anotado con el `models/*.md` que lo generó, de
modo que **cualquier cifra de la memoria es trazable hasta el script que la
produjo**. Si un resultado cambia, se re-ejecuta el script de
`scripts/zeek/`, se actualiza `resultados.py` y se regenera todo.

Las figuras basadas en datos reales (F09, F17, F18, F25) leen agregados
pequeños de `figuras/cache/`, no los 5,4 GB de datasets.

### Decisiones visuales

- **Paleta validada para daltonismo.** Azul / naranja / aqua superan los
  umbrales de separación en todos los pares y en todos los tipos de daltonismo
  (peor par ΔE 9,2 sobre un mínimo de 8), además del umbral de visión normal
  (24,0 sobre 15). Comprobado con un validador, no a ojo.
- **El color significa siempre lo mismo:** azul = payload/bytes y benigno;
  naranja = metadatos/conducta y ataque; aqua = híbrido; gris = contexto.
- **Etiqueta directa en cada barra**, para no obligar a ir al eje (y porque el
  aqua queda por debajo del umbral de contraste y lo exige).
- **Línea de azar visible** en toda figura de accuracy: sin ella, un 0,57
  parece un resultado cuando no lo es.
- **Nota al pie en cada figura** con el protocolo de evaluación y el fichero
  fuente: es lo que permite al tribunal saber sobre qué partición se midió.

---

## Avisos de contenido — leer antes de escribir

1. **Resultados obsoletos del día DoS.** El re-etiquetado del 11 de agosto
   invalidó las cifras del 16-02 medidas antes: el Eje A del 15-jul y las
   métricas de rigor del 7-ago. Están en `resultados.py` marcadas
   `_OBSOLETO` y se conservan **solo** para la comparación antes/después de
   F20. No usarlas como resultado del sistema. Las figuras F21 y F28 excluyen
   ese día a propósito, y lo dicen en su nota al pie.

2. **`SUMMARY.md` está desactualizado** (es del 7 de agosto). Dice que la firma
   del DoS da 0,81 y habla de «8 hallazgos»; tras la revisión del 11 de agosto
   son **13 hallazgos** y el DoS da 1,000 con benigno genuino. El estado
   correcto es el del `README.md` (entrada del 11 de agosto), que es lo que
   recoge `resultados.py`.

3. **El «benigno SSH» tiene dos tamaños según el criterio**: 433 flujos por
   puerto, 358 por contenido (DPI). Las figuras usan el criterio por puerto
   donde así se midió el experimento original, y lo indican. Al citar en la
   memoria, decir cuál de los dos se usa.

4. **Estado tras la revisión del 22 de agosto (seis días procesados).**

   **Hecho:** `resultados.py` incorpora los tres días nuevos y el 28-02 como
   caso sin `.npz`, los **cuatro regímenes**, la matriz de 6 pares
   (`CRUZADO_DIAS`), el *beaconing* (`BOT_BEACONING`), la ceguera de la
   Infiltration (`INFILTRACION_CEGUERA`), la dilución de la ráfaga
   (`RAFAGA_DILUIDA`, `RAFAGA_MEDIANA`) y la reutilización de IPs del
   laboratorio (`REUTILIZACION_IPS`). `extraer_datos.py` acepta los seis días y
   produce además `perfil_<dia>.npz`. **T01, T02 y T03** incluyen los días
   nuevos, y el **Bloque 8 (F33–F36)** cubre los tres hallazgos que faltaban.

   **Resuelto el 22-ago, despues de darlo por pendiente:**

   - **F16 ya tiene cuatro regímenes.** La fila del Bot era la duda («¿qué se
     pone donde ninguna vista mide la firma?») y resultó ser la más elocuente:
     las tres cifras son ~0,999 y las tres llevan el rótulo *«no mide la firma»*.
     Que una fila acierte del todo y aun así no sirva es el argumento, no un
     problema de la figura.
   - **F37 mide el *beaconing* de verdad.** Se creía que hacía falta el
     `conn.log` del Eje E, y era falso: el `.npz` guarda `ts` y `orig_h`, así que
     el inter-arribo por origen se calcula directamente. El resultado es más
     fuerte que el perfil agregado de F34: **dos modas de 50 ms concentran el
     91 % de los intervalos del Bot** (0,5 s y 2,0 s) frente a la curva suave
     del benigno — contraste ×32 en la banda 0,50–0,55 s.

   **Resuelto tambien el 22-ago, y cambio el hallazgo:**

   - **F38 mide la calibración**, que era la otra cosa dada por pendiente. Y el
     resultado **invierte el HALLAZGO 14**: el byte-CNN tiene AUC ≥ 0,97 en los
     seis pares, así que su representación **sí** transfiere; lo que no transfiere
     es el **umbral**. Los cuatro colapsos se recuperan enteros recalibrando
     (F1 ≥ 0,9849). El que falla de verdad es el histograma, cuyo AUC baja a 0,67
     y 0,80 en la dirección «→ 15-02» sin que el umbral óptimo lo rescate.

   **Lo que sigue pendiente de verdad:**

   - **El estado del arte** (prioridad 2) no tiene ninguna figura ni tabla, y no
     puede tenerla hasta que exista la búsqueda bibliográfica.
   - **La mitad del Eje E que necesita `conn.log`:** el `conn_state` y el abanico
     de destinos del HALLAZGO 16 no están en los `.npz` (el pipeline solo guarda
     flujos **con payload**, justo los que la Infiltration no genera), así que
     exigirían re-pasar Zeek. *La otra mitad —el inter-arribo— ya está hecha: ver
     F39 y el HALLAZGO 17.*

   **Aviso de maquetación:** la fila del 15-02 en T02 lleva los dos atacantes en
   una celda y es larga; conviene comprobar que no desborde el ancho de página.

   Para añadir un día nuevo basta una entrada en `DIAS_DISCO` (`extraer_datos.py`)
   y otra en `DIAS` (`resultados.py`), sin tocar el resto.

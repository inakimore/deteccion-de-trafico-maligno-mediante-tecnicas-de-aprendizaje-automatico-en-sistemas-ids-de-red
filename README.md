# Detección de tráfico maligno mediante técnicas de aprendizaje automático en sistemas IDS de red

Trabajo de Fin de Grado del Grado en Inteligencia Artificial, UPV/EHU.
Autor: Iñaki Moreno Estebanez. Director: Iñigo Perona Balda. Curso 2025-2026.

Este repositorio contiene el código con el que se obtuvieron todos los
resultados de la memoria: la extracción del tráfico, la construcción del
conjunto de datos, los modelos y los experimentos de evaluación.

## Qué hace este trabajo

Compara tres representaciones del tráfico de red —la distribución de bytes de la
carga útil, las características de flujo y una vista conductual— sobre siete días
del CSE-CIC-IDS2018 y tres del CIC-IDS2017, con un único protocolo de medida.

El resultado central es negativo: **dentro de un mismo día las tres saturan** por
encima de 0.97 y la comparación no discrimina entre ellas. La discriminación solo
aparece al perturbar las condiciones: camuflar los primeros bytes, cambiar de día
o cambiar de conjunto de datos.

## Cómo está organizado

| Ruta | Qué contiene |
|---|---|
| `scripts/zeek/` | El *pipeline* completo: saneado del PCAP, extracción con Zeek, vectorización, etiquetado, modelos y experimentos (37 *scripts*). |
| `scripts/figuras/` | Generación de las 42 figuras y 12 tablas de la memoria, más el auditor de coherencia. |
| `scripts/figuras/resultados.py` | **Fuente única de verdad.** Toda cifra que aparece en la memoria sale de aquí. |
| `models/*.md` | Los 62 informes de resultados que producen los experimentos. |
| `DIF_Dissertation_2026/` | La memoria en LaTeX. |
| `figuras/` | Figuras generadas, en dos variantes: anotada y para la memoria. |

## Reproducir los resultados

### Requisitos

- Python 3.11 con `numpy`, `scikit-learn`, `torch`, `xgboost`, `matplotlib`.
- Zeek, ejecutado sobre el contenedor oficial `zeek/zeek`. El *script* de
  extracción se apoya en el evento `tcp_packet`, que expone la cabecera y el
  cuerpo de cada segmento.
- Las capturas en bruto del CSE-CIC-IDS2018, que **no** se incluyen aquí: son
  unos 150 GB y se descargan del [CIC](https://www.unb.ca/cic/datasets/ids-2018.html).

```bash
conda create -n tfg_ia python=3.11
conda activate tfg_ia
pip install numpy scikit-learn torch xgboost matplotlib
```

### El pipeline, de la captura al conjunto de datos

```bash
# 1. Saneado. Obligatorio: sin el, Zeek trunca en silencio y pierde el ataque.
python scripts/zeek/repair_pcap.py --day Wednesday-14-02-2018

# 2. Extraccion de la carga util con Zeek (dentro del contenedor).
zeek -C -r captura.pcap scripts/zeek/extract_payload.zeek

# 3. Vectorizacion: una fila por conexion TCP, cinco representaciones.
python scripts/zeek/build_dataset.py --day Wednesday-14-02-2018

# 4. Etiquetado con la ground-truth verificada sobre las capturas.
python scripts/zeek/relabel_dataset.py --day Wednesday-14-02-2018
```

### Los experimentos

Cada uno escribe su informe en `models/` y sus cifras se recogen a mano en
`scripts/figuras/resultados.py`.

```bash
# Comparacion entre vistas con intervalos de confianza (capitulo 4).
python scripts/zeek/ic_caso_dificil.py --day Wednesday-14-02-2018

# Leave-one-attacker-out con control negativo y positivo (seccion 4.4).
python scripts/zeek/loao_eval.py --day Tuesday-20-02-2018

# Interpretabilidad y evasion (secciones 5.2 y 5.3).
python scripts/zeek/eval_saliency.py --day Wednesday-14-02-2018
python scripts/zeek/evasion_test.py --day Wednesday-14-02-2018 --prefijo 24

# Transferencia entre dias y recalibracion (seccion 5.6).
python scripts/zeek/cross_dataset_eval.py --train Friday-16-02-2018 --test Tuesday-20-02-2018
python scripts/zeek/cross_recalibration.py --train Friday-16-02-2018 --test Tuesday-20-02-2018

# Deteccion sin etiquetas de ataque (seccion 5.5).
python scripts/zeek/anomaly_detection.py --day Friday-16-02-2018

# Arquitecturas del estado del arte a presupuesto igualado (seccion 5.10).
python scripts/zeek/arquitecturas_eval.py --day Thursday-22-02-2018
python scripts/zeek/hyperparam_search.py --day Thursday-22-02-2018 --vista metadatos
```

### Regenerar la memoria

```bash
# Figuras y tablas. Sin la variable se generan las anotadas, con ella las de la memoria.
python scripts/figuras/generar_todo.py
FIGURAS_MEMORIA=1 python scripts/figuras/generar_todo.py

# Auditor: comprueba que cada cifra de la memoria sale de resultados.py.
python scripts/figuras/verificar_memoria.py

# La memoria.
cd DIF_Dissertation_2026 && pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## Una nota sobre las cifras

Ninguna cifra de la memoria está escrita a mano sin respaldo. `resultados.py`
recoge lo que producen los experimentos, y `verificar_memoria.py` recorre los
capítulos y las tablas comprobando que cada número aparece allí. El auditor tiene
además su propio test negativo, `test_verificar_memoria.py`, que le inyecta un
error deliberado y comprueba que lo detecta, para que un resultado en verde no
pueda ser un falso verde.

## Advertencia sobre los datos

Los resultados anteriores al 24 de agosto de 2026 se obtuvieron con un conjunto
benigno contaminado por tráfico del propio atacante, y **no son comparables** con
los de la memoria. El error, cómo se detectó y por qué no se manifiesta como un
fallo sino como un resultado plausible, se describe en la sección 3.6 de la
memoria y en el diario que sigue.

---

# Diario de seguimiento

Lo que sigue es el diario de trabajo del proyecto, conservado tal cual. No es
documentación de uso: es el registro de lo que se fue probando, descartando y
corrigiendo, y se mantiene porque varias de las conclusiones de la memoria salen
de errores que están anotados aquí.

> **Importante.** Al conservarse tal cual, el diario contiene conclusiones que el
> propio trabajo corrigió después. No están erratadas a propósito: se dejan para
> que el proceso sea legible. **La memoria es la versión buena de cada una de
> ellas.** Los dos casos más visibles:
>
> - El diario afirma que el byte-CNN es «frágil de forma binaria» entre días. Es
>   falso, y medirlo con el AUC en lugar de con el F1 de umbral fijo fue lo que
>   lo desmintió: la representación transfiere (AUC por encima de 0.9724), lo que
>   no transfiere es el umbral. Sección 5.6 de la memoria.
> - El diario asigna a cada régimen una «vista ganadora». La medición uniforme la
>   desmiente en tres de las cuatro filas: dentro del día las tres vistas saturan
>   y la comparación no discrimina. Secciones 4.3 y 4.4.


**Documentación y Diario de Seguimiento: TFG IA Iñaki Moreno**

Trabajo de Fin de Grado centrado en la detección de intrusiones en redes (IDS) basado en el dataset **CIC-IDS-2018**. El proyecto construye un modelo híbrido capaz de identificar múltiples tipos de ciberataques frente al tráfico legítimo.

## Resumen del Proyecto

Este TFG desarrolla un sistema avanzado de detección de intrusiones mediante una metodología dividida en tres fases:

1. **Fase 1 (Baseline):** Clasificación mediante características estadísticas y metadatos de flujo (archivos CSV).
2. **Fase 2 (Innovación):** Análisis de payload en crudo (archivos PCAP), tratando el contenido de los paquetes como secuencias de bytes para detectar patrones que los metadatos ignoran. Con seis días de regímenes distintos (fuerza bruta cifrada, ataques web en claro, tres variantes volumétricas y una botnet) se caracteriza **dónde vive la firma** de cada tipo de ataque. La tesis central —*ninguna vista basta por sí sola; la detección robusta exige combinar payload y conducta*— **no la sostiene la comparación de aciertos dentro del día**, que está saturada y no discrimina (HALLAZGO 19), sino la prueba de evasión, la transferencia entre dominios y los ataques que sencillamente no dejan payload que analizar.
3. **Fase 3 (Profundización en IA):** Deep learning de verdad sobre la secuencia de bytes (byte-CNN / BiLSTM), un modelo híbrido de dos ramas con fusión aprendida, interpretabilidad (saliency) y un benchmark **multidía / multiataque** de **seis días** con **cuatro regímenes de firma** según dónde vive la firma del ataque (conducta, contenido, agregado y periodicidad). Incluye la prueba que más aprieta: la **generalización entre días del mismo régimen**, donde el byte-CNN resulta **frágil de forma binaria** —o transfiere casi perfecto o colapsa a recall nulo, sin término medio (HALLAZGO 14). *(Ejes A/B/C/D ejecutados — ver la sección «Fase 3».)* **[CORREGIDO DESPUÉS: era un artefacto de medir con umbral fijo. El AUC no baja de 0.9724 en ningún par, así que la representación sí transfiere y lo que no transfiere es el umbral. Ver la sección 5.6 de la memoria.]**

> **Estado (24 de agosto):** **seis días procesados** del CSE-CIC-IDS2018 y **cuatro
> regímenes de firma** identificados según **dónde vive la firma del ataque**: conducta
> (fuerza bruta cifrada), contenido (web en claro), agregado (volumétrico) y periodicidad
> (botnet).
>
> **El hallazgo que reordena el argumento (HALLAZGO 19, 24-ago):** medidas las **mismas tres
> vistas con la misma métrica y el mismo protocolo en los seis días**, la evaluación
> **intra-día está saturada** —el payload no baja de 0,973 y la conducta no baja de 0,982 en
> ningún día—, de modo que **no discrimina entre vistas**. La causa es que cada día tiene
> **un solo host atacante**, así que cualquier vista memoriza lo idiosincrásico de ese host
> (el atajo de Engelen). Un 0,99 ahí no significa que el problema esté resuelto: significa
> que la pregunta está mal planteada. Donde sí se discrimina es en la **robustez**: al
> camuflar los primeros bytes el payload cae a **0,0025** en el Bot y a **0,0108** en el
> LOIC, mientras la conducta es invariante.
>
> Junto a él, los tres hallazgos de la tanda anterior siguen en pie: el **byte-CNN es frágil
> de forma binaria** entre días del mismo régimen —o transfiere casi perfecto o colapsa a
> recall 0, sin término medio, mientras el histograma se degrada con suavidad
> (**HALLAZGO 14**, enunciado con 2 días y **corregido con 6 pares**)—, la firma del Bot
> **no la mide ninguna vista actual** (**HALLAZGO 15**), y el análisis de payload es **ciego
> por construcción al 94,4% de la Infiltration** (**HALLAZGO 16**), el argumento más fuerte
> de la tesis y llegado por la vía del resultado negativo. El orden de trabajo lo re-prioriza
> el autor: primero más días, luego estado del arte, luego gráficos, y la memoria al final.
> Ver el diario del 24 de agosto y el «Plan de cierre».
>
> *(Estado previo, 11 de agosto: aplicada la revisión del tutor — el **servicio** sustituye
> al **puerto** como criterio de selección y se añaden **19 atributos del payload** tomados
> de la literatura.)*

## Enlaces de Referencia

- **GitHub (repositorio de trabajo, privado):** el repositorio público con el
  código de la memoria es este mismo.

## Calendario de Hitos (Convocatoria de Septiembre)

- **Fecha límite de matriculación:** 1 de septiembre
- **Primera versión de la memoria para revisión del tutor:** **finales de agosto**
  *(indicación del tutor del 11 de agosto: es la prioridad número 1)*
- **Entrega de la memoria y proyecto:** **6 de septiembre** *(fecha corregida el 11 de
  agosto por indicación del tutor; el README decía 9 de septiembre)*
- **Defensa del TFG:** 16 al 25 de septiembre

## Infraestructura y Software Utilizado

El laboratorio técnico se apoya en las siguientes herramientas para garantizar un desarrollo profesional:

- **Miniconda:** Gestión de entornos virtuales aislados (`tfg_ia`). Permite instalar librerías de IA sin interferir con el sistema operativo y asegura que el proyecto sea reproducible.
- **VS Code (Visual Studio Code):** Entorno de desarrollo integrado. Utiliza extensiones de Jupyter para la experimentación interactiva y visualización de datos en tiempo real.
- **Git & GitHub:** Control de versiones. Permite mantener un historial de cambios del código y disponer de un respaldo de seguridad en la nube (excluyendo datos pesados).
- **AWS CLI:** Interfaz de comandos para la transferencia eficiente de datasets masivos desde los buckets S3 de Amazon.
- **Docker & Zeek:** Contenedores para procesar archivos de tráfico de red (`.pcap`) y extraer el payload en crudo de forma aislada y eficiente. En uso desde la Fase 2 (mayo); ver el diario y la sección «Pipeline de Fase 2».

## Diario de Actividad

### [26 de Marzo] - Configuración de Laboratorio y Datos Iniciales

**Objetivos:** Establecer la infraestructura base y descargar los datos para el primer caso de estudio.

**Hitos alcanzados:**

- Creación del entorno virtual `tfg_ia` e instalación de librerías: pandas, scikit-learn, jupyter.
- Configuración de la estructura de directorios: `/data/raw`, `/data/processed`, `/notebooks`, `/models`.
- Descarga del dataset PCAP (37GB) y CSV (300MB) correspondientes al primer vector de ataque (Brute Force 14-02-2018).
- Inicialización del repositorio Git y configuración de `.gitignore` para protección de datos masivos y otros datos.
- Verificación de integridad: Carga y lectura exitosa del primer DataFrame en VS Code.

**Bloqueos técnicos y soluciones:**

- **Acceso a S3:** Errores de ruta por espacios en los nombres de carpeta de Amazon. Solucionado mediante el uso de comillas dobles en las strings de comando.
- **Visibilidad de Conda en VS Code:** La terminal integrada no detectaba el entorno. Solucionado iniciando el editor desde la terminal activa mediante `code .` para heredar las variables de entorno.

---

### [31 de Marzo] - Exploración, Baseline y Data Leakage

**Objetivos:**

- Validar la clasificación binaria de tráfico (Fuerza Bruta vs Benigno).
- Comprobar empíricamente la existencia de fuga de datos (Data Leakage) en CIC-IDS-2018.

**Hitos alcanzados:**

- **Preprocesamiento:** Carga y limpieza de datos (valores inf/NaN, nulos). Binarización de la variable Label y eliminación de Timestamp.
- **Modelado Base:** División train/test (80-20) y entrenamiento inicial del clasificador RandomForest. Extracción del Top 10 de Feature Importances.
- **Experimentos Comparativos (Ablación):** Se realizaron pruebas de variable única y eliminación de la dominante (`Dst Port`) para aislar variables "atajo".
- **Análisis Honesto:** Reentrenamiento del modelo con un dataset purgado de columnas propensas a atajos (`Dst Port`, `Protocol`, `Timestamp`).

**Bloqueos técnicos y soluciones:**

- **Incidencia:** Sospecha de que las métricas casi perfectas del modelo base provenían de variables que facilitan atajos (ej. memorizar el puerto) en lugar de señales conductuales.
- **Solución:** El diseño experimental confirmó la hipótesis de fuga. Al realizar el "análisis honesto" (sin las variables de fuga), el rendimiento se mantuvo alto, demostrando que existen señales conductuales reales (como el tamaño de los paquetes) en la estructura del ataque de Fuerza Bruta.

> **Nota retrospectiva (11 de agosto, revisión del tutor):** la exclusión de `Dst Port`
> se hizo aquí por un motivo empírico (era una variable-atajo que inflaba las métricas),
> pero tiene además una justificación **metodológica** que conviene explicitar en la
> memoria: *el puerto, igual que la IP, depende de la configuración de cada red y no es
> un atributo «context independent»*. Un modelo que lo use no generaliza a una red donde
> los servicios escuchen en otros puertos. Lo que sí es un atributo legítimo es el
> **servicio**, siempre que se identifique por el **contenido** del tráfico (que es lo
> que hacen los analizadores de Zeek). Ver el diario del 11 de agosto.

---

### [27 de Abril] - Benchmark Multiclase, Prueba de Robustez Extrema y Cierre de la Fase 1

**Objetivos:**

- Ampliación del dataset mediante la ingesta dinámica de múltiples archivos CSV (Wednesday y Thursday).
- Implementación de clasificación multiclase y evaluación comparativa (5-Fold Stratified CV) usando Decision Tree, Random Forest y XGBoost.
- Realizar una "Prueba de Robustez Extrema" (Análisis Súper Honesto): eliminar variables de firmas mecánicas (tiempos y tamaños de paquete) y aplicar Undersampling para corregir el desbalanceo masivo de clases.

**Hitos alcanzados:**

- **Generalización y Falso Éxito:** Se integraron ataques volumétricos con ataques Web y DoS. Inicialmente, los modelos mantuvieron un ~0.9999 de precisión, lo que evidenció el "Síndrome del Script" (la IA memoriza el tamaño exacto de los paquetes de las herramientas de ataque).
- **Desenmascarando el Modelo:** Al vendar los ojos al algoritmo (eliminando variables clave como `Init_Win_bytes` o `Fwd Seg Size Min`) y balancear el dataset igualando todas las clases a 8.792 filas, se obligó a XGBoost a predecir basándose en el comportamiento real.
- **Descubrimiento de Fragilidad:** La precisión del ataque sigiloso (Slowloris) cayó drásticamente al 0.80. Se constató que, sin las muletas mecánicas, el modelo confunde el ataque con tráfico benigno lento, generando un 20% de Falsos Positivos (lo que en un entorno real causaría inasumible "Fatiga de Alertas").

**Bloqueos y soluciones:**

- **Incidencia:** Limitaciones de memoria RAM al intentar procesar casi 2 millones de filas simultáneamente y errores de extensión al descargar de AWS CLI.
- **Solución:** Descarga directa controlada, renombrado manual, y uso de la técnica de Undersampling (imbalanced-learn). Esta última no solo balanceó las clases de forma justa, sino que redujo el tamaño de los datos a ~40.000 filas, bajando los tiempos de entrenamiento de minutos a apenas segundos.

**Conclusión Definitiva de la Fase 1 (Justificación para la Memoria):**

Queda demostrado matemáticamente que los sistemas basados exclusivamente en metadatos son altamente vulnerables a técnicas de evasión u ofuscación que alteren la morfología externa del paquete. Cae el mito del 99.99%. Esto cierra la Fase 1 y justifica de forma irrefutable el salto a la Fase 2: el análisis profundo y semántico del Payload en crudo mediante Deep Learning.

---

## Resultados del Benchmark (27 de Abril)

### A. Benchmark Multiclase (5-Fold CV - Sin Balancear)

El modelo se beneficia del desbalanceo y de las firmas mecánicas.

| Modelo | Mean Accuracy | Desviación Estándar (±) |
|--------|---------------|------------------------|
| Decision Tree | 0.99986 | 0.00002 |
| Random Forest | 0.99992 | 0.00001 |
| XGBoost | 0.99993 | 0.00002 |

### B. Prueba de Robustez (XGBoost Súper Honesto + Undersampling)

Eliminadas firmas del script e igualadas todas las clases.

- **Tráfico Benigno / Fuerza Bruta:** Precisión del 1.00 (el modelo encuentra patrones secundarios).
- **Ataque DoS-Slowloris (Low-Rate):** Precisión se desploma al 0.80 y el F1-Score al 0.89. (Aparición de Falsos Positivos).

---

### [28 de Abril] - Inicio Fase 2: Aprobación de Tutor y Definición de Estrategia Payload

**Objetivos:**

- Validar las conclusiones de la Fase 1 con el tutor académico.
- Definir las herramientas y métodos de representación de datos para la Fase 2 (Deep Learning sobre PCAPs).

**Hitos alcanzados:**

- **Validación de Fase 1:** El tutor confirmó la validez de la caída de precisión ante el ataque Slowloris, ratificando que al no ser de tipo flood (inundación), los metadatos pierden eficacia, justificando técnicamente el salto a la Fase 2.
- **Definición de Infraestructura:** Se descarta el uso de librerías nativas de Python (como Scapy) por su lentitud en favor de Zeek ejecutado sobre contenedores Docker. Zeek permitirá procesar archivos `.pcap` masivos mediante scripts personalizados para extraer el evento `tcp_packet` y su payload asociado.
- **Estrategia de Vectorización (Feature Engineering):** Se definen los dos primeros enfoques para traducir el Payload a entradas de Deep Learning:
  1. **Distribución de bytes y entropía:** Útil para detectar la ofuscación y aleatoriedad típica del tráfico malicioso.
  2. **Secuencia de bytes / n-gramas:** Uso de ventana deslizante (Sliding-window) de longitud fija (ej. 256 bytes) sobre el contenido crudo.

**Próximos pasos operativos:**

1. Instalar Docker en el entorno de desarrollo y descargar la imagen oficial de Zeek.
2. Escribir un script de Zeek (`.zeek`) basado en el evento `tcp_packet` para leer los PCAP del miércoles y volcar el payload TCP en crudo a un TSV cargable.
3. Montar un orquestador reproducible (Python + Docker) que procese las capturas del día por fases y verificar la cadena PCAP → Zeek → TSV decodificando tráfico real. *(La vectorización histograma+entropía se aborda a continuación, el 6 de mayo, una vez asentada la extracción.)*

---

### [5 de Mayo] - Pipeline de Extracción de Payload con Zeek sobre Docker (Wednesday 14-02-2018)

**Objetivos:**

- Montar la infraestructura de la Fase 2 siguiendo el material `docker_zeek.pdf`: contenedor oficial `zeek/zeek` y script personalizado basado en el evento `tcp_packet`.
- Construir un flujo reproducible que extraiga el payload TCP en crudo de las capturas del primer día (Brute Force, 14-02-2018) y dejarlo en un formato cargable para la vectorización posterior.

**Hitos alcanzados:**

- **Script Zeek personalizado** ([scripts/zeek/extract_payload.zeek](scripts/zeek/extract_payload.zeek)): por cada paquete TCP con datos (`len > 0`) escribe una fila con `ts`, la 5-tupla de conexión, la dirección (`orig`/`resp`), el tamaño y el `payload_hex`. Se emplea el **Log framework** de Zeek en lugar de `print`, que escapaba los tabuladores como `\x09`; así se obtiene un TSV limpio con cabecera `#fields`/`#types`.
- **Orquestador en Python + Docker** ([scripts/zeek/run_zeek_payload.py](scripts/zeek/run_zeek_payload.py)): recorre los 449 PCAP del miércoles (≈46 GB), monta los volúmenes y ejecuta `zeek -C -r ...` por captura, dejando un TSV por fichero en `data/processed/zeek/wednesday-14-02-2018/`. Incorpora filtros (`--limit`, `--smallest`, `--only`, `--force`) para trabajar por fases sin procesar todo el dataset de golpe.
- **Utilidades de soporte:** [scripts/zeek/repair_pcap.py](scripts/zeek/repair_pcap.py) para sanear capturas truncadas y [scripts/zeek/decode_payload.py](scripts/zeek/decode_payload.py) para leer los payloads en texto/hexdump filtrando por puerto o dirección.
- **Verificación funcional:** se confirmó el formato libpcap (magic `d4c3b2a1`), se procesaron varias capturas y se decodificó tráfico HTTP en claro real (p. ej. `GET /latest/meta-data/instance-id HTTP/1.1`), validando que la cadena PCAP → Zeek → TSV → decodificación funciona de extremo a extremo.

**Bloqueos técnicos y soluciones:**

- **Path-mangling de Git Bash con Docker:** al ejecutar el comando `docker run` **desde la terminal Git Bash**, las rutas internas del contenedor (`/scripts`, `/pcap`) se traducían a rutas de Windows (`C:/Program Files/Git/scripts`) y rompían los montajes. (Docker Desktop como tal se arranca aparte; el problema era únicamente el shell desde el que se invocaba `docker`.) **Solución:** orquestar el contenedor desde Python con `subprocess`, que no aplica esa traducción, en lugar de un wrapper `.cmd`/Bash.
- **Capturas truncadas (`truncated dump file`):** las capturas de CSE-CIC-IDS2018 terminan con el último record cortado, lo que hace que Zeek aborte al llegar al final. **Solución y comprobación:** se verificó que Zeek vuelca **todo** el log antes de abortar (mismo número de paquetes, 1027, que tras sanear la captura con `repair_pcap.py`), por lo que el orquestador trata ese caso como benigno y **no se pierde payload**. El saneado queda como opción para obtener una copia limpia sin avisos.

**Próximos pasos operativos:**

1. Implementar la vectorización definida el 28 de abril sobre los TSV: histograma de bytes + entropía y secuencias/n-gramas con ventana deslizante (`build_dataset.py`).
2. Etiquetar los flujos cruzando la 5-tupla y el `timestamp` con las etiquetas del CSV para preparar el dataset de Deep Learning. *(Corregido el 6 de mayo: el CSV no trae IPs, así que el join por 5-tupla no es posible; se etiqueta con ground-truth documentada. Ver la entrada del 6 de mayo y la sección «Pipeline de Fase 2».)*
3. Procesar el resto del conjunto del día (por fases) y consolidar los TSV de payload para ampliar el tráfico benigno.

---

### [6 de Mayo] - Vectorización y Etiquetado del Payload: del TSV al Dataset de Deep Learning

**Objetivos:**

- Convertir los TSV de payload del miércoles en un dataset etiquetado y vectorizado, implementando los próximos pasos del 5 de mayo (consolidación, vectorización y etiquetado).

**Hitos alcanzados:**

- **`uid` de conexión en Zeek:** se añadió el identificador único de conexión (`c$uid`) a [extract_payload.zeek](scripts/zeek/extract_payload.zeek) para poder agrupar paquetes por flujo de forma exacta (los puertos de origen se reutilizan masivamente en fuerza bruta).
- **Configuración de etiquetas** ([attack_metadata.py](scripts/zeek/attack_metadata.py)): ground-truth por día (IP atacante/víctima, puerto, ventana temporal) y conversión de zona horaria. Extensible añadiendo un día nuevo al diccionario.
- **Constructor de dataset** ([build_dataset.py](scripts/zeek/build_dataset.py)): por cada flujo TCP calcula histograma de bytes (256), entropía de Shannon y secuencia de los primeros 256 bytes, asigna la etiqueta y guarda `dataset_<dia>.npz` + `dataset_<dia>_meta.csv`.
- **Verificación funcional:** el etiquetador se probó con flujos sintéticos (atacante→víctima:21 en ventana → `FTP-BruteForce`; fuera de ventana → `Benign`). El dataset generado tiene histogramas normalizados (suma=1) y entropía coherente (SSH benigno ≈ 8.0 bits/byte).

**Bloqueos técnicos y soluciones:**

- **El CSV no tiene IPs:** los CSV de CICFlowMeter solo traen `Dst Port`, `Protocol`, `Timestamp` y `Label`, no las IPs. **Solución:** etiquetar por ground-truth documentada (IP+puerto+ventana) en lugar de un join por 5-tupla, que es imposible.
- **Desfase horario:** los PCAP están en UTC y el CSV/documentación en UTC-4 (verificado: CSV `08:31` ↔ PCAP `12:30 UTC`). Se codifica `tz_offset_hours = -4` para convertir las ventanas.
- **`conda run` con `-c` multilínea:** falla en este entorno; las verificaciones se hacen con ficheros `.py`.

**Hallazgo clave (relevante para la memoria):**

- El **FTP-BruteForce del 14-02 no tiene payload**: las 134.945 conexiones del atacante (`18.221.219.4 → 172.31.69.25:21`) están en estado `REJ` con 0 bytes (el servicio FTP estaba caído y rechazó todos los intentos). El análisis de payload es **ciego** a este ataque en esta captura, lo que demuestra empíricamente que el enfoque de payload necesita complementarse con metadatos para ataques que no intercambian datos de aplicación. El payload real del SSH-Bruteforce (cifrado, con datos) está en capturas de la tarde aún por procesar.

**Próximos pasos operativos:**

1. Localizar y procesar las capturas con el SSH-Bruteforce de la tarde para obtener payload de ataque etiquetable.
2. Consolidar el dataset del miércoles procesando el resto de capturas por fases.
3. Entrenar un primer modelo de Deep Learning (histograma+entropía y secuencial) y compararlo con el baseline de metadatos de la Fase 1.

---

### [7 de Mayo] - SSH-Bruteforce Recuperado y Corrección de Pérdida Silenciosa de Datos

**Objetivos:**

- Obtener payload de ataque etiquetable (paso 1 del 6 de mayo): localizar y procesar el SSH-Bruteforce.

**Hitos alcanzados:**

- **Herramienta de localización** ([find_host.py](scripts/zeek/find_host.py)): barrido binario rápido (66 s para los 46 GB) que cuenta apariciones de una IP por captura. Confirmó que el atacante FTP `18.221.219.4` solo aparece en `UCAP172.31.69.25`.
- **Atacante SSH identificado:** el SSH-Bruteforce **no** viene de `18.221.219.4` (como asumía la documentación), sino de **`13.58.98.64`** (otro host AWS), contra la misma víctima `172.31.69.25:22`, en la ventana 18:01–19:32 UTC. Descubierto empíricamente con `conn.log`.
- **Dataset con ataque real:** tras recuperar la captura completa, el dataset pasa de *4.313 flujos todos benignos* a **94.482 flujos**: 92.618 `SSH-Bruteforce` (con payload cifrado), 1.864 `Benign`, 0 `FTP-BruteForce` (REJ).
- **Pipeline corregido:** `run_zeek_payload.py` ahora **sanea cada captura antes de Zeek** (repair-first).

**Bloqueo técnico crítico y solución (pérdida silenciosa de datos):**

- **Incidencia:** se creía que las capturas solo se truncaban al final sin pérdida. Era **falso**: en `UCAP172.31.69.25` Zeek se detenía a las 18:05 UTC por un record intermedio que libpcap rechaza, perdiendo **toda la tarde en silencio** (129.546 paquetes extraídos frente a **2.924.653** reales) — incluida la ventana entera del SSH-Bruteforce.
- **Diagnóstico:** el rango temporal de lo extraído (hasta 18:05) no coincidía con el rango real de la captura (hasta 20:30); `repair_pcap` sí leía el fichero completo.
- **Solución:** sanear (reescribir solo records válidos) **antes** de cada ejecución de Zeek. Sobre la copia saneada Zeek procesa el fichero entero (exit 0) y aparecen los 2,9 M de paquetes y el ataque SSH completo. La corrección invalida la nota anterior («sin pérdida») y queda documentada en la sección «Pipeline de Fase 2».

**Hallazgo para la memoria:**

- Los dos ataques de fuerza bruta del día son **opuestos respecto al payload**: el FTP no exporta datos (REJ → invisible al análisis de payload) y el SSH sí (handshakes cifrados, alta entropía). Es un argumento directo para el enfoque híbrido payload + metadatos.

**Próximos pasos operativos:**

1. Balancear clases (undersampling, como en la Fase 1) y entrenar el primer modelo de Deep Learning sobre el dataset de payload (histograma+entropía y secuencial).
2. Procesar el resto de capturas del miércoles (ya con saneado automático) para ampliar el tráfico benigno y consolidar el dataset.
3. Pasar al siguiente día del dataset (añadir su ground-truth a `attack_metadata.py` tras verificar IPs).

---

### [9 de Mayo] - Primer Modelo de Deep Learning sobre Payload y Consolidación del Día Completo: el Espejismo del 99,96%

**Objetivos:**

- Implementar el paso 1 del 7 de mayo: balancear las clases y entrenar el primer modelo de Deep Learning sobre el payload (histograma+entropía y secuencial).
- Consolidar el **día completo** procesando las 449 capturas del miércoles, para entrenar con tráfico benigno diverso (no solo SSH) y validar las conclusiones.

**Hitos alcanzados:**

- **Entrenador de la Fase 2** ([train_phase2.py](scripts/zeek/train_phase2.py)): carga `dataset_<dia>.npz`, balancea con `RandomUnderSampler` (igual que la Fase 1), entrena **dos redes neuronales** (`MLPClassifier`, capas 256→128) —una sobre `X_hist`+entropía y otra sobre la secuencia `X_seq`— y evalúa con **5-Fold Stratified CV** + un **test held-out** (20%). Guarda los modelos (`.joblib`), las matrices de confusión (PNG) y un resumen ([models/phase2_results.md](models/phase2_results.md)).
- **Acto 1 — con dataset parcial (4 capturas), el payload no discrimina:** entrenando solo sobre la víctima saneada, ambos modelos se quedan **al borde del azar** (CV ≈ 0.566 / 0.573). La causa (verificada, no es un bug): el benigno de esa captura es **también SSH cifrado** (1.821/1.864 al puerto 22), con entropía casi idéntica a la del ataque (7.27 vs 7.38). Sin tráfico benigno diverso, payload-SSH-benigno y payload-SSH-ataque son indistinguibles.
- **Procesamiento del día completo:** se ejecutaron las **449 capturas** del miércoles (46 GB) con `run_zeek_payload.py` (saneado automático + Zeek en Docker), **445 ok, 0 errores**. El dataset reconstruido pasa de 94 k a **2.202.231 flujos**: 2.109.613 `Benign` (ahora diverso: RDP 3389, HTTPS 443, HTTP 80, SMB 445...) y 92.618 `SSH-Bruteforce`.
- **Acto 2 — con el día completo, accuracy ≈ 0.9996... aparente:** reentrenado sobre el dataset balanceado (185.236 muestras), ambos modelos alcanzan **0.9996** de accuracy (CV y test). Pero ese número es **engañoso**: como el benigno balanceado es 99,9% NO-SSH, el modelo solo está separando "SSH cifrado" de "otros protocolos".
- **Prueba honesta** ([honest_check.py](scripts/zeek/honest_check.py)): evaluado **únicamente sobre el tráfico benigno que SÍ es SSH** (puerto 22, 2.022 flujos), el modelo marca como ataque el **96,0% (histograma) / 79,5% (secuencial)** de las conexiones SSH **legítimas**. El 0.9996 se desmorona: el modelo reconoce el **protocolo**, no el **ataque**.

**Bloqueos técnicos y soluciones:**

- **`MLPClassifier` con `early_stopping` y etiquetas string:** scikit-learn aplica `np.isnan` sobre las predicciones durante la validación interna y revienta con etiquetas de texto. **Solución:** codificar las etiquetas a enteros con `LabelEncoder` antes de entrenar y mapearlas de vuelta para los informes.
- **`conda run` auto-segundo-plano en tareas largas:** el procesamiento de 46 GB y el reentrenamiento sobre 185 k muestras son trabajos largos; se lanzaron en segundo plano con log a fichero. (El log de `conda run` no hace streaming: se vuelca al final; el progreso se siguió contando los `*.payload.tsv` generados.)

**HALLAZGO CLAVE 3 (relevante para la memoria):**

- **El análisis de payload es ciego al brute-force cifrado, y el 99,96% es un espejismo del desbalanceo de servicios.** Cuando el ataque y el tráfico legítimo comparten un servicio cifrado (SSH), sus payloads son **estadísticamente indistinguibles** (entropía casi máxima, bytes uniformes). Un modelo de payload puede *parecer* perfecto (0.9996) solo porque el benigno de evaluación es mayoritariamente otro protocolo; en cuanto se le enfrenta a SSH benigno real, **clasifica como ataque al 96% de los usuarios legítimos** — una tasa de falsos positivos catastrófica ("Fatiga de Alertas", igual que el Slowloris de la Fase 1). La firma del SSH-Bruteforce **no está en los bytes** sino en los **metadatos de flujo** (ráfaga de conexiones cortas, duración, nº de paquetes). Esto **repite el "Cae el mito del 99.99%" de la Fase 1, ahora desde el payload**, y cierra el argumento: **ninguna vista por separado basta; el enfoque híbrido payload + metadatos es necesario.**

**Próximos pasos operativos:**

1. Cuantificar la ventaja híbrida: entrenar el baseline de metadatos de la Fase 1 sobre **estos mismos flujos** (cruzando por la 5-tupla/uid) y compararlo con el modelo de payload y con una combinación de ambas vistas.
2. Para una evaluación honesta del payload, balancear **por servicio** (no solo por clase): comparar SSH-ataque contra SSH-benigno, para no inflar el accuracy con la separación trivial entre protocolos.
3. Pasar al siguiente día del dataset, preferiblemente un ataque con **payload en claro** (p. ej. Web/SQLi) donde el análisis de bytes sí debería tener señal, añadiendo su ground-truth a `attack_metadata.py`.

---

### [16 de junio] - Ventaja Híbrida: Payload vs Metadatos vs Híbrido — el Espejismo es del Balanceo, no de la Vista

**Objetivos:**

- Implementar el **paso 1** de la Fase 2 (9 de mayo): entrenar el baseline de metadatos sobre **estos mismos flujos** y compararlo con el modelo de payload y con una **combinación** de ambas vistas, para cuantificar cuánto aporta cada una.

**Hitos alcanzados:**

- **Comparador de vistas** ([hybrid_compare.py](scripts/zeek/hybrid_compare.py)): entrena tres MLP (256→128) sobre los **mismos flujos** y con el **mismo protocolo** que la Fase 2 (undersampling global por clase, 5-Fold CV + test held-out), añadiendo una **auditoría honesta** por vista sobre el SSH benigno real (puerto 22). Las tres vistas son: `payload` (`X_hist`+entropía), `metadatos` (escalares de flujo) e `híbrido` (concatenación).
- **Baseline de metadatos sin el CSV:** como el CSV de CICFlowMeter no trae IPs (no se puede unir por 5-tupla), los metadatos se reconstruyen de la propia extracción de Zeek por `uid`: `n_pkts`, `tot_bytes`, `bytes/paquete` y `seq_len` (con `log1p` por las colas pesadas). **Se excluye el puerto destino a propósito**: sería un "atajo" (memorizar el 22) y además no separa SSH-ataque de SSH-benigno (ambos en el 22), justo el caso difícil.
- **Resultado medido:** las tres vistas son **estadísticamente equivalentes**. Accuracy global ~0.9996 en todas; sobre el SSH benigno real, los falsos positivos son **payload 78.9%, metadatos 78.1%, híbrido 78.8%** (recall del ataque 100% en las tres). Resumen en [models/phase2_hybrid_compare.md](models/phase2_hybrid_compare.md).

| Vista | CV accuracy | Test acc | FP sobre SSH benigno | Recall ataque SSH |
|-------|-------------|----------|----------------------|-------------------|
| payload | 0.99959 | 0.99965 | 1596/2022 (78.9%) | 100.0% |
| metadatos | 0.99951 | 0.99946 | 1579/2022 (78.1%) | 100.0% |
| híbrido | 0.99958 | 0.99965 | 1594/2022 (78.8%) | 100.0% |

**Bloqueos técnicos y soluciones:**

- **Hipótesis no confirmada (y eso es un hallazgo):** se esperaba que los metadatos "salvaran" el caso difícil. **No lo hacen** bajo el balanceo global por clase. La corrección honesta es **no** maquillar el resultado: el problema no está en la vista sino en el **protocolo de balanceo**, lo que motiva directamente el paso 2.
- **`conda run` con `-c` multilínea:** sigue fallando en este entorno (documentado el 6 de mayo); la inspección y el entrenamiento se ejecutan desde ficheros `.py`. El entrenamiento de las tres vistas se lanzó en segundo plano (la salida de `conda run` no hace streaming, se vuelca al final).

**Hallazgo clave (relevante para la memoria):**

- **El espejismo del 99,96% es estructural al balanceo global por clase, NO exclusivo del payload.** Como el benigno balanceado es 99,9% NO-SSH, **ninguna** de las tres vistas aprende a separar SSH-ataque de SSH-benigno: todas aprenden el atajo "SSH / flujo-corto = ataque" y por eso todas disparan ~78% de falsos positivos sobre el SSH legítimo. Añadir los metadatos a ciegas no aporta nada **mientras el conjunto benigno esté dominado por otros protocolos**. Para medir de verdad la aportación de cada vista hay que **balancear por servicio** (SSH-ataque contra SSH-benigno), que es justo el paso 2.

**Próximos pasos operativos:**

1. **Evaluación honesta por servicio (paso 2):** construir un conjunto balanceado SSH-ataque vs SSH-benigno (1:1) y reentrenar las tres vistas sobre él, para aislar el caso difícil y obtener la métrica realista de cada vista sin la inflación de la separación trivial entre protocolos.
2. Pasar al siguiente día del dataset, preferiblemente un ataque con payload en claro (Web/SQLi).

---

### [16 de junio] - (cont.) Evaluación Honesta por Servicio: la Métrica Realista del Caso Difícil

**Objetivos:**

- Implementar el **paso 2** de la Fase 2: balancear **SSH-ataque contra SSH-benigno** (no solo por clase) para eliminar la separación trivial entre protocolos y obtener la **métrica realista** de cada vista sobre el caso que de verdad importa.

**Hitos alcanzados:**

- **Evaluador por servicio** ([honest_by_service.py](scripts/zeek/honest_by_service.py)): restringe el dataset al servicio atacado (puerto 22, SSH), balancea **1:1** `SSH-Bruteforce` vs `Benign` (2.022 c/u, 4.044 flujos, ambos cifrados) y reentrena las tres vistas del paso 1 con 5-Fold CV + test held-out. Reutiliza las funciones de [hybrid_compare.py](scripts/zeek/hybrid_compare.py). Resumen en [models/phase2_by_service.md](models/phase2_by_service.md).
- **Resultado medido (caso difícil, accuracy CV):**

| Vista | CV accuracy | F1 ataque (test) | Lectura |
|-------|-------------|------------------|---------|
| payload | 0.5732 | 0.6225 | al borde del azar |
| metadatos | **0.6093** | 0.6659 | la mejor, pero débil |
| híbrido | 0.5776 | 0.5952 | no supera a metadatos |

**Bloqueos técnicos y soluciones:**

- **La fusión ingenua no ayuda:** el híbrido (0.578) **no** supera a los metadatos (0.609); concatenar 257 features de payload casi aleatorias **diluye** los 4 escalares útiles (el MLP no logra aislarlos). Lección: la fusión requiere ponderar/seleccionar features o, mejor, enriquecer primero la metadata, no apilar vistas a ciegas.

**Hallazgo clave (relevante para la memoria):**

- **Aislado el caso difícil, el payload es estadísticamente azar (CV 0.57) y los metadatos ganan (CV 0.61).** Esto **confirma de forma cuantitativa** la dirección de la tesis: contra un brute-force sobre un servicio **cifrado**, los bytes del payload no contienen la firma (SSH-ataque y SSH-benigno son indistinguibles a nivel de byte), mientras que el **comportamiento de flujo** sí la contiene, aunque sea parcialmente. Pero el 0.61 de los metadatos **sigue siendo débil**: los 4 escalares disponibles (paquetes y bytes de *payload* por flujo) son pobres. Falta la **metadata rica de flujo** —duración, inter-arribo de paquetes, estado de conexión (`conn_state`), ráfaga entre conexiones cortas— que la extracción de solo-payload **descarta**. Recuperarla (estilo `conn.log` de Zeek) es lo que de verdad debería disparar la detección del SSH-Bruteforce.

**Próximos pasos operativos:**

1. **Enriquecer la metadata de flujo:** extender el script Zeek para volcar también features de conexión (`conn.log`: `duration`, `orig_pkts`/`resp_pkts`, `conn_state`, inter-arribo) y, sobre todo, **agregados de ráfaga** (nº de conexiones cortas por ventana/origen), que es la firma natural del brute-force. Reentrenar la vista `metadatos`/`híbrido` por servicio y ver si supera con holgura el 0.61.
2. Pasar al siguiente día del dataset, preferiblemente un ataque con **payload en claro** (p. ej. Web/SQLi), donde el análisis de bytes sí debería tener señal (caso opuesto al SSH cifrado), añadiendo su ground-truth a `attack_metadata.py`.

---

### [17 de junio] - Metadata de Ráfaga y el Benigno Contaminado: por qué el 0.61 no era un techo real

**Objetivos:**

- Implementar el **paso 1** del refinamiento (enriquecer la metadata de flujo con la **ráfaga** de conexiones, la firma natural del brute-force) y reentrenar por servicio para ver si supera el techo de 0.61 del paso 2.

**Hitos alcanzados:**

- **Evaluador enriquecido** ([honest_by_service_rich.py](scripts/zeek/honest_by_service_rich.py)): añade una feature de **ráfaga** (nº de conexiones del mismo origen en ventanas causales de 1/5/30 s) calculada **directamente del meta CSV existente, sin reprocesar los 67 GB de TSV**, y compara tres vistas (`payload`, `meta-básica` de 4 escalares, `meta-rica` = básica + ráfaga) sobre el caso SSH. Resumen en [models/phase2_by_service_rich.md](models/phase2_by_service_rich.md).
- **HALLAZGO: el "SSH benigno" del paso 2 estaba contaminado.** De los 2.022 flujos `Benign` del puerto 22, el **78,6% (1.589) son del propio atacante `13.58.98.64`** conectando al SSH **fuera de la ventana etiquetada** (14:01–15:31); el etiquetador los marca `Benign` por caer fuera de la ventana, pero su comportamiento es **idéntico al ataque** (ráfaga ≈87 conn/5s, 31 paquetes, 4.593 bytes). El paso 2 comparaba, en gran parte, **ataque contra ataque** → de ahí el techo de 0.61. El benigno **genuino** son solo **433 flujos de 75 IPs de terceros**.
- **Resultado medido (dos definiciones de benigno):**

| Escenario (benigno) | Vista | CV accuracy | F1 ataque (test) |
|---------------------|-------|-------------|------------------|
| contaminado (todos) | payload | 0.5732 | 0.6225 |
| contaminado (todos) | meta-básica | 0.6093 | 0.6659 |
| contaminado (todos) | meta-rica (ráfaga) | **0.7841** | 0.7826 |
| limpio (terceros) | payload | 0.9908 | 1.0000 |
| limpio (terceros) | meta-básica | 0.9793 | 1.0000 |
| limpio (terceros) | meta-rica (ráfaga) | **1.0000** | 1.0000 |

**Bloqueos técnicos y soluciones:**

- **El payload separa en el escenario limpio... pero por una huella de herramienta, no por el cifrado.** Sorprendió que el payload diera 0.99 sobre el benigno limpio. Inspeccionando los primeros bytes (banner SSH **en claro** del handshake): el atacante usa un cliente fijo (`paramiko_2.0.0` → solo **2 banners distintos**) frente a **81 banners** de clientes legítimos diversos (PuTTY, libssh2, OpenSSH...). El modelo **no lee el contenido cifrado** (entropía ~7.4 en ambos), lee el banner; es señal real pero **evadible** (basta falsear el banner). La firma **robusta** sigue siendo conductual.

**Hallazgo clave (relevante para la memoria):**

- **El techo de 0.61 del paso 2 no era un límite de los metadatos sino un artefacto de un conjunto benigno contaminado por el propio atacante.** Corregida la contaminación (benigno = solo terceros), la firma del SSH-Bruteforce se separa **casi perfecta** y la vista **robusta y generalizable** es la **conductual (ráfaga: ~1 conn/5s el benigno real vs ~86 el ataque)**, no la de bytes. El éxito del payload es un *fingerprint* de la herramienta (`paramiko`) que un atacante evade trivialmente; la ráfaga de conexiones es **intrínseca** al ataque. Esto **refuerza el HALLAZGO CLAVE 3**: el payload no "ve" el cifrado; cuando parece verlo, está leyendo metadatos en claro (el banner). Confirma cuantitativamente la dirección de la tesis hacia el enfoque conductual/híbrido.

**Corrección aplicada el mismo día (limpieza del etiquetado en origen):**

- **Causa raíz confirmada:** un **error de límite de ventana**. Verificado con el meta CSV: el atacante `13.58.98.64` conecta **exclusivamente** a `172.31.69.25:22` (94.207 flujos, un único destino) en una **ráfaga continua sin huecos** (gap máximo 1 s) de **18:01:50 a 19:32:30 UTC**. La ventana documentada acababa a las 19:31:00, dejando los **1.589 flujos de la cola de 90 s** mal etiquetados como `Benign`.
- **Arreglo:** se amplió el fin de ventana del SSH a **15:33 local (19:33 UTC)** en [attack_metadata.py](scripts/zeek/attack_metadata.py) (con la nota de verificación). El emparejamiento por par {atacante, víctima} garantiza que ningún tercero al puerto 22 se reetiquete por error.
- **Re-etiquetado sin reprocesar:** [relabel_dataset.py](scripts/zeek/relabel_dataset.py) re-aplica las etiquetas al `dataset_*.npz`/`_meta.csv` existentes usando la 5-tupla y el `ts` ya guardados —**sin re-leer los 67 GB de TSV**—, con copia `.bak` y diff de distribución. Resultado: **1.589 flujos** pasan de `Benign` a `SSH-Bruteforce` (92.618 → 94.207). Verificado: el SSH benigno queda en **433 flujos genuinos de 75 IPs de terceros**, con **0 flujos del atacante**.

**Próximos pasos operativos:**

1. **(Opcional) Metadata de flujo completa:** la ráfaga ya resuelve el caso, pero `duration`/`inter-arribo`/`conn_state` (estilo `conn.log`) reforzarían la robustez. Requiere re-leer los TSV (solo `ts`/`dir`/`len`, sin payload) o volcar `conn.log` en una pasada de Zeek; queda pendiente por coste (67 GB) y bajo retorno marginal.
2. Pasar al siguiente día del dataset, preferiblemente un ataque con **payload en claro** (p. ej. Web/SQLi), donde el análisis de bytes sí debería tener señal real (no una mera huella de cliente), añadiendo su ground-truth a `attack_metadata.py`.

---

### [7 de julio] - Día 2: Web Attacks (22-02-2018), el Caso del Payload EN CLARO (opuesto al SSH)

**Objetivos:**

- Implementar el **paso 2** pendiente del 17 de junio: incorporar un segundo día con un ataque de **payload en claro** (Web/SQLi), el espejo del SSH cifrado, para cerrar el argumento híbrido (cifrado → metadata; claro → payload).

**Saneado de disco previo (necesario):**

- El miércoles ocupaba ~151 GB (PCAP crudo 83 GB + TSV de Zeek 66 GB). Como el dataset ya está **vectorizado y re-etiquetado** en `dataset_Wednesday-14-02-2018.npz` (751 MB) + `_meta.csv` (217 MB), que es **autocontenido** (histograma, secuencia, entropía, 5-tupla, `ts` y etiqueta por flujo), se **borraron el PCAP crudo y los 449 TSV** del miércoles tras verificar la integridad del `.npz` (2.202.231 flujos, 94.207 SSH-Bruteforce). Se conservan los `.bak` (~1 GB, rollback del re-etiquetado del 17-jun). Disco: **38 GB → 186 GB libres**. Lo pesado del miércoles es re-derivable (re-descarga de S3 + Zeek) si hiciera falta.

**Hitos alcanzados:**

- **Día elegido: `Thursday-22-02-2018`** (Web Attacks, 46,8 GB, más pequeño que el viernes 23 con los mismos ataques). Descargado de S3, extraído (447 capturas) y borrado el `pcap.zip`.
- **Ground-truth verificada empíricamente** (no de la documentación; lección del SSH). Con [find_host.py](scripts/zeek/find_host.py) el atacante `18.218.115.60` aparece **solo en una captura** (`UCAP172.31.69.28`, 24 MB); procesada con Zeek, **el 100% de su tráfico (21.607 paquetes) va a `172.31.69.28:80`** contra la app vulnerable **DVWA** (`POST /DVWA/login.php`...). Un único par atacante→víctima, todo HTTP en claro.
- **Los 3 sub-ataques del día son separables en el tiempo Y en el payload.** La actividad del atacante forma 3 clústeres con huecos que casan con las ventanas documentadas, y las firmas de bytes lo confirman:

| Sub-ataque | Ventana verificada (local, UTC-4) | Firma en el payload en claro | Paquetes |
|------------|-----------------------------------|------------------------------|----------|
| Brute Force -Web | 10:13–11:24 | `POST /DVWA/login.php` (fuerza bruta) | 3.439 |
| Brute Force -XSS | 13:50–14:29 (tras gap) | `<script>` / `onerror=` | 1.915 |
| SQL Injection | 16:10–16:28 (tras gap) | `union select` / `or 1=1` | 141 |

- **`attack_metadata.py` extendido** con el día 22-02 (3 ataques con el mismo par {atacante, víctima}:80 y ventanas disjuntas; cada flujo cae en su sub-ataque por su `ts`). `tz -4` confirmado: CSV 10:13 local = primer paquete del atacante 14:13 UTC.
- **Extracción del día completo en marcha** (447 capturas con `run_zeek_payload.py`, saneado + Zeek en Docker) para obtener HTTP **benigno diverso** con el que comparar el ataque (misma metodología que el miércoles).

**Hallazgo clave (relevante para la memoria):**

- **El día 22-02 es el contraejemplo exacto del SSH.** Frente al SSH-Bruteforce (payload **cifrado** → los bytes son azar, la firma vive en la metadata/ráfaga), los ataques web viajan en **HTTP sin cifrar**: el contenido malicioso está **literalmente en los bytes** (`' OR 1=1`, `<script>`, `POST login.php` repetido). Aquí se espera que el **payload SÍ discrimine** —e incluso distinga el **tipo** de ataque (SQLi vs XSS vs BF), algo que la metadata de flujo no puede—, invirtiendo el resultado del SSH. Es la otra mitad del argumento híbrido: **ninguna vista basta sola; cada una gana en su régimen** (claro→payload, cifrado→conducta).

**Resultado medido (mismo día, tras procesar las 447 capturas):**

- **Dataset del día completo:** 2.777.898 flujos con payload → `Benign` 2.777.695, `Brute Force -Web` 142, `Brute Force -XSS` 42, `SQL Injection` 19 (203 flujos de ataque). En el puerto 80: 459.857 flujos (459.654 benignos de **450 IPs distintas** + 203 ataque). **Contaminación 0**: el atacante `18.218.115.60` tiene exactamente 203 flujos, todos etiquetados ataque, ninguno `Benign` (a diferencia del SSH, que tuvo 78,6%). Entropía media baja (**Web-Attack 6.61, Benign 5.95**) → confirma HTTP **en claro**, frente al SSH cifrado (~7.4).
- **Evaluación honesta por servicio sobre HTTP:80** ([honest_by_service_web.py](scripts/zeek/honest_by_service_web.py), balanceo 1:1 Web-Attack vs HTTP-benigno, 203 c/u; 3 MLP 256→128, 5-Fold CV + test held-out). Resumen en [models/phase2_by_service_web.md](models/phase2_by_service_web.md):

| Vista | HTTP en claro (22-02) | SSH cifrado (14-02, benigno limpio) |
|-------|----------------------|-------------------------------------|
| **payload** | **CV 0.9877, F1 ataque 1.00** ✅ | CV 0.5732 ❌ (azar) |
| metadatos | CV 0.9286 | CV 0.6093 |
| híbrido | CV 0.9926 | CV 0.5776 |

**HALLAZGO CLAVE 4 (el cierre del argumento híbrido):** el resultado del SSH se **invierte por completo**. En un ataque de **payload en claro** (web sobre HTTP), el **payload gana** (CV 0.99, detección perfecta del ataque en test) porque el contenido malicioso está en los bytes; la metadata de flujo, que dominaba en el SSH cifrado, aquí es la vista **más débil** (CV 0.93). Cada vista **gana en su régimen** (claro→payload, cifrado→conducta) y **ninguna basta sola** en ambos. El **híbrido es el único robusto en los dos escenarios** (0.99 en claro; y sobre el SSH benigno limpio del 17-jun también acertaba). Esto demuestra empíricamente, con dos ataques opuestos del mismo dataset, la tesis central del TFG: **la detección robusta exige combinar payload y metadatos**. *(Caveat honesto: la clase de ataque web es pequeña —203 flujos— por ser un ataque de bajo volumen; la señal en test es nítida pero el N es reducido.)*

> **[Supersedido el 24-ago por el HALLAZGO 19.]** Estas cifras son **exactitud en validación cruzada**, y la comparación de la que salen medía `meta-rica` (con ráfaga) en el lado SSH contra `build_meta_features` (sin ráfaga) en el lado web. Medidas las tres vistas con la misma métrica y el mismo protocolo, **la evaluación intra-día está saturada y no discrimina entre vistas**: lo único que se invierte de verdad son los metadatos per-flujo. Ver el diario del 24 de agosto.


**Próximos pasos operativos:**

1. Liberar disco: borrar los TSV del día 22 (93 GB) conservando `.npz`+`_meta.csv` (patrón del miércoles). *(Hecho el 8 de julio.)*
2. (Opcional) Clasificación multi-tipo del ataque web (BF/XSS/SQLi) **solo con payload**, para mostrar que los bytes no solo detectan el ataque sino que distinguen el **tipo** (imposible para la metadata). *(Hecho el 8 de julio; ver la entrada siguiente — el resultado matiza la hipótesis.)*
3. (Opcional) Un tercer día para triangular (p. ej. DDoS/Infiltration), si el tiempo lo permite antes de la memoria.

---

### [8 de julio] - Multi-tipo del Ataque Web: el Tipo vive en la Secuencia, no en el Histograma ni en la Metadata

**Objetivos:**

- Implementar el **paso 2** (opcional) del 7 de julio: clasificación **multi-tipo** del ataque web (Brute Force -Web vs XSS vs SQL Injection) para comprobar si el payload en claro no solo **detecta** el ataque sino que identifica su **tipo**, algo que la metadata de flujo no debería poder.
- Liberar disco borrando los TSV del día 22 (patrón del miércoles).

**Hitos alcanzados:**

- **Saneado de disco hecho:** borrados los TSV de Zeek del día 22; su directorio queda en **1,2 GB** (solo `dataset_Thursday-22-02-2018.npz` + `_meta.csv`, autocontenido). Lo pesado es re-derivable desde S3+Zeek si hiciera falta.
- **Clasificador multi-tipo** ([multitype_web.py](scripts/zeek/multitype_web.py)): restringe a los **203 flujos de ataque** del puerto 80 (142 BF-Web, 42 XSS, 19 SQLi) y compara tres vistas en un problema de **3 clases** con predicciones **out-of-fold** (5-Fold Stratified, sin fuga; se usa out-of-fold en vez de un test held-out diminuto por el N pequeño). Resumen en [models/phase2_multitype_web.md](models/phase2_multitype_web.md).
- **Resultado medido (macro-F1 out-of-fold sobre los 203 flujos):**

| Vista | Macro-F1 | SQLi (recall) | Lectura |
|-------|----------|---------------|---------|
| **payload-seq** (secuencia 256 B) | **0.9505** | 16/19 (0.84) | identifica los 3 tipos |
| payload-hist (histograma+entropía) | 0.7462 | 5/19 (0.26) | difumina los tokens |
| metadatos (flujo) | 0.7695 | 5/19 (0.26) | solo separa por volumen |

**Hallazgo clave (relevante para la memoria):**

- **El *tipo* de ataque vive en la representación SECUENCIAL del payload en claro, no en el histograma ni en la metadata.** La hipótesis ingenua («el payload distingue el tipo, la metadata no») resultó ser solo **medio cierta**, y corregirla es el hallazgo: con la vista de la Fase 2 hasta ahora —el **histograma** de bytes— el payload **NO** separa los tipos (macro-F1 0.75, falla el SQLi) porque el histograma **difumina los tokens** (`<script>` y `union select` tienen distribuciones de bytes parecidas); y la **metadata de flujo** los separa por **volumen** casi igual de bien (0.77), salvo el SQLi. **Solo la secuencia de bytes** (los primeros 256 B, donde están literalmente los tokens del ataque: `POST /login.php`, `<script>`, `union select`) identifica los 3 tipos con nitidez (macro-F1 **0.95**, SQLi recall 0.84). Doble matiz honesto: (1) **la representación importa** —para identificar el tipo hace falta la secuencia, no el histograma—, y (2) el SQLi son solo **19 flujos**, la clase más frágil en las tres vistas. Refuerza el HALLAZGO 4: el payload en claro es la vista rica, pero **hay que representarlo como secuencia** para explotar su ventaja diferencial (identificar el tipo), fuera del alcance de la metadata de flujo.

**Próximos pasos operativos:**

1. (Opcional) Un tercer día para triangular (p. ej. DDoS/Infiltration), si el tiempo lo permite antes de la memoria.
2. Empezar la redacción de la **memoria** (LaTeX): los cuatro HALLAZGOS CLAVE y la evaluación honesta por servicio ya cierran el argumento híbrido.

---

### [8 de julio] - (cont.) Arranca la Fase 3: Deep Learning sobre Bytes, Híbrido de Dos Ramas e Interpretabilidad

**Objetivos:**

- Elevar el componente de IA del TFG (hasta ahora MLP de scikit-learn): **modelos profundos de verdad sobre la secuencia de bytes** (Eje A), un **híbrido de dos ramas** con fusión aprendida (Eje B) e **interpretabilidad** del modelo (Eje D). Se instala **PyTorch (CPU)** en `tfg_ia`.

**Hitos alcanzados:**

- **Infraestructura de deep learning** ([dl_models.py](scripts/zeek/dl_models.py)): `ByteCNN` (embedding de bytes + convolución 1D multi-kernel 3/5/7, estilo *Deep Packet* — cada filtro aprende un detector de n-gramas de bytes) y `ByteLSTM` (BiLSTM sobre la misma secuencia). Toda la evaluación es **out-of-fold** (5-Fold Stratified), directamente comparable con la Fase 2.
- **Eje A — DL sobre bytes** ([train_dl_payload.py](scripts/zeek/train_dl_payload.py)): compara, en la misma partición, los modelos profundos contra los baselines shallow. **Macro-F1 out-of-fold:**

| Tarea | **byte-CNN** | byte-LSTM | mlp-seq | mlp-hist | metadatos |
|-------|--------------|-----------|---------|----------|-----------|
| Multi-tipo web (BF/XSS/SQLi) | **0.968** | 0.486 | 0.951 | 0.746 | 0.769 |
| Detección web (HTTP en claro) | **1.000** | 0.995 | 0.975 | 0.990 | 0.918 |
| Detección SSH (cifrado, benigno limpio) | 0.999 | 0.999 | 0.999 | 0.990 | 0.993 |

  Resúmenes: [dl multitype](models/phase2_dl_Thursday-22-02-2018_multitype.md), [dl web](models/phase2_dl_Thursday-22-02-2018_binary.md), [dl ssh](models/phase2_dl_Wednesday-14-02-2018_binary.md). El **byte-CNN es el mejor** identificando el *tipo* (0.968) y detectando en claro (perfecto); el LSTM infra-ajusta con N pequeño (honesto).
- **Eje B — Híbrido de dos ramas** ([train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py)): rama payload (CNN) + rama metadatos (MLP), **fusión tardía de los embeddings aprendidos**. **Macro-F1 out-of-fold:**

| Tarea | **híbrido 2-ramas** | fusión ingenua (concat) | solo-payload CNN | solo-metadatos |
|-------|---------------------|-------------------------|------------------|----------------|
| Multi-tipo web | 0.963 | 0.901 | 0.968 | 0.769 |
| Detección web (claro) | 0.998 | 0.980 | 1.000 | 0.918 |
| Detección SSH (cifrado) | **1.000** | 0.999 | 0.999 | 0.993 |

  Resúmenes: [hyb multitype](models/phase2_dlhybrid_Thursday-22-02-2018_multitype.md), [hyb web](models/phase2_dlhybrid_Thursday-22-02-2018_binary.md), [hyb ssh](models/phase2_dlhybrid_Wednesday-14-02-2018_binary.md). El híbrido de dos ramas es **robusto en ambos regímenes** (iguala o supera a la mejor vista suelta) y **corrige la dilución** de la fusión ingenua (que cae a 0.901 en multi-tipo).
- **Eje D — Interpretabilidad (saliency)** ([eval_saliency.py](scripts/zeek/eval_saliency.py)): explica **por qué** el byte-CNN "ve" el SSH **cifrado**. El banner modal del ataque es literalmente `SSH-2.0-paramiko_2.0.0` y el **31,1%** de la importancia (|gradiente|) se concentra en los primeros 48 bytes (la zona del banner en claro), no en el cuerpo cifrado. Ver [phase2_saliency_ssh.md](models/phase2_saliency_ssh.md) y `models/phase2_saliency_ssh.png`.

**Hallazgos clave (relevantes para la memoria):**

- **HALLAZGO 5 — el byte-CNN es el modelo más fuerte y confirma que la firma vive en la *secuencia*.** Sobre bytes en claro, la convolución (que aprende detectores de n-gramas) gana tanto en detección (web 1.00) como en identificar el *tipo* de ataque (0.968 macro-F1), superando a todos los baselines shallow. Es el salto de IA que justifica el deep learning frente al MLP sobre histograma.
- **HALLAZGO 6 — la fusión hecha bien (dos ramas) es robusta en ambos regímenes.** Un único modelo híbrido logra ~1.0 tanto en web en claro como en SSH cifrado, e iguala/supera a la mejor vista suelta en cada caso, mientras que la **fusión ingenua diluye** (0.968→0.901 en multi-tipo). Es la validación arquitectónica de la tesis híbrida (corrige el resultado negativo del 16-jun).
- **HALLAZGO 7 (interpretabilidad) — el "éxito" del payload sobre el cifrado es un *fingerprint* del cliente (banner `paramiko`), no lectura del cifrado.** La saliency lo prueba: el modelo mira el banner en claro del handshake, señal **real pero evadible**. Refuerza que la firma **robusta** del brute-force cifrado es **conductual** (ráfaga), y que payload y conducta se complementan — la tesis central.

**Próximos pasos operativos:**

1. **Eje C — más días (dataset multidía/multiataque):** procesar un día nuevo con el pipeline ya genérico (todo acepta `--day`). Candidato más pequeño: `Friday-16-02-2018` (DoS, 35,9 GB). Es una tarea larga (descarga + pase de Zeek de horas + vectorización) y con disco justo, así que se ejecuta de forma deliberada (ver «Fase 3 → Eje C»).
2. **Eje D (ampliación):** con ≥2 días del mismo tipo de ataque, **generalización cruzada entre días** (entrenar en A, testear en B) para medir si el CNN generaliza o memoriza la huella `paramiko`.

---

### [15 de julio] - Eje C: Día 3, DoS-Hulk (16-02-2018) — el Tercer Régimen: la Firma es VOLUMÉTRICA

> ⚠️ **ENTRADA REVISADA EL 11 DE AGOSTO.** Todas las cifras de esta entrada se midieron
> con un **benigno contaminado** (el 65,1% del "benigno" HTTP eran flujos del propio
> atacante, por una ventana de etiquetado ~5 min corta). El **HALLAZGO CLAVE 8 queda
> revisado**: con el etiquetado corregido, las vistas per-flujo **sí** separan el ataque.
> Se conserva la entrada como registro del proceso; las cifras válidas y la lectura
> corregida están en el **diario del 11 de agosto**.

**Objetivos:**

- Ejecutar el **Eje C** de la Fase 3: incorporar un **tercer día** con un ataque de naturaleza distinta a los dos anteriores (SSH cifrado y web en claro) para poner a prueba la generalidad de la tesis híbrida. Día elegido: `Friday-16-02-2018` (**DoS**, el más pequeño), donde se espera un **tercer régimen** de firma: ni los bytes (como el web) ni la ráfaga de conexiones cortas fallidas (como el SSH), sino el **volumen agregado** de un flood.

**Hitos alcanzados:**

- **Localizador de atacante sin IP previa** ([find_attacker.py](scripts/zeek/find_attacker.py)): complementa a `find_host.py`. En vez de necesitar una IP candidata, ejecuta Zeek (`conn.log`) sobre una captura y lista los **top-talkers** por nº de conexiones (total y hacia un puerto). En un ataque volumétrico el atacante **aplasta el ranking**, así que se identifica **sin conocer su IP**; además imprime el rango temporal UTC, `conn_state` y bytes de aplicación por par, para fijar la ventana en `attack_metadata.py`. Sanea la captura (o la pasa directa si es pcapng) igual que el orquestador.
- **Ground-truth verificada empíricamente** (lección del SSH y el web; no de la documentación). Sobre la captura de la víctima (`UCAP172.31.69.25-part1.pcap`) los dos atacantes dominan el ranking:

| Sub-ataque | Atacante | Víctima:puerto | Conexiones | Ventana verificada (UTC / local −4) |
|------------|----------|----------------|-----------:|-------------------------------------|
| **DoS-Hulk** | `18.219.193.20` | `172.31.69.25:80` | 999.007 | 17:45:27–17:52:34 UTC = 13:45–13:52 |
| **DoS-SlowHTTPTest** | `13.59.126.31` | `172.31.69.25:21` | 105.550 | 14:12:14–15:05:13 UTC = 10:12–11:05 |

  Hallazgo empírico: **SlowHTTPTest ataca el puerto 21, no el 80** (la doc lo daba en 80); se registra lo verificado en los datos. El Hulk es un **flood HTTP en claro** (~1 M de conexiones en ~7 min desde una sola IP). `attack_metadata.py` extendido con el día 16-02 (dos ataques, mismo par {atacante, víctima} disjunto por puerto y ventana).
- **Pipeline endurecido para días masivos y capturas pcapng:**
  - **pcapng nativo** ([repair_pcap.py](scripts/zeek/repair_pcap.py) `is_pcapng()` + [run_zeek_payload.py](scripts/zeek/run_zeek_payload.py) / [find_attacker.py](scripts/zeek/find_attacker.py)): la captura de la víctima del DoS venía en **pcapng** (magic `0x0a0d0d0a`), que `repair()` no sabe sanear; se detecta y se pasa el fichero **original** a Zeek, que lee pcapng de forma nativa (el resto del día es libpcap clásico y sí se sanea).
  - **Memory-safety** ([train_dl_payload.py](scripts/zeek/train_dl_payload.py), [train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py), [hybrid_compare.py](scripts/zeek/hybrid_compare.py)): con **4,04 M de flujos**, castear `X_seq` completo a `int64` son ~8 GB → OOM con 16 GB de RAM. Se dejó de materializar las vistas completas: primero se calcula `sel` (índices) con arrays ligeros y solo después se construyen las vistas **para el subconjunto**. Nuevo flag `--cap N` (subsampleo reproducible por clase) para que el DL sea tratable en CPU sin cambiar el resultado (la señal satura con unos miles de muestras).
- **Dataset del día completo** (444 capturas, saneado + Zeek en Docker) → **4.041.078 flujos**: `Benign` 2.978.739, `DoS-Hulk` 1.062.339. En el puerto 80: 1.137.872 benignos (de **444 IPs distintas**) + 1.062.339 Hulk. **El SlowHTTPTest (:21) deja 0 flujos con payload** — como el FTP-BruteForce del 14-02 (REJ), el ataque lento no intercambia datos analizables y es **invisible al análisis de payload** (refuerza el HALLAZGO 1).
- **Acto 1 — per-flujo, TODAS las vistas son débiles** ([train_dl_payload.py](scripts/zeek/train_dl_payload.py) `--task binary`, Hulk vs HTTP-benigno :80, 1:1, `--cap 4000`, out-of-fold). Macro-F1: **byte-CNN 0.607, byte-LSTM 0.630, mlp-seq 0.630, mlp-hist 0.738, metadatos 0.619**. Coherente: **un GET de Hulk es indistinguible de un GET benigno** en los bytes, y su flujo es corto como cualquier HTTP en la metadata per-flujo. Resumen: [phase2_dl_Friday-16-02-2018_binary.md](models/phase2_dl_Friday-16-02-2018_binary.md).
- **Acto 2 — el volumen agregado separa el DoS** ([dos_burst.py](scripts/zeek/dos_burst.py)): reutilizando la feature de **ráfaga** (nº de conexiones del mismo origen en ventanas causales de 1/5/30 s, la misma que resolvió el SSH el 17-jun), la vista conductual pasa a ser **la mejor**. Macro-F1 out-of-fold:

| Vista | Macro-F1 | Lectura |
|-------|----------|---------|
| payload-hist (per-flujo) | 0.7375 | los bytes de un GET no distinguen el flood |
| meta-básica (per-flujo) | 0.6186 | un flujo Hulk ≈ un HTTP corto benigno |
| **meta+ráfaga (agregado)** | **0.8057** | el **volumen por origen** es la firma |

  Resumen: [phase2_dos_burst_Friday-16-02-2018.md](models/phase2_dos_burst_Friday-16-02-2018.md).

> ⚠️ **CORREGIDO EL 11 DE AGOSTO — leer junto con el diario de esa fecha.** Los números de
> esta entrada se midieron sobre un **benigno contaminado**: la ventana del Hulk terminaba
> 5 min antes de que acabara el flood, así que **740.821 flujos del propio atacante (el
> 65,1% del "benigno" HTTP del día)** estaban etiquetados `Benign`. Buena parte de la
> debilidad per-flujo que se concluye aquí era, otra vez, **comparar ataque contra ataque**
> (mismo error que el SSH el 17-jun). Las cifras corregidas están en el diario del 11 de
> agosto; la lectura cualitativa de los **tres regímenes** se mantiene, pero el
> **HALLAZGO CLAVE 8 queda revisado**.

**HALLAZGO CLAVE 8 (Eje C — el tercer régimen cierra la generalización de la tesis):** el DoS-Hulk exhibe un **tercer patrón de firma**, distinto de los dos días anteriores. **Per-flujo, ninguna vista sirve** (todas ≤0.74): un paquete/flujo del flood es idéntico a tráfico HTTP legítimo, tanto en los **bytes** (mismo `GET`) como en la **metadata per-flujo** (flujo corto). La firma **solo emerge en el agregado**: el **volumen de conexiones por origen** (ráfaga), que sube la detección de 0.62/0.74 a **0.81** y es la vista dominante. Queda así un mapa de tres regímenes, **cada uno con su firma**, y **ninguna vista per-flujo basta en los tres**:

| Día | Ataque | Régimen | Firma dominante | Vista ganadora |
|-----|--------|---------|-----------------|----------------|
| 14-02 | SSH-Bruteforce | cifrado | conducta / ráfaga de conexiones | metadata+ráfaga (~1.0) |
| 22-02 | Web (BF/XSS/SQLi) | en claro | contenido en los bytes | payload-seq / byte-CNN (0.95–1.0) |
| 16-02 | DoS-Hulk | volumétrico | volumen agregado por origen | metadata+ráfaga (0.81) |

Es la **validación de generalidad** de la tesis: no hay una vista universalmente superior; la detección robusta exige **combinar payload y metadatos** (incluyendo agregados de flujo) porque cada régimen esconde su firma en una vista distinta.

**Caveats honestos:**

- **El 0.81 del DoS no es el ~1.0 del SSH**, y la razón es real: el benigno de :80 son **444 IPs distintas**, algunas legítimamente de alto volumen (servidores/proxies), así que el agregado de volumen es la **mejor** vista pero **no un separador limpio** (un cliente HTTP muy activo se parece a un flood). El régimen volumétrico es intrínsecamente más ruidoso que la ráfaga limpia del SSH.
- **SlowHTTPTest quedó fuera del payload** (0 flujos en :21), igual que el FTP-BruteForce: es un recordatorio de que los ataques que no exportan datos de aplicación necesitan sí o sí la vista de flujo/`conn.log`.

**Saneado de disco (patrón del miércoles/jueves):** vectorizado el día a `.npz` (1,18 GB) + `_meta.csv` (415 MB), **autocontenido**, se borraron el **PCAP crudo (47 GB)** y los **444 TSV (70 GB)**. Disco: **64 GB → 180 GB libres**. Re-derivable desde S3+Zeek si hiciera falta.

**Próximos pasos operativos:**

1. Con **tres días** y los tres regímenes cubiertos, los 8 HALLAZGOS CLAVE cierran el argumento híbrido de forma general. El siguiente paso natural es **empezar la memoria (LaTeX)** (al cierre, bajo orden explícita).
2. (Opcional) **Generalización cruzada** (Eje D): requiere ≥2 días del **mismo** tipo de ataque; los tres días actuales son de ataques distintos, así que quedaría añadir un cuarto día homólogo (p. ej. otro DoS/DDoS 20-21-02) si el tiempo lo permite.

---

### [4 de agosto] - Segundo dataset (CIC-IDS2017) y generalización cruzada entre datasets: infraestructura

**Objetivos:**

- Abordar dos cosas del plan oficial del TFG que aún faltaban: usar **más de una base
  de datos pública** (el enunciado nombra CSE-CIC-IDS2018, **CIC-IDS2017**, UNSW-NB15 y
  Malware-Traffic-Analysis.net) y, sobre todo, montar la **generalización cruzada entre
  datasets** (entrenar en uno y testear en otro). Es la prueba directa contra la duda del
  *"100% sospechoso"*: si un modelo entrenado en 2018 sigue detectando en 2017, la firma
  que aprende es **real**; si se hunde hacia el azar, estaba **memorizando** la huella del
  laboratorio o de la herramienta (el banner `paramiko`, la app DVWA...).

**Elección del dataset y de los análogos:** se añade **CIC-IDS2017** por ser el hermano
directo del 2018 (mismo formato, PCAPs disponibles) y tener un **análogo de cada uno de
los tres regímenes** ya cubiertos, lo que permite comparar ataque contra ataque:

| Régimen | 2018 (hecho) | 2017 (análogo) | Servicio |
|---------|--------------|----------------|----------|
| cifrado | SSH-Bruteforce (14-02) | SSH-Patator (Tuesday 04-07) | :22 |
| en claro | Web BF/XSS/SQLi (22-02) | Web Attack BF/XSS/SQLi (Thursday 06-07) | :80 |
| volumétrico | DoS-Hulk (16-02) | DoS-Hulk (Wednesday 05-07) | :80 |

**Hitos alcanzados (infraestructura, sin re-procesar datos pesados):**

- **Ground-truth de CIC-IDS2017** añadida a [attack_metadata.py](scripts/zeek/attack_metadata.py)
  (días Tuesday/Wednesday/Thursday de julio-2017). Se codifica con `status: "documented"`
  y `tz_offset_hours = -3` **provisional**: siguiendo la lección del 2018 (la doc erraba en
  el atacante del SSH y en el puerto del SlowHTTPTest), las IPs, ventanas y zona horaria
  **deben verificarse empíricamente con `find_attacker.py` antes de construir el dataset**
  (hay además NAT en 2017: firewall `205.174.165.80 ↔ 172.16.0.1`, así que la IP del
  atacante dentro del PCAP puede diferir de la documentada `205.174.165.73`). El mismo
  `DayLabeler` sirve para los dos datasets (mismo esquema par+puerto+ventana).
- **Pipeline hecho genérico entre datasets** sin tocar el flujo 2018: nuevo flag
  `--pcap-dir` en [run_zeek_payload.py](scripts/zeek/run_zeek_payload.py) y
  [find_attacker.py](scripts/zeek/find_attacker.py) para apuntar a la carpeta de PCAPs de
  otro dataset (los del 2017 no siguen la estructura `.../<día>/pcap` del bucket 2018). Por
  defecto todo se comporta **exactamente igual** que antes.
- **Script de generalización cruzada** ([cross_dataset_eval.py](scripts/zeek/cross_dataset_eval.py)):
  entrena en el `.npz` de un día/dataset y evalúa en el de **otro**, sobre el servicio
  atacado y en binario Attack vs Benign (balanceado 1:1 en ambos → 0.5 = azar). Compara las
  tres vistas —**payload-hist** (MLP), **metadatos** (MLP) y **byte-CNN** (PyTorch)— para
  ver **cuál generaliza** entre datasets. Reutiliza `load_dataset`/`build_meta_features` de
  [hybrid_compare.py](scripts/zeek/hybrid_compare.py) y `ByteCNN` de
  [dl_models.py](scripts/zeek/dl_models.py). Escribe `models/phase2_crossdataset_<A>__<B>_p<port>.md`.
- **Verificado el funcionamiento** de las tres vistas y del manejo de errores sobre los
  datos 2018 existentes (prueba de plomería; el experimento real requiere el `.npz` de 2017).

**Primer día 2017 procesado y ground-truth verificada (mismo día, tarde):**

- **Descargado `Thursday-WorkingHours.pcap`** (8,3 GB, **pcapng** → Zeek lo lee nativo). La
  descarga directa de CIC-IDS2017 está tras el formulario de términos de UNB (el enlace
  público redirige a su landing), así que este paso lo hace un humano; el resto del pipeline
  es automático.
- **Ground-truth verificada empíricamente con `find_attacker.py`** (Zeek `conn.log`, 363.760
  conexiones), con **dos correcciones frente a la documentación** —la misma lección que en
  2018—:
  1. **El atacante NO es `205.174.165.73`** (esa IP no aparece en el PCAP): por el **NAT** del
     firewall (`205.174.165.80 ↔ 172.16.0.1`), el Kali atacante sale dentro de la captura
     como **`172.16.0.1`**. Par real de ataque: `172.16.0.1 → 192.168.10.50:80` (HTTP en claro,
     mayoría `SF`, 12,7 MB de bytes de aplicación).
  2. **Zona horaria confirmada UTC-3** (Atlantic/ADT): la actividad del atacante empieza a las
     `12:15 UTC` = 09:15 local, justo antes del Brute Force documentado (9:20). Con −4 caería a
     las 8:15 (antes del horario laboral) → no encaja.

  Actualizada [attack_metadata.py](scripts/zeek/attack_metadata.py) a `status: verified`.
- **Dataset vectorizado** (`dataset_Thursday-06-07-2017.npz`, 83.886 flujos): **174 flujos de
  ataque web** (143 Brute Force, 22 XSS, 9 SQLi) + 83.712 benignos — un **análogo casi exacto**
  del 22-02-2018 (203 = 142/42/19), mismo tipo y volumen, todo HTTP en claro.

**HALLAZGO CLAVE 9 (generalización cruzada — la firma del payload es REAL, no memorización):**
resultado del web en claro entrenando en un dataset y testeando en el OTRO (binario Attack vs
Benign :80, balanceado 1:1, macro-F1 / accuracy):

| Sentido | **byte-CNN** | payload-hist | metadatos |
|---------|--------------|--------------|-----------|
| **2018 → 2017** | **0.991** (recall ataque 0.98, **0 falsos positivos**) | 0.839 | 0.529 (≈ azar) |
| 2017 → 2018 | 0.500 (colapsa) | 0.636 | 0.744 |

- **La dirección fuerte (2018 → 2017) responde a la objeción del "100% sospechoso":** el
  byte-CNN entrenado en 2018 detecta el ataque web de **otro laboratorio** (2017) con **99% y
  sin un solo falso positivo**. La firma que aprende (`union select`, `<script>`, `POST login`)
  es **intrínseca al ataque**, no una memorización de la app DVWA del 2018. En cambio los
  **metadatos de flujo caen al azar (0.53)**: son específicos del laboratorio y **no transfieren**
  → refuerza que la señal robusta y generalizable del ataque en claro vive en el **payload**.
- **Asimetría honesta (2017 → 2018 colapsa a 0.50):** el CNN entrenado en 2017 **no** generaliza
  al 2018 (predice todo benigno, incluso subiendo a 30 épocas → no es infra-ajuste). La causa es
  la **cobertura de los datos de entrenamiento**: el conjunto de ataque de 2017 es más pequeño y
  **menos diverso** (22 XSS / 9 SQLi frente a 42/19 en 2018), así que su frontera no cubre la
  distribución del 2018. No es un fallo que ocultar: es la **prueba directa de que la
  generalización depende de la amplitud de los datos** — justo el argumento del plan para usar
  **varios datasets**. La transferencia funciona cuando se entrena con el conjunto más rico.

Resúmenes: [2018→2017](models/phase2_crossdataset_Thursday-22-02-2018__Thursday-06-07-2017_p80.md),
[2017→2018](models/phase2_crossdataset_Thursday-06-07-2017__Thursday-22-02-2018_p80.md).

**Próximos pasos operativos:**

1. (Opcional) Añadir los otros dos días análogos de 2017 —**Tuesday** (SSH-Patator, :22) y
   **Wednesday** (DoS-Hulk, :80)— para la generalización cruzada en los regímenes **cifrado** y
   **volumétrico** (verificar antes su ground-truth con `find_attacker.py`; se espera que su
   atacante sea también `172.16.0.1` por el mismo NAT).
2. (Opcional, plan oficial) Un tercer/cuarto origen de datos —**UNSW-NB15**, **Malware-Traffic-
   Analysis.net**— para ampliar aún más la diversidad, con mayor coste de integración (otro
   formato/etiquetado).
3. Redacción de la memoria (al cierre, bajo orden explícita).

---

### [5-6 de agosto] - Generalización cruzada en los otros dos regímenes (SSH cifrado y DoS volumétrico): *fingerprint* de herramienta vs contenido del ataque

**Objetivos:**

- Completar la generalización cruzada 2018↔2017 en los **otros dos regímenes** (el web se hizo
  el 4-ago): **SSH cifrado** (Tuesday-04-07, :22, análogo del SSH-Bruteforce del 14-02) y **DoS
  volumétrico** (Wednesday-05-07, :80, análogo del DoS-Hulk del 16-02).

**Ground-truth verificada (mismo patrón que el web):** con `find_attacker.py` sobre cada PCAP
(pcapng de 11 y 13,4 GB), el atacante vuelve a salir como **`172.16.0.1`** (NAT, no la IP
documentada `205.174.165.73`) y la **tz se confirma UTC-3**. SSH-Patator: `172.16.0.1 →
192.168.10.50:22`, 2.979 conexiones (14:09–15:11 local). DoS: `172.16.0.1 → 192.168.10.50:80`,
191.161 conexiones de flood (se usa **una ventana amplia** para no dejar flujos del atacante
fuera contaminando el benigno). Datasets: Tuesday 100.871 flujos (**2.979 SSH-Patator**, 3.937
FTP-Patator); Wednesday 263.226 flujos (**170.032 DoS-Hulk**). [attack_metadata.py](scripts/zeek/attack_metadata.py)
a `status: verified`.

**Resultado (byte-CNN, train 2018 → test 2017, binario Attack vs Benign, balanceado 1:1):**

| Régimen | **byte-CNN 2018→2017** | metadatos | 2017→2018 (CNN) |
|---------|------------------------|-----------|-----------------|
| Web (claro) | 0.991 | 0.529 | 0.500 |
| SSH (cifrado) | 0.999 | 0.514 | 0.605 |
| DoS (volumétrico) | 0.966 | 0.429 | 0.671 |

Resúmenes: [ssh 2018→2017](models/phase2_crossdataset_Wednesday-14-02-2018__Tuesday-04-07-2017_p22.md),
[dos 2018→2017](models/phase2_crossdataset_Friday-16-02-2018__Wednesday-05-07-2017_p80.md) (+ los
inversos `*__*_p{22,80}.md`).

**HALLAZGO CLAVE 10 (el matiz que da rigor a la generalización cruzada — *por qué* generaliza
importa tanto como *si* generaliza):** en los **tres** regímenes el byte-CNN entrenado en 2018
detecta el ataque de 2017 (0.97–1.0) y los **metadatos de flujo caen al azar** (0.43–0.53,
específicos del laboratorio). Pero la *razón* por la que el payload transfiere **no es la misma**,
y verificarlo empíricamente (inspeccionando los bytes) es el hallazgo:

- **Web → señal INTRÍNSECA (robusta).** El payload transfiere porque la firma es el **contenido
  del ataque** (`union select`, `<script>`, `POST /login.php`), que es el ataque en sí. No
  depende de la herramienta → señal robusta y difícil de evadir.
- **SSH → *fingerprint* de herramienta (evadible).** Verificado en los bytes: **el 96–99% de los
  flujos de ataque de AMBOS años emiten el mismo banner en claro `SSH-2.0-paramiko_2.0.0`**
  (2018: 62.402; 2017: 2.869). El CNN cruza porque los dos brute-forcers usan el mismo cliente
  (paramiko), no porque lea el cifrado. Confirma el **HALLAZGO 7**: es una firma real pero
  **evadible** (basta cambiar el banner).
- **DoS → *fingerprint* de herramienta (evadible).** Igual: dentro de 2018 el per-flujo daba solo
  0.61 (HALLAZGO 8), pero cruza a 0.97 porque **Hulk/GoldenEye de ambos años comparten el mismo
  *pool* de User-Agents y plantilla de cabeceras** (p. ej. `Mozilla/5.0 (X11; U; Linux
  x86_64...rv:1.9.1.3)` y `MSIE 8.0; Windows NT 6.0; Trident` aparecen idénticos en 2018 y 2017,
  con `Accept-Encoding: identity` / `Keep-Alive: 115`). El CNN reconoce el *tool*, no el volumen;
  la firma robusta del DoS sigue siendo el **agregado** (HALLAZGO 8), no los bytes per-flujo.

**Lección metodológica (fuerte para la memoria):** la generalización cruzada demuestra que el
modelo **no memoriza el laboratorio** (detecta ataques de un dataset que no vio), pero **no basta
con que generalice: hay que inspeccionar *por qué***. Solo el web se apoya en una firma
**intrínseca y robusta**; en SSH y DoS la transferencia se apoya en el **fingerprint de la
herramienta de ataque**, real pero **evadible** cambiando de herramienta. Esto conecta las tres
piezas del TFG: cada régimen esconde su firma en una vista distinta (payload/conducta/agregado),
y **la robustez real exige combinar vistas** porque las firmas de payload evadibles se caen solas.

**Asimetría honesta (2017→2018 más débil en los tres):** entrenar en 2017 y testear en 2018 rinde
peor (colapsa o sobre-marca) porque el conjunto de ataque de 2017 es **más pequeño y menos
diverso**, y su benigno también, así que su frontera no cubre la mayor variedad del 2018 → **la
generalización depende de la amplitud de los datos de entrenamiento**, que es exactamente el
argumento del plan para usar **varios datasets**.

**Saneado de disco:** vectorizados los tres días de 2017 a `.npz` (~40–90 MB c/u, autocontenidos),
se borran sus TSV (11–19 GB c/u, re-derivables del PCAP local). Se conservan los PCAP (la descarga
de CIC-IDS2017 pasa por el formulario de UNB, no es re-derivable de S3 como el 2018).

**Próximos pasos operativos:**

1. (Opcional, plan oficial) Añadir un tercer/cuarto origen —**UNSW-NB15**, **Malware-Traffic-
   Analysis.net**— para más diversidad, con mayor coste de integración.
2. Redacción de la memoria (al cierre, bajo orden explícita).

---

### [7 de agosto] - Robustez ante evasión, detección no supervisada (zero-day) y rigor estadístico

**Objetivos:** reforzar la tesis **sin datos nuevos** (solo los datasets ya vectorizados) por tres
vías que el plan/tribunal valora: (3) demostrar que las firmas de payload que son *fingerprint* de
herramienta se **evaden** trivialmente; (4) un enfoque **no supervisado** (detección tipo zero-day,
sin etiquetas de ataque); y (6) **rigor estadístico** (ROC/PR-AUC + intervalos de confianza) en vez
de solo accuracy. Scripts nuevos: [evasion_test.py](scripts/zeek/evasion_test.py),
[anomaly_detection.py](scripts/zeek/anomaly_detection.py), [rigor_metrics.py](scripts/zeek/rigor_metrics.py).

**Punto 3 — Prueba de evasión ([evasion_test.py](scripts/zeek/evasion_test.py)).** Se entrena un
byte-CNN y se mide su recall sobre los ataques (a) originales y (b) **evadidos**: el atacante
camufla los primeros bytes del flujo con los de un cliente benigno (spoofing trivial del banner/
cabecera); el resto no cambia. La vista conductual **meta+ráfaga** no depende del contenido, así que
es invariante al spoofing.

| Régimen | payload byte-CNN (original) | payload byte-CNN (evadido) | conducta meta+ráfaga |
|---------|-----------------------------|----------------------------|----------------------|
| SSH (:22, camufla 48 B del banner) | 1.000 | **0.354** (−0.65) | 1.000 (invariante) |
| DoS (:80, camufla 200 B de la petición) | 0.724 | **0.426** (−0.30) | 0.999 (invariante) |

**HALLAZGO CLAVE 11 (las firmas de payload evadibles se caen; la conductual aguanta):** camuflando
solo los primeros bytes —coste ínfimo para el atacante—, el recall de la detección por **payload se
desploma** (SSH 1.0→0.35, DoS 0.72→0.43), confirmando que esas firmas son *fingerprints* de la
herramienta (banner `paramiko`, User-Agents de Hulk; HALLAZGOS 7/8/10). La vista **conductual
(ráfaga) es inmune** al spoofing de payload y mantiene el recall (~1.0). Es la demostración
**activa** de que, contra evasión, la robustez exige la vista conductual, no solo el payload.
Resúmenes: [evasión ssh](models/phase2_evasion_Wednesday-14-02-2018_p22.md),
[evasión dos](models/phase2_evasion_Friday-16-02-2018_p80.md).

**Punto 4 — Detección no supervisada / zero-day ([anomaly_detection.py](scripts/zeek/anomaly_detection.py)).**
Se entrena **solo con tráfico benigno** (IsolationForest y un autoencoder) y se mide si los ataques
emergen como **anomalías**, sin usar sus etiquetas (escenario de ataque desconocido). Métrica
ROC-AUC (ataque = positivo):

| Régimen | payload (IsoForest) | payload (autoencoder) | conducta meta+ráfaga (IsoForest) |
|---------|---------------------|-----------------------|----------------------------------|
| Web (claro) | 0.758 | 0.792 | **0.912** |
| SSH (cifrado) | 0.695 | 0.568 | **1.000** |
| DoS (volumétrico) | 0.341 | 0.479 | 0.540 |

**HALLAZGO CLAVE 12 (incluso sin etiquetas, ninguna vista única basta — y el DoS volumétrico es el
más duro):** el enfoque no supervisado **funciona** cuando se usa la vista adecuada de cada régimen
—web por su payload anómalo (hasta 0.79) y, sobre todo, la **conducta**; SSH cifrado **imposible por
payload** (0.57, ≈ ruido cifrado) pero la **ráfaga detecta el 100% (1.0)**—, lo que **replica la
tesis supervisada en el terreno zero-day**. El caso difícil es el **DoS**: un GET de Hulk es *más
normal* que el benigno (payload-IF 0.34) y, como el «alto volumen» también aparece en benigno
legítimo (444 IPs, algunas de gran caudal), ni la ráfaga destaca sin etiquetas (0.54). Honesto y
relevante: la detección **no supervisada** de floods volumétricos es intrínsecamente dura y necesita
umbrales aprendidos o mejores agregados. Resúmenes `models/phase2_anomaly_*.md`.

**Punto 6 — Rigor estadístico ([rigor_metrics.py](scripts/zeek/rigor_metrics.py)).** ROC-AUC y
PR-AUC con **intervalos de confianza al 95% por bootstrap** (2000 remuestreos) y curvas ROC/PR (PNG),
para no depender de un accuracy puntual con clases pequeñas:

| Régimen | payload byte-CNN | payload histograma | conducta meta+ráfaga |
|---------|------------------|--------------------|----------------------|
| Web :80 | 1.000 [1.0, 1.0] | 0.995 [0.984, 1.0] | 1.000 [0.999, 1.0] |
| SSH :22 | 1.000 [1.0, 1.0] | 0.996 [0.990, 1.0] | 1.000 [1.0, 1.0] |
| DoS :80 | 0.678 [0.665, 0.690] | 0.842 [0.834, 0.851] | 0.843 [0.835, 0.851] |

Los IC son **estrechos y ~1.0** en web/SSH (separación nítida, aunque el histograma delata algo de
incertidumbre por el N pequeño) y **más bajos y bien acotados** en el DoS (N grande, señal per-flujo
genuinamente parcial). Gráficas: `models/phase2_rigor_*.png`. Añade el rigor que el tribunal espera
sobre las clases pequeñas del TFG.

**Fuera de alcance en esta tanda (requieren descargas o son de retorno marginal):**

- **Más días/datasets (Puntos 5 y 7):** un 4º día homólogo (DDoS 20-21-02) y otros orígenes
  (**UNSW-NB15**, **Malware-Traffic-Analysis.net**) exigen descargas nuevas; quedan pendientes.
- **Eje E (`conn.log` completo):** enriquecer la metadata con `duration`/inter-arribo/`conn_state`
  exigiría re-descargar ~150 GB de PCAP de 2018 de S3 y re-pasar Zeek horas, con retorno marginal
  (la ráfaga ya captura el grueso de la firma conductual). Aplazado.

**Próximos pasos operativos:**

1. (Opcional) Puntos 5/7 (más días/datasets) o Eje E, cuando compense el coste.
2. **Punto 2 — estudio del estado del arte** (pendiente, a la señal del autor).
3. Redacción de la memoria (al cierre, bajo orden explícita).

---

### [11 de agosto] - Revisión del tutor: el servicio sustituye al puerto, atributos de payload de la literatura y re-priorización hacia la memoria

**Revisión recibida (íntegra, para trazabilidad):**

> - Los puertos no deberían de ir como atributo (es un poco como la IP, depende de cada
>   configuración, no es un atributo *context indiferent*); el servicio podría ir si es
>   que Zeek tiene reglas para identificarlo.
> 1. Sobre los experimentos realizados, vas bien. Has entrenado los modelos a nivel de
>    byte, y funcionan bien (con *saliency maps*). La meta que te propuse era esa. Igual
>    no me ha quedado claro si has extraído atributos concretos del payload tipo
>    entropía... (y los que haya en la literatura científica) para unirlos a las
>    características obtenidas con Zeek. Luego, supongo que cada ejemplo corresponde a
>    una conexión (en TCP) que incluirá varios paquetes de tráfico.
> 2. Sí, igual mejor analizar más días/ataques de la base de datos en la que estás
>    trabajando. Profundizar lo más posible en esa base de datos. Probar los
>    clasificadores con otras bases de datos lo dejaría para trabajo futuro.
> 3. No tengo artículos identificados solo el libro que te pasé. [...] Tendrás que hacer
>    una búsqueda y hacer una síntesis de estrategias de ML que se utilizan en el
>    contexto de *network IDS*.
> 4. Priorizar una primera versión de la memoria (lo miraría a finales de agosto). El 6
>    de septiembre es el último día para entregar.

**Objetivos:** aplicar las correcciones accionables sobre el código y re-planificar el
trabajo restante conforme a la nueva priorización.

---

#### Corrección 1 — El puerto no puede definir el servicio

**Diagnóstico previo (verificado en el código, no asumido):**

- Como **atributo del modelo**, el puerto ya estaba excluido a propósito desde la Fase 2:
  la vista de metadatos son `n_pkts`, `tot_bytes`, `bytes/paquete` y `seq_len`
  ([hybrid_compare.py](scripts/zeek/hybrid_compare.py)), y el propio docstring documenta
  la exclusión. En la Fase 1 sí se usó `Dst Port` y fue precisamente la variable-atajo
  detectada y ablacionada el 31 de marzo — pero por un motivo empírico, no metodológico.
- Sin embargo, el puerto **sí seguía usándose para *seleccionar* el subconjunto evaluado**
  (`resp_p == 22` ≡ "SSH", `resp_p == 80` ≡ "HTTP") en los 15 scripts de evaluación. Eso
  hereda exactamente el mismo defecto que señala el tutor: define el servicio por una
  convención de configuración en lugar de por el tráfico.

**Hitos alcanzados:**

- **Zeek emite ahora su propia identificación de servicio**
  ([extract_payload.zeek](scripts/zeek/extract_payload.zeek)): nueva columna `service`
  con `c$service`, que rellenan los analizadores de protocolo de Zeek por DPI (es el
  mismo campo que alimenta `conn.log$service`). Como la detección es progresiva,
  [build_dataset.py](scripts/zeek/build_dataset.py) se queda con el último valor no vacío
  de cada `uid` y lo guarda en el `.npz` y el `_meta.csv`. Es la vía que pedía el tutor y
  la preferente para toda extracción futura.
- **Identificación por contenido para los días ya vectorizados**
  ([service_id.py](scripts/zeek/service_id.py)): los PCAP/TSV de los seis días
  procesados se borraron por espacio, así que re-ejecutar Zeek exigiría re-descargar
  ~150 GB. En su lugar el servicio se deriva de los bytes que el dataset **ya guarda**
  (`X_seq`) con firmas equivalentes a las de los analizadores de Zeek: banner `SSH-`,
  métodos/respuesta HTTP, *record* TLS, NBSS/SMB, TPKT/X.224 de RDP, saludos
  SMTP/FTP/POP3/IMAP, negociación Telnet y *greeting* de MySQL. Mismo criterio (el
  protocolo se reconoce por lo que dice el tráfico), sin coste de descarga.
- **Los 15 scripts de evaluación aceptan `--service`** (`ssh`, `http`, `ssl`...), que
  sustituye a `--port` en la selección del subconjunto. Se conserva `--port` únicamente
  para reproducir los resultados ya publicados en este diario.

**Validación medida (puerto vs contenido, tres días de 2018):**

| Día | Flujos comparables | El contenido confirma el puerto | Lo contradice |
|-----|--------------------|--------------------------------|---------------|
| Wednesday-14-02 (SSH) | 2.200.888 | 2.200.419 (**99,98%**) | 469 |
| Thursday-22-02 (Web) | 2.769.964 | 2.769.217 (**99,97%**) | 747 |
| Friday-16-02 (DoS) | 4.038.401 | 4.037.957 (**99,99%**) | 444 |

Y en los tres días de CIC-IDS2017 (mismo patrón, laboratorio distinto):

| Día | Flujos comparables | El contenido confirma el puerto | Lo contradice |
|-----|--------------------|--------------------------------|---------------|
| Tuesday-04-07 (SSH-Patator) | 98.154 | 98.033 (**99,88%**) | 121 |
| Wednesday-05-07 (DoS-Hulk) | 260.796 | 259.410 (**99,47%**) | 1.386 |
| Thursday-06-07 (Web) | 81.352 | 81.330 (**99,97%**) | 22 |

Informes: `models/phase3_service_id_<día>.md`.

**Lectura honesta (importante para la memoria):** en CSE-CIC-IDS2018, que es un
laboratorio controlado, puerto y servicio **coinciden casi perfectamente**, así que
**ningún resultado anterior cambia** por este motivo. El valor de la corrección no es
numérico sino **metodológico y de generalización**: el criterio deja de depender de la
configuración de la red. El efecto se ve en los flujos que la convención se dejaba
fuera —p. ej. **99 flujos HTTP fuera del puerto 80** el 22-02 y **75 flujos del puerto 22
que no son SSH** el 14-02 (que salen del "SSH benigno": 433 → 358)—; en una red real, con
servicios en puertos no estándar, esa diferencia dejaría de ser marginal.

---

#### Corrección 2 — Atributos concretos del payload (literatura) unidos a Zeek

**Diagnóstico previo:** la entropía de Shannon **sí** se extraía desde el 6 de mayo, pero
como un escalar suelto dentro de un vector de 257 dimensiones dominado por el histograma;
no había un conjunto de **descriptores interpretables** al mismo nivel que los de Zeek.
Ese desequilibrio es justo el que explicaba la "dilución" observada el 16 de junio
(concatenar 257 *features* casi aleatorias tapaba los 4 escalares útiles).

**Hitos alcanzados:**

- **19 descriptores del payload** ([payload_features.py](scripts/zeek/payload_features.py)),
  todos derivables de lo ya almacenado (histograma + entropía + secuencia), con su origen
  bibliográfico documentado en el módulo:
  - *Distribución de bytes y momentos* (media, desviación, byte dominante, masa de los 4
    dominantes, riqueza, distancia L1 a la uniforme) — **PAYL**, Wang & Stolfo, RAID 2004.
  - *Entropía normalizada, χ² frente a la uniforme e índice de coincidencia* — línea
    clásica de detección de contenido cifrado/comprimido (**Lyda & Hamrock**, IEEE S&P
    2007; **Dorfinger et al.**, 2011).
  - *Ratio de compresión* (zlib) como aproximación práctica a la complejidad de Kolmogorov.
  - *Entropía y diversidad de 2-gramas* — **Anagram**, Wang, Parekh & Stolfo, RAID 2006.
  - *Composición léxica* (imprimibles, alfanuméricos, control, no-ASCII, nulos, *run*
    imprimible más largo, tasa de transición) — descriptores estándar en detección de
    inyecciones y *shellcode* sobre protocolos en claro.
- **Evaluación de la unión payload + Zeek**
  ([payload_attrs_eval.py](scripts/zeek/payload_attrs_eval.py)): compara cinco vistas
  sobre el mismo subconjunto (seleccionado **por servicio**, balanceado 1:1, benigno
  limpio de la IP atacante, 5-Fold CV + test *held-out*): `payload-attrs` (19),
  `payload-hist` (257), `zeek-meta` (7 = 4 escalares + 3 ráfagas), **`zeek+attrs` (26, la
  unión que pide el tutor)** y `zeek+hist` (264, la fusión anterior).

| Régimen | `payload-attrs` (19) | `payload-hist` (257) | `zeek-meta` (7) | **`zeek+attrs` (26)** | `zeek+hist` (264) |
|---------|----------------------|----------------------|-----------------|-----------------------|-------------------|
| SSH cifrado (14-02) | 0.9833 | 0.9847 | **0.9986** | 0.9958 | 0.9819 |
| Web en claro (22-02) | 0.9606 | 0.9753 | **0.9926** | 0.9877 | 0.9877 |
| DoS volumétrico (16-02) † | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

*(CV accuracy, selección por servicio, balanceo 1:1, benigno limpio de la IP atacante.
† El día del DoS se midió tras la corrección de etiquetado que destapó esta misma tanda —
ver más abajo—; saturado a 1.0 en las cinco vistas, no discrimina entre ellas.)*
Resúmenes: `models/phase3_payload_attrs_<día>_<servicio>.md`.

**HALLAZGO CLAVE 13 (relevante para la memoria): 19 descriptores interpretables valen lo
que 257 dimensiones de histograma, y no diluyen la fusión.** `payload-attrs` iguala a
`payload-hist` con **13 veces menos dimensiones** (0.983 vs 0.985 en SSH; 0.961 vs 0.975
en web), y al unirlo con Zeek **`zeek+attrs` ≥ `zeek+hist`** en los dos regímenes
(0.996 vs 0.982 en SSH; empate en web con desviación mucho menor). Es decir: la
"dilución" del 16 de junio **no era un problema de la fusión sino de la representación**
—un vector compacto de atributos con significado se combina bien con los metadatos,
mientras que el histograma crudo ahoga a los escalares útiles—. Además, la importancia por
permutación sobre `zeek+attrs` en el caso web muestra una mezcla real de ambas familias
(`bytes_per_pkt` +0.066, `bigram_entropy_norm` +0.054, `n_pkts` +0.039, `std_byte` +0.034,
`burst_1s` +0.029, `ctrl_ratio` +0.024): la unión payload+Zeek **usa de verdad las dos
vistas**, no una sola.

---

#### Confirmación 3 — La unidad de ejemplo es la conexión TCP

El tutor lo supone correctamente y así es desde el 6 de mayo: cada ejemplo del dataset es
**una conexión TCP identificada por el `uid` de Zeek**, que agrega **todos los paquetes
con datos** de ese flujo (`FlowAcc` en [build_dataset.py](scripts/zeek/build_dataset.py)).
El histograma acumula hasta 64 KB de payload del flujo completo y la secuencia guarda los
primeros 256 bytes; `n_pkts` es literalmente el número de paquetes con datos agregados. No
requiere cambios, pero queda explicitado aquí para la memoria.

---

#### Hallazgo colateral: el benigno del día DoS estaba contaminado (corrección del HALLAZGO 8)

Al aplicar en `payload_attrs_eval.py` la limpieza del benigno (excluir la IP atacante,
lección del 17 de junio) al día del DoS, **todas las vistas saltaron a 1.0000**, en
contradicción directa con el HALLAZGO 8 (per-flujo todo débil, ≤0.74). Comprobado antes de
darlo por bueno:

- El atacante `18.219.193.20` genera **1.803.160 flujos** contra `172.31.69.25:80` en una
  **ráfaga continua sin huecos** (gap **máximo de 0,2 s**; ningún hueco > 60 s) desde las
  **17:45:27 hasta las 17:58:22 UTC**.
- La ventana etiquetada terminaba a las **17:52:59 UTC** (13:53 local), de modo que
  **740.821 flujos del propio atacante —el 65,1% de todo el "benigno" HTTP del día—**
  estaban etiquetados `Benign`. El benigno **genuino** son 396.977 flujos de 464 IPs.
- Causa raíz: el fin de ventana se fijó el 14 de julio con el `conn.log` de **una sola
  captura** (`UCAP...-part1`), no del día completo. Es **el mismo error de límite de
  ventana** que el del SSH corregido el 17 de junio.

**Corrección aplicada:** ventana del `DoS-Hulk` ampliada a **13:59 local (17:59 UTC)** en
[attack_metadata.py](scripts/zeek/attack_metadata.py) (con la verificación anotada) y
dataset re-etiquetado con [relabel_dataset.py](scripts/zeek/relabel_dataset.py) **sin
reprocesar los PCAP** (que ya no existen), usando la 5-tupla y el `ts` guardados:
**740.821 flujos** pasan de `Benign` a `DoS-Hulk` (1.062.339 → **1.803.160**; benigno
2.978.739 → 2.237.918). El emparejamiento por par {atacante, víctima}:puerto garantiza que
ningún tercero se reetiquete.

**HALLAZGO CLAVE 8 — REVISADO.** Re-ejecutado
[dos_burst.py](scripts/zeek/dos_burst.py) con las etiquetas corregidas (mismo protocolo:
1:1, `--cap 4000`, out-of-fold 5-Fold; selección por `--service http`):

| Vista | Macro-F1 (15-jul, benigno contaminado) | Macro-F1 (11-ago, benigno genuino) |
|-------|---------------------------------------|------------------------------------|
| payload-hist (per-flujo) | 0.7375 | **1.0000** |
| meta-básica (per-flujo) | 0.6186 | **0.9714** |
| meta+ráfaga (agregado) | 0.8057 | **1.0000** |

**Lo que cae y lo que se mantiene, honestamente:**

- **Cae** la afirmación central del HALLAZGO 8 —«*per-flujo ninguna vista sirve*»—. Era un
  artefacto de comparar **ataque contra ataque**: el 65,1% del "benigno" era el propio
  flood. Con benigno genuino, el payload per-flujo separa perfectamente el `GET` de Hulk
  del tráfico HTTP legítimo. También cae el caveat de «0.81 < 1.0 porque el benigno de :80
  son 444 IPs de alto volumen»: el techo lo ponía la contaminación, no la diversidad.
- **Se mantiene** que la ráfaga (agregado por origen) es la vista **más fuerte** (1.0000
  frente a 0.9714 de la metadata per-flujo) y, sobre todo, la **única robusta ante
  evasión**: el HALLAZGO 11 (7 de agosto) ya mostró que camuflar los primeros bytes hunde
  el *recall* del payload en el DoS (0.72 → 0.43) mientras `meta+ráfaga` se mantiene ≈1.0.
  El éxito del payload en el DoS es de nuevo un ***fingerprint* de herramienta** (los
  `User-Agent` y cabeceras de Hulk, ya identificados en el HALLAZGO 10), no contenido
  intrínseco del ataque.
- **Se mantiene el mapa de tres regímenes** como estructura del argumento, pero con una
  lectura más matizada: el DoS deja de ser "el régimen donde nada per-flujo funciona" y
  pasa a ser **"el régimen donde lo que funciona per-flujo es evadible"**. La conclusión
  de la tesis no se debilita —sigue exigiendo combinar payload y conducta—, pero el
  argumento correcto es el de **robustez ante evasión**, no el de **capacidad de
  detección**.

**Lección metodológica (para la memoria):** es la **segunda vez** que un límite de ventana
mal fijado contamina el benigno con el propio atacante y produce una conclusión errónea
(SSH el 17-jun, DoS ahora). El procedimiento correcto queda fijado: **verificar que la
ventana cubre toda la actividad continua del atacante sobre el dataset COMPLETO**, no
sobre una sola captura — comprobando que no quedan huecos y que la actividad del atacante
termina realmente donde acaba la ventana.

---

#### Re-planificación (puntos 2, 3 y 4 del tutor)

- **Punto 2 — profundizar en CSE-CIC-IDS2018, no en más datasets.** El trabajo del 4-6 de
  agosto (CIC-IDS2017 y generalización cruzada, HALLAZGOS 9 y 10) **no se descarta ni se
  borra**: pasa a presentarse como **trabajo futuro / validación complementaria**, y el
  esfuerzo restante se redirige a **más días y ataques del 2018** (DDoS 20-21/02, Bot
  02/03, Infiltration 28/02-01/03). Ver la sección «Fase 3» reescrita.
- **Punto 3 — estado del arte.** No hay artículos de partida más allá del libro del tutor;
  hay que hacer búsqueda propia y **sintetizar las estrategias de ML usadas en *network
  IDS***. Sigue pendiente y ahora es requisito explícito de la memoria.
- **Punto 4 — la memoria es la prioridad 1.** Primera versión para **finales de agosto**
  (el tutor la revisa entonces); entrega el **6 de septiembre**. Las experimentaciones
  nuevas se añaden **después** de tener una versión de la memoria, no antes.

**Próximos pasos operativos (en este orden, fijado por el tutor):**

1. **Primera versión de la memoria** (LaTeX) con lo ya demostrado. Prioridad absoluta.
2. **Estado del arte**: búsqueda y síntesis de estrategias de ML en *network IDS*.
3. **Más días/ataques del 2018** (DDoS, Bot, Infiltration), ya con el pipeline genérico.
4. Re-ejecutar con `--service` las evaluaciones que se citen en la memoria, para que las
   cifras publicadas no dependan de la convención de puertos.

---

### [19-22 de agosto] - Días 4, 5 y 6 (DDoS 20-02, Bot 02-03 y DoS 15-02) e Infiltration: el byte-CNN es frágil, aparece un régimen de PERIODICIDAD, y el payload resulta CIEGO a la intrusión

> **Re-priorización del usuario (21 de agosto).** El orden de trabajo pasa a ser:
> **1)** descargar y procesar más días, **2)** estado del arte, **3)** rehacer gráficos y
> contenido, **4)** escribir la memoria. Invierte el orden fijado por el tutor el 11-ago
> (memoria primero); queda anotado para no perder la trazabilidad de la decisión.

Se cierran dos días nuevos del CSE-CIC-IDS2018, ambos con el procedimiento completo
(descarga → ground-truth verificada empíricamente → Zeek → dataset → evaluación).

#### Día 4 — `Tuesday-20-02-2018` (DDoS-LOIC-HTTP): el DoS, pero **distribuido**

Diez atacantes contra `172.31.69.25:80`, 27.897–29.749 conexiones **cada uno**, con
`conn_state` **RSTO en el ~97%** (el originador manda RST: firma de LOIC). Frente al
DoS-Hulk del 16-02, que era **un solo origen con ~1 M de conexiones**, aquí la ráfaga
**por origen** es ~34× menor: es el **caso difícil** del régimen volumétrico.

- **Dataset:** 2.837.519 flujos, de ellos **289.328** `DDoS-LOIC-HTTP`. 451/451 capturas
  procesadas con Zeek, 0 errores.
- **Per-flujo (`--service http`):** byte-CNN **1.0000**, byte-LSTM 1.0000, mlp-seq 1.0000,
  mlp-hist 1.0000, metadatos 0.9985.
- **Ráfaga:** payload-hist 1.0000, meta-basica 0.9985, **meta+ráfaga 0.9982**. La ráfaga
  **ya no aporta**, justo lo previsible al repartir el flood entre diez fuentes.

#### Día 6 — `Thursday-15-02-2018` (DoS-GoldenEye + Slowloris): el día que estaba descargado y nadie había usado

Auditando qué días se habían descargado y cuáles usado (a petición del autor, 21-ago)
apareció `data/raw/15-02-2018.csv`, de **24 de abril de 2026** —un mes después de arrancar el
proyecto— **sin una sola referencia en todo el repositorio**. Su MD5 coincide con el fichero
oficial (`30af0113266137dc4cb6dcd984ccfdb6`), así que era el CSV correcto: simplemente nunca
se usó. Se bajaron sus PCAP (38,4 GiB) porque es el **tercer día volumétrico**, y con él el
HALLAZGO 14 pasa de **un par de días a seis pares dirigidos**.

**Ground-truth verificada** con `find_attacker.py` sobre `UCAP172.31.69.25` (38.536 conexiones):

| Ataque | Atacante | Conexiones | Ventana local | `conn_state` | Perfil |
|--------|----------|-----------:|---------------|--------------|--------|
| DoS-GoldenEye | `18.219.211.138` | 29.696 | 09:27:42–10:11:45 | RSTO 23.272 | **a oleadas**, huecos de hasta 8,8 min |
| DoS-Slowloris | `18.217.165.70` | 7.248 | 11:00:12–11:41:34 | RSTR 4.615 / S0 2.233 | **goteo plano**, ~800-850 conex./5 min |

Ambos hablan **exclusivamente** con la víctima por el `:80` (cero destinos ajenos), así que
las ventanas anchas no pueden mal-etiquetar nada.

> **Reutilización de infraestructura del laboratorio:** `18.219.211.138`, el atacante del
> GoldenEye, es **la misma IP que el C2 de la botnet del 02-03**, dos semanas después y con
> un rol de ataque completamente distinto. Es el segundo caso (`18.218.115.60` ataca web el
> 22-02 y participa en el DDoS del 20-02). **No hay fuga en nuestras vistas** —el payload son
> bytes y la metadata son contadores; la IP no es una *feature*—, pero invalidaría cualquier
> experimento cruzado que incluyera identificadores de red, y conviene decirlo en la memoria.

- **Dataset:** 1.997.325 flujos — **26.861** `DoS-GoldenEye` y **5.015** `DoS-Slowloris`.
  450/450 capturas, 0 errores, 4,0 h.
- **Per-flujo (`--service http`):** byte-CNN 1.0000, byte-LSTM 0.9999, mlp-hist 0.9998,
  mlp-seq 0.9935, metadatos **0.9589**.

**Dato colateral sobre la ceguera del payload:** el `conn.log` contaba 29.696 conexiones de
GoldenEye y 7.248 de Slowloris, pero al dataset llegan 26.861 y 5.015 — solo las que llevan
payload. GoldenEye conserva el **90%**; **Slowloris solo el 69%**. Coherente con el
HALLAZGO 16: cuanto más «lento» y menos hablador es el ataque, más se le escapa a un pipeline
basado en contenido.

#### La ráfaga se diluye conforme el ataque se reparte entre orígenes (refinamiento del HALLAZGO 8)

> **Figura:** [F36_rafaga_diluida](figuras/png/F36_rafaga_diluida.png).

Con tres días volumétricos, el agregado de ráfaga por origen se puede comparar de verdad:

| Día | Ataque | orígenes | meta-basica | meta+ráfaga | ¿aporta? |
|-----|--------|---------:|------------:|------------:|----------|
| 16-02 | DoS-Hulk (~1 M conex.) | 1 | 0.9714 | **1.0000** | sí, es la vista más fuerte |
| 15-02 | GoldenEye + Slowloris | 1 + 1 | 0.9589 | **0.9964** | sí, claramente (+0,038) |
| 20-02 | DDoS-LOIC | **10** | 0.9985 | 0.9982 | **no** |

El valor del agregado por origen **se degrada conforme el flood se distribuye**: con un solo
origen es la vista dominante; repartido entre diez, deja de aportar. Es un matiz que **solo se
ve teniendo los tres días**, y que la memoria debería recoger: la ráfaga no es una solución
universal al régimen volumétrico, es una solución al régimen volumétrico **concentrado**.

#### HALLAZGO CLAVE 14: lo que no transfiere del byte-CNN es el UMBRAL, no la representación

> **Figuras:** [F33_cruzado_entre_dias](figuras/png/F33_cruzado_entre_dias.png) (con umbral fijo), **[F38_calibracion_cruzada](figuras/png/F38_calibracion_cruzada.png)** (lo que revela el AUC) y **[F41_recalibracion](figuras/png/F41_recalibracion.png)** (el arreglo, con 25 etiquetas).

> **Este hallazgo se enunció el 19-ago con DOS días y se CORRIGIÓ el 22-ago al añadir el
> tercero.** La primera versión decía «el modelo más expresivo es el que peor generaliza», y
> con un solo par de días lo parecía. Con `Thursday-15-02-2018` en la mesa, esa lectura es
> **falsa como generalización**: hay pares donde el byte-CNN transfiere perfecto y es la
> **mejor** de las tres vistas. Se conserva la corrección a la vista porque el error —inducir
> una ley general de n=2— es en sí mismo la lección metodológica.

Con **tres días volumétricos** —DoS-Hulk (16-02), GoldenEye+Slowloris (15-02) y DDoS-LOIC
(20-02)— se pueden medir **seis pares dirigidos** de entrenar-en-A / testear-en-B dentro del
mismo régimen:

| Entreno → Test | payload-hist | metadatos | byte-CNN |
|----------------|-------------:|----------:|---------:|
| 15-02 → 16-02 | 1.0000 | 0.8393 | **1.0000** |
| 16-02 → 15-02 | 0.7904 | 0.7510 | **0.9597** |
| 15-02 → 20-02 | 1.0000 | 0.9854 | **0.4996** *(recall atk 0.0000)* |
| 20-02 → 15-02 | 0.7218 | 0.6025 | **0.5000** *(recall atk 0.0000)* |
| 16-02 → 20-02 | 1.0000 | 0.4700 | **0.5000** *(recall atk 0.0000)* |
| 20-02 → 16-02 | 0.9928 | 0.5011 | **0.5000** *(recall atk 0.0000)* |

**Lo que dicen esos números con umbral fijo:**

1. **El byte-CNN falla de forma binaria.** O transfiere casi perfecto (1,0000, 0,9597) o
   colapsa a **0,4996 / 0,5000 con recall de ataque exactamente 0,0000** — degenerado,
   predice una sola clase. **Nunca cae en un valor intermedio.**
2. **El histograma se degrada con suavidad:** 1,0000 → 0,7218. Nunca colapsa.
3. **La frontera parece ser la herramienta:** el byte-CNN colapsa siempre que el 20-02
   (LOIC) está en un lado, y nunca entre 15-02 y 16-02.

#### …y la vuelta de tuerca: el colapso es de CALIBRACIÓN, no de representación (22-ago)

La accuracy con un umbral fijo **no distingue** «el modelo no sabe» de «el modelo sabe pero
su umbral está mal». El **AUC** sí, porque mide la calidad del **orden** sin depender del
umbral. Al medirlo ([cross_calibration.py](scripts/zeek/cross_calibration.py)) el resultado
**invierte la lectura anterior**:

| Entreno → Test | byte-CNN AUC | F1 @0,5 | F1 óptimo | histograma AUC | F1 @0,5 | F1 óptimo |
|---|---:|---:|---:|---:|---:|---:|
| 16-02 → 20-02 | 0,9724 | **0,0000** | **0,9849** | 1,0000 | 1,0000 | 1,0000 |
| 20-02 → 16-02 | 0,9886 | **0,0000** | **0,9918** | 1,0000 | 0,9927 | 0,9997 |
| 15-02 → 20-02 | 0,9758 | **0,0000** | **0,9872** | 1,0000 | 1,0000 | 1,0000 |
| 20-02 → 15-02 | 0,9854 | **0,0000** | **0,9899** | **0,6749** | 0,6145 | **0,7346** |
| 15-02 → 16-02 | 1,0000 | 1,0000 | 1,0000 | 1,0000 | 1,0000 | 1,0000 |
| 16-02 → 15-02 | 1,0000 | 0,9581 | 0,9999 | **0,8023** | 0,7348 | **0,8538** |

- **El byte-CNN tiene AUC ≥ 0,9724 en los SEIS pares.** Su representación transfiere
  *siempre*. Los cuatro «colapsos» se recuperan **enteros** con el umbral adecuado
  (F1 ≥ 0,9849). Lo que no transfiere es la **calibración**: en el día nuevo sus
  puntuaciones caen dos órdenes de magnitud (media 0,0051 en ataque y 0,0006 en benigno),
  así que un umbral de 0,5 lo manda todo a `Benign`.
- **El histograma es el que falla de verdad.** En la dirección «→ 15-02» su AUC baja a
  0,6749 y 0,8023, y **ni con el umbral óptimo** pasa de 0,7346 y 0,8538. Ahí el límite es
  de representación, no de umbral.

**Es exactamente al revés de lo que parecía.** La representación más transferible de las dos
es la del **byte-CNN**; la que se degrada de verdad es la del histograma. Lo que hacía
parecer lo contrario era juzgar la transferencia con un umbral fijo.

#### …y el remate: recalibrar cuesta 25 etiquetas (23-ago)

El «umbral óptimo» de la tabla anterior es un **oráculo**: se elige conociendo las etiquetas
del día de test, así que es una cota superior y **no un método**. Un IDS desplegado no las
tiene. [cross_recalibration.py](scripts/zeek/cross_recalibration.py) lo sustituye por
**Platt scaling** —σ(A·logit(p)+B)— ajustado sobre una muestra **pequeña** del día nuevo y
evaluado sobre el **resto**, que el calibrador nunca ve. Se añaden además las dos métricas de
calibración que faltaban: **ECE** (*Expected Calibration Error*) y **Brier**.

| Entreno → Test | F1 sin recalibrar | F1 con **25 etiquetas** | ECE antes → después |
|---|---:|---:|---|
| 16-02 → 20-02 | 0,3333 | **0,9750** | 0,4973 → 0,0216 |
| 20-02 → 16-02 | 0,3333 | **0,9912** | 0,4991 → 0,0087 |
| 15-02 → 20-02 | 0,3332 | **0,9828** | 0,4967 → 0,0170 |
| 20-02 → 15-02 | 0,3333 | **0,9698** | 0,4993 → 0,0216 |
| 15-02 → 16-02 | 1,0000 | 1,0000 | 0,0002 *(ya calibrado)* |
| 16-02 → 15-02 | 0,9597 | **0,9999** | 0,0611 → 0,0002 |

- **Veinticinco flujos etiquetados bastan** en los cuatro pares colapsados. Más etiquetas
  apenas mejoran, salvo en el par más difícil (20-02 → 15-02: recall 0,9571 con 25 frente a
  0,9997 con 1000). En despliegue, eso es que un analista etiquete 25 conexiones.
- **El ECE separa perfectamente** los pares rotos (0,4967-0,4993, prácticamente el máximo
  posible) de los sanos (0,0002-0,0611). Es la métrica que delata el problema, y el trabajo
  no la reportaba.
- **Recalibrar nunca perjudica:** el par que ya funcionaba pasa de 0,9597 a **0,9999**.

> **Corroboración independiente.** El trabajo *Cross-Dataset Transformer-IDS with Calibration
> and AUC Optimization* (2026) documenta **el mismo fenómeno** en otros datasets: ~99 % dentro
> del dataset, cerca del azar al cruzar, con el AUC revelando que la representación sí
> transfiere (Transformer F1 0,55 / AUC 0,80 frente a CNN-LSTM F1 0,32 / AUC 0,64), y lo
> corrige con **Platt scaling**, bajando el ECE de 0,25 a 0,06. Nuestro punto de partida es
> peor (ECE ≈ 0,499) y la mejora, mayor. Que un trabajo independiente llegue a la misma
> conclusión por otro camino refuerza el HALLAZGO 14 considerablemente.

**Para la memoria, esto convierte el hallazgo de diagnóstico en receta:** el byte-CNN no hay
que descartarlo, hay que **recalibrarlo** al desplegarlo en un dominio nuevo, y el coste es
trivial.

> **Lección metodológica (la más importante de la tanda).** Este hallazgo se enunció tres
> veces y cambió las tres: con 2 días («el modelo más expresivo generaliza peor»), con 6
> pares («falla de forma binaria») y al medir el AUC («falla de calibración, no de
> representación»). Cada versión era consistente con los datos que había y **falsa** con los
> siguientes. Para la memoria: **nunca juzgar la transferencia entre dominios con un umbral
> fijo**, y desconfiar de una ley inducida de pocos casos.

**Lo que hay que decir en la memoria**, entonces, no es «el CNN generaliza peor», sino:

- La **representación** aprendida por el byte-CNN **es la más transferible**, pero su
  **confianza no lo es**: un IDS desplegado con umbral fijo **falla en silencio** ante una
  herramienta no vista — sigue ordenando bien, pero no dispara ni una alerta. Es un aviso
  operativo concreto, y se arregla recalibrando con unas pocas muestras del dominio nuevo.
- El **histograma** no necesita recalibración, pero tiene **techo**: hay pares donde su
  señal simplemente no basta.

> **Matiz honesto (y trabajo que genera):** que el CNN sea *degenerado* y no simplemente
> impreciso sugiere que lo que no transfiere puede ser el **umbral de decisión** tanto como
> la representación. Distinguir ambas cosas es exactamente lo que dan las **curvas PR /
> calibración** que seguían pendientes en el Eje D: este resultado las convierte en el
> siguiente paso natural, y ya no opcional.

#### Día 5 — `Friday-02-03-2018` (Bot, Ares): la ground-truth hay que buscarla al revés

Este día **rompe el método** de los anteriores. No hay una víctima única que delate al
atacante en el ranking de top-talkers, que es lo que busca `find_attacker.py`: la estructura
es **un C2 externo y muchos hosts internos infectados**. Y el CSV del día **no trae IPs**
(empieza en `Dst Port`), a diferencia del CSV del 20-02.

Se invirtió el orden: **primero** la extracción de payload de todo el día y **después** la
localización del C2 sobre los TSV, buscando destinos comunes en el `:8080` que el CSV señala
como puerto del Bot (281.634 de 286.191 flujos). Resultado:

- **C2:** `18.219.211.138`, **solo** puerto 8080 (438.825 paquetes, ningún otro puerto).
- **10 bots**, todos en `172.31.69.x`: `.6 .8 .10 .12 .14 .17 .23 .26 .29 .30`. Nueve baten
  ~15.000 flujos cada uno; **`172.31.69.12` solo 4.988** (un tercio): se infectó tarde o
  dejó de responder antes.
- **Ventana:** 10:13:28–15:53:46 local, **continua** — hueco máximo **32,6 s** en 5 h 40 min.
  La doc oficial parte el Bot en dos franjas (10:11–11:35 y 14:24–15:55) y **en los datos no
  hay tal corte**. Es la **tercera vez** que la documentación no cuadra con las capturas
  (SSH 17-jun, Hulk 11-ago).
- **Dataset:** 3.347.221 flujos, **142.925** `Bot`. El recuento coincide **exactamente** con
  la suma de flujos por bot, así que el etiquetado captura el tráfico al C2 y nada más.
- **Per-flujo (`--service http`):** byte-CNN 1.0000, mlp-seq 1.0000, byte-LSTM 0.9999,
  mlp-hist 0.9992, metadatos 0.9986. **Ráfaga:** 0.9992 / 0.9986 / **0.9964**.

#### HALLAZGO CLAVE 15: la firma de la botnet es la PERIODICIDAD, y ninguna vista actual la mide

> **Figuras:** [F34_perfiles_temporales](figuras/png/F34_perfiles_temporales.png) (perfil agregado) y **[F37_interarribo_beacon](figuras/png/F37_interarribo_beacon.png)** (la medida que lo demuestra).

El perfil temporal del tráfico al C2, en bloques de 10 minutos:

```
10:10-11:30   rampa de subida, pico de 38.318 paquetes
11:40-15:20   MESETA PLANA de ~8.035 paquetes cada 10 min  <-- beaconing
14:20         pico de 22.873   (ordenes)
15:30-15:50   picos de 34.065 y 34.927
```

Durante casi **cuatro horas** el tráfico al C2 es constante **hasta la tercera cifra
significativa**. Eso es un **metrónomo**: los bots consultan al C2 a intervalo fijo. Es un
**cuarto régimen de firma**, cualitativamente distinto de los tres ya cubiertos — no vive en
el payload (SSH cifrado → conducta), ni en el contenido (web en claro → payload), ni en el
volumen (DoS → agregado), sino en el **intervalo entre conexiones**.

**El beacon, medido (22-ago).** La afirmación anterior se apoyaba en el perfil agregado,
que es **ambiguo**: el DDoS-LOIC también es plano. La medida que no es ambigua es el
**intervalo entre conexiones consecutivas de un mismo origen**, y se calcula directamente
desde el `.npz` (`ts` + `orig_h`), sin necesidad del `conn.log`:

| Banda | Bot (ataque) | Benigno del mismo día |
|-------|-------------:|----------------------:|
| 0,50–0,55 s | **41,8 %** | 1,3 % *(×32)* |
| 2,00–2,05 s | **49,3 %** | 0,7 % |
| **Suma de las dos** | **91,1 %** | 2,0 % |

Ares late con **dos intervalos discretos** —~0,5 s y ~2,0 s— que concentran el **91,1 % de
sus intervalos en dos bandas de 50 ms**, mientras el tráfico legítimo del mismo día es una
curva suave decreciente sin ninguna moda. Como control: el DDoS-LOIC tiene una concentración
del 3,3 % y el DoS-Hulk del 13,0 %, frente al **47,1 %** del Bot.

Y aquí está lo importante: **ninguna de las vistas del trabajo lo mide**. El payload no lo
ve, los escalares de flujo no lo ven, y las ventanas de ráfaga (1/5/30 s) miden *volumen*,
que es precisamente lo contrario de un beacon regular — de hecho `meta+ráfaga` **resta**
(0.9964 frente a 0.9986 de la metadata sola). El 1.0000 del byte-CNN en este día es, con
toda probabilidad, la **huella HTTP del C2 de Ares**, no "lo que es una botnet". Esto
conecta directamente con el **Eje E** (inter-arribo desde `conn.log`), aplazado por «retorno
marginal» y que este día justifica.

> **Limitación que debe declararse en la memoria:** **no existe un día homólogo de botnet**
> en el dataset, así que el contraste cruzado que desenmascaró al byte-CNN en el DoS
> **no se puede repetir en este régimen**. El 1.0000 del Bot no está validado contra el
> mismo test que sí suspendió al DoS.

#### HALLAZGO CLAVE 16: el pipeline de payload es CIEGO al 94,4% de la Infiltration — por construcción

> **Figura:** [F35_ceguera_infiltracion](figuras/png/F35_ceguera_infiltracion.png).

`Wednesday-28-02-2018` (Infiltration) **se descargó y se analizó, pero deliberadamente NO se
pasó por el pipeline de payload**, y el motivo *es* el resultado.

**Cómo se localizó.** El CSV del día no trae IPs, y los puertos del ataque están **dispersos**
(53 con 24.522 flujos, 443 con 17.000, 3389 con 4.400, 80, 445, 135, 139, 22, 137, 123, 67…):
eso no es un ataque contra un servicio, es **reconocimiento interno**. Con
[find_host.py](scripts/zeek/find_host.py) se buscó la IP que la documentación da como
atacante, `13.58.225.34`: aparece **1.669 veces** en `capEC2AMAZ-O4EL3NG-172.31.69.24-part2`
y 1–2 veces (ruido de coincidencia binaria) en las otras 436 capturas. La víctima es
`172.31.69.24` — **el mismo host cuya captura falta en el día Bot**, sustituida allí por un
acceso directo de Windows.

**El ataque tiene dos fases con propiedades opuestas** (Zeek sobre la captura de la víctima,
196.699 conexiones):

| Fase | Conexiones | Puerto | Payload |
|------|-----------:|--------|---------|
| **Canal C2** (`13.58.225.34` ↔ víctima) | **5** | **31337** | **100% con payload**, 195.816 B |
| **Escaneo interno** (víctima → 612 destinos) | **193.097** | 53, 135, 443, 22, 445, 3389… | **94,4% SIN payload** |

El `conn_state` del escaneo: **`S0` 158.474 (82%)** —SYN sin respuesta—, `REJ` 21.069,
`SF` 8.505, `RSTR` 2.255, `S1` 1.140, `SH` 988. Solo **10.774 conexiones (5,6%)** transportan
algún byte de aplicación; las otras **182.323 (94,4%)** no transportan **ninguno**. Zeek ni
siquiera puede identificar el servicio en 183.907 de ellas (`service = "-"`), porque no hay
contenido que analizar. Ventana de la actividad saliente: 10:38:27–17:42:23 local.

**Por qué esto importa más que un día más de dataset.** `extract_payload.zeek` solo registra
flujos **con payload TCP**. No es que el análisis de bytes *funcione peor* en este ataque:
**no puede verlo**. Una fase entera de la intrusión —el reconocimiento, que es justo lo que
un IDS debería cazar antes de que haya daño— es **estructuralmente invisible** a cualquier
enfoque basado en contenido, por bueno que sea el modelo. El **HALLAZGO CLAVE 1** ya lo
apuntaba con el FTP-BruteForce (un ataque sin payload); aquí es el **94,4% de una intrusión
real**, y con el contraste perfecto al lado: las 5 conexiones del C2, que sí llevan payload,
son el 0,003% de las conexiones del ataque.

Es el argumento más fuerte de la tesis del TFG, y llega por la vía del **resultado negativo**:
*ninguna vista basta por sí sola* no es aquí una cuestión de exactitud, sino de **existencia
del dato**.

**Por qué no se construye el dataset de este día.** Además de que solo el 5,6% del ataque
sería visible —una muestra sesgada—, el ataque **no se puede expresar** con el modelo de
`attack_metadata.py`, que empareja `{atacante, víctima}:puerto + ventana`:

- El "ataque" es **un origen contra 612 destinos** en decenas de puertos. Enumerar 612 IPs
  como `victim_ips` haría que la regla `pair.issubset(ips)` de `DayLabeler` etiquetase como
  ataque **cualquier flujo entre dos hosts internos cualesquiera**.
- Tampoco vale «todo lo que salga de la víctima»: su ventana saliente llega hasta las 17:42 y
  buena parte es tráfico legítimo suyo (DNS, navegación SSL).

Etiquetarlo bien exigiría una regla **basada en origen + `conn_state` + fan-out**, no en el
par de IPs. Se deja anotado como trabajo futuro, no como deuda silenciosa.

**Qué lo detectaría sí o sí.** La firma de este ataque es el **abanico** (un origen, 612
destinos) y el **`conn_state`** (82% de SYN sin respuesta). Ninguna de las dos vive en el
payload, y **ninguna de las dos la mide el pipeline actual**. Son exactamente las features
del **Eje E** (`conn.log`: `conn_state`, inter-arribo, duración). Junto con el *beaconing*
del Bot (HALLAZGO 15), este día convierte el Eje E de «opcional, retorno marginal» en la
ampliación con mayor retorno pendiente del trabajo.

> **`Thursday-01-03-2018`** es el segundo día de Infiltration y, por construcción del
> escenario, cabe esperar la misma estructura. No se descarga: repetiría el hallazgo con
> ~49 GB más de tráfico y sin aportar un régimen nuevo.

#### HALLAZGO CLAVE 17: la evasión distingue la huella de la herramienta del contenido real

> **Figura:** [F39_evasion_interarribo](figuras/png/F39_evasion_interarribo.png).

Cierra el **Eje E** por su mitad medible y, de paso, corrige cómo se debe hacer un test de
evasión. Se construyen **seis características de inter-arribo** por flujo (`dt_prev`,
`dt_next`, `media_local`, `cv_local` —el coeficiente de variación, ~0 en un metrónomo—,
`regularidad` y `frac_cerca_mediana`) desde el `.npz`, **sin `conn.log`**, y se somete cada
vista al ataque del HALLAZGO 11: el atacante sobrescribe los primeros bytes de cada flujo
con los de un cliente benigno.

> **Corregido el 24-ago:** aquí se escribió que `cv_local` era «LA característica del
> beaconing». La **ablación** lo desmiente: en *leave-one-out* pesa más `media_local`
> (0,0125 frente a 0,0079) y por sí sola la mejor es `dt_prev` (0,9669). Además
> `regularidad` **estorba** —quitarla mejora el resultado—. Ver el diario del 24 de agosto.

| Día | payload (original → evadido) | meta+ráfaga | inter-arribo **solo** |
|---|---|---|---|
| 02-03 Bot | 1,0000 → **0,0025** | 0,9983 | **0,9900** |
| 16-02 DoS-Hulk | 1,0000 → **0,0417** | 1,0000 | 0,9950 |
| 20-02 DDoS-LOIC | 1,0000 → **0,0108** | 0,9992 | 0,9467 |
| 22-02 Web | 0,9672 → 0,0164 *(ver abajo)* | 1,0000 | **0,8525** |

**1. El 1,0000 del payload en el día Bot era huella de herramienta pura.** Camuflando 160
bytes cae a **0,0025**: deja de detectar prácticamente nada. Lo mismo en Hulk y LOIC.

**2. Seis características temporales, sin mirar un solo byte, dan 0,9900 de recall** en el
Bot y son **inmunes a la evasión por construcción**. La periodicidad del HALLAZGO 15 no es
solo medible: es **usable**.

**3. Y no son buenas «porque sí»:** caen a **0,8525** en el día web, que es exactamente
donde la firma no es temporal sino de contenido. Discriminan por régimen, como debe ser.

**El aviso metodológico, que vale para toda la memoria.** En el día web el payload también
parecía desplomarse (0,0164), pero repitiendo con un prefijo de **24 bytes** —que no llega a
la inyección— **aguanta en 0,8852** (caída de solo 0,0820):

| Día web, prefijo camuflado | payload original | evadido | caída |
|---|---|---|---|
| 160 bytes | 0,9672 | 0,0164 | 0,9508 |
| **24 bytes** | 0,9672 | **0,8852** | **0,0820** |

Con 160 bytes no se estaba evadiendo la detección: **se estaba borrando el ataque**, porque
el `union select` vive en esos bytes. Eso separa dos cosas que parecían iguales:

- **SSH, DoS, Bot** → los primeros bytes son la **huella de la herramienta**.
  Sobrescribirlos es gratis y el ataque sigue funcionando: **evasión real**.
- **Web** → los primeros bytes **son el ataque**. Sobrescribirlos no es evadir, es dejar de
  atacar: la firma de payload es **contenido genuino**.

Es decir, el **HALLAZGO CLAVE 4** —«en payload en claro, el payload gana»— **sobrevive al
test de evasión** cuando el test se hace bien. Y la regla para la memoria: *un test de
evasión solo es válido si el ataque sigue siendo el ataque después de la modificación*.

> **Limitación honesta:** el inter-arribo **no mejora a la ráfaga**. `meta+ráfaga` iguala o
> supera a `meta+inter-arribo` en tres de los cuatro días. Su valor es ser una vista
> **compacta** (6 características frente a las decenas de la metadata), **inmune a la
> evasión**, y demostrar que la firma del Bot es explotable. No es una vista superior, y la
> memoria no debe presentarla como tal.

#### Notas de método e infraestructura

- **Nuevo** [run_zeek_payload_batched.py](scripts/zeek/run_zeek_payload_batched.py): los TSV
  de payload ocupan **~1,48× el PCAP** de origen (medido sobre el log del 16-02: 69,1 GB de
  TSV desde 46,8 GB de PCAP), así que un día no cabe en disco con el procedimiento literal
  del Eje C. Este envoltorio procesa captura a captura y **borra cada PCAP en cuanto su TSV
  existe**, bajando el balance de +1,48× a +0,48×. La existencia del `.tsv` es el único
  estado, así que reanudar es idempotente.
- **Tres defectos corregidos en** [dos_burst.py](scripts/zeek/dos_burst.py): la plantilla del
  informe estaba **cableada al día del Hulk** y, aplicada a otros días, rotulaba cualquiera
  como *«DoS-Hulk vs HTTP-benigno (:80)»*, anunciaba `:80` cuando el Bot va por el `:8080`,
  arrastraba la nota de la corrección del 11-ago a días donde esa primera versión errónea
  nunca existió, y titulaba una botnet como *«régimen volumétrico»*. Como estos `.md` son la
  fuente de las figuras, el error habría llegado a la memoria.
- **Defecto del dataset original:** el host `172.31.69.24` del día Bot **no tiene captura**;
  el archivo oficial trae en su lugar un **acceso directo de Windows de 697 B**
  (`capEC2AMAZ-O4EL3NG-172.31.69.24 - Shortcut.lnk`). Si fue un bot, su tráfico no está.
- **Zona horaria del 02-03: UTC-4 confirmada empíricamente.** Por calendario el 2 de marzo
  es aún EST (UTC-5), pero con -5 las horas no cuadran con el CSV (saldrían las 09–14 h y el
  CSV marca 10–15 h); con -4 encajan exactamente.
- **El equipo se suspende durante los trabajos largos** (Modern Standby S0): una extracción
  de ~4 h de cómputo tardó **18,8 h de reloj**, avanzando solo en los despertares. Se
  resuelve con un inhibidor `SetThreadExecutionState` mientras dura el trabajo. *Ojo:
  `0x80000000` en PowerShell se parsea como `Int32` negativo; hay que escribirlo
  `[uint32]2147483648`.*

---

### [22 de agosto] - Estado del arte (prioridad 2): la taxonomía, y qué de ella mejora lo nuestro

> Fuente documental: `Machine Learning en NIDS.pdf` (revisión 2020-2026, 38 referencias).
> Fuente experimental: [sota_baselines.py](scripts/zeek/sota_baselines.py) →
> `models/phase3_sota_*.json`.

No basta con resumir la literatura: el punto 3 del tutor pide **sintetizar las estrategias de
ML aplicadas a *network IDS***, y la pregunta que importa para este trabajo es si alguna de
ellas **mejora lo que ya tenemos**. Así que la síntesis va acompañada de la comprobación.

#### La taxonomía, en siete familias

| Familia | Ejemplos | Qué aporta | Qué cuesta |
|---|---|---|---|
| **Ensembles sobre flujo** | Random Forest, XGBoost, LightGBM | imbatibles en volumétrico, coste de inferencia mínimo | miopía contextual: cada flujo es una isla |
| **Tabular profundo** | TabNet | potencia de DNN con selección interpretable | 97 % en 2017, 95 % en 2018 |
| **Grafos** | GNN, E-GraphSAGE | movimiento lateral, anomalía topológica | gestión de estado compleja, riesgo de fuga temporal |
| **Payload como imagen** | CNN 2D sobre bytes rasterizados | patrones espaciales del código malicioso | **destruye la causalidad temporal** del tráfico |
| **Transformers** | ET-BERT, DeBERTav2 | semántica del paquete, *malware* ofuscado | autoatención **O(N²)**: inviable a velocidad de línea |
| **Espacios de estados** | MambaNetBurst (Mamba-2) | byte-level **sin tokenización ni preentreno** | escala lineal; es la punta de lanza 2025-26 |
| **Híbridos multimodales** | AE-GMM, CNN-RNN/LSTM, CPS-IDS (*cross-attention*) | fusión de flujo y payload | complejidad de diseño |

**Dónde encaja este TFG.** Nuestro híbrido de dos ramas con fusión tardía (Eje B) es un
miembro de la última familia, la que el documento identifica como *«el horizonte resolutivo
de los NIDS multimodales»*. Nuestro byte-CNN es la familia 4 pero **sobre la secuencia, no
rasterizada a imagen** — que es justo la crítica que el documento hace a la rasterización.
Lo que **no** hemos tocado: grafos, Transformers y Mamba.

#### Dos afirmaciones del estado del arte, comprobadas sobre nuestros datos

El documento hace dos afirmaciones concretas y falsables. Las dos se han medido.

**(A) «La supremacía del Ensemble Learning»** — RF/XGBoost dominan sobre características de
flujo (~99,9 % intra-dataset; XGBoost 0,9367 en cruzado).

**Dentro del día la afirmación SE CONFIRMA**, aunque con margen pequeño: los ensembles ganan
en la vista tabular, que es donde la literatura los sitúa. El mayor margen es de **+4,7
puntos** (22-02, metadatos: RandomForest 0,9581 frente a 0,9109 de nuestro MLP); en las demás
vistas y días la diferencia es ruido, porque todo ronda 0,999.

La prueba que decide es la transferencia **entre días** (macro-F1 sobre el día de test):

| Entreno → Test | Vista | MLP (nuestro) | RandomForest | XGBoost |
|---|---|---:|---:|---:|
| 20-02 → 16-02 | payload-hist | **0,9952** | 0,3333 | 0,3333 |
| 20-02 → 15-02 | payload-hist | **0,7446** | 0,3333 | 0,3333 |
| 16-02 → 15-02 | metadatos | **0,8444** | 0,5744 | 0,6096 |
| 20-02 → 15-02 | meta+ráfaga | **0,5996** | 0,4818 | 0,4480 |
| 15-02 → 16-02 | meta+ráfaga | 0,9969 | **0,9992** | 0,9984 |

**Y aquí se invierte.** En las direcciones difíciles nuestro MLP **gana** a los dos
ensembles, a veces por un margen enorme (0,9952 frente a 0,3333); solo empatan donde el
problema ya es fácil. Es decir: **los ensembles son mejores en su día y peores fuera de él**,
que es exactamente lo contrario de lo que un NIDS necesita — un detector se despliega para
ver tráfico que no estaba en su conjunto de entrenamiento.

> Una nota sobre la cifra de 0,9367 que el documento atribuye a XGBoost en cruzado: es de un
> orden comparable a lo que aquí obtiene en los pares **fáciles**, pero muy por encima de lo
> que da en los difíciles. Sin conocer qué pares concretos promedia esa cifra, no es
> comparable directamente con nuestra tabla; se cita, no se contrasta.

> **Matiz honesto, y es el mismo del HALLAZGO 14:** buena parte de esa ventaja **no es
> representacional sino de calibración**. Los AUC de RF y XGBoost son altos justo donde su F1
> se hunde — RandomForest en 20-02 → 16-02 da **F1 0,3333 con AUC 0,9994**—. Es decir: **el
> problema de calibración entre dominios afecta a todas las familias de modelo**, no solo al
> byte-CNN. Nuestro MLP resulta estar mejor calibrado, y eso es lo que mide la tabla.

**(B) El «aprendizaje por atajos» de Engelen et al. (WTMC2021)** — si no se eliminan IPs y
puertos efímeros, el modelo memoriza la topología del laboratorio, da 99,99 % en el
laboratorio y *«fracasa por completo al generalizar en redes externas»*.

Se añadió a propósito una vista `meta+FUGA` (metadatos **+ puerto de origen efímero +
los octetos de ambas IPs**) para **medir el atajo**, no para usarlo:

| Entreno → Test | MLP | RandomForest | XGBoost |
|---|---:|---:|---:|
| 16-02 → 20-02 | 0,7756 | **1,0000** | **1,0000** |
| 20-02 → 16-02 | 1,0000 | **1,0000** | **1,0000** |
| 15-02 → 20-02 | 0,8759 | **1,0000** | **1,0000** |
| 20-02 → 15-02 | 0,9886 | **1,0000** | **1,0000** |
| 15-02 → 16-02 | 1,0000 | **1,0000** | 0,9999 |
| 16-02 → 15-02 | 0,9960 | **1,0000** | **1,0000** |

#### HALLAZGO CLAVE 18: la fuga de IPs sobrevive a la validación cruzada entre días

> **Figura:** [F40_fuga_ips](figuras/png/F40_fuga_ips.png).

Y aquí el resultado es **peor de lo que advierte Engelen**. Él dice que la fuga infla el
laboratorio y falla en redes externas. En nuestros datos la fuga da **macro-F1 = 1,0000
entre días** en cinco de los seis pares, mientras las vistas honestas se hunden a 0,33.

El mecanismo es verificable en `attack_metadata.py`: de las **18 IPs atacantes** de los seis
días, **15 empiezan por `18.`** (el rango de AWS del laboratorio), y **las 12 víctimas están
todas en `172.31.69.x`**. Un modelo que aprenda *«origen `18.x` → ataque»* transfiere
perfecto entre **cualquier** par de días del dataset.

**La consecuencia metodológica es seria:** la validación cruzada entre días —que es la que
un revisor consideraría rigurosa, y la que este mismo trabajo usó para el HALLAZGO 14— **no
protege contra el aprendizaje por atajos** si el laboratorio reutiliza sus rangos de
direcciones. Un investigador que validara entre días vería 1,0000 y concluiría que su modelo
generaliza, cuando lo único que ha aprendido es el prefijo de la IP.

Solo la validación **entre datasets distintos** rompe el atajo. Es, retrospectivamente, la
mejor justificación del trabajo con CIC-IDS2017 (HALLAZGOS 9 y 10) que el tutor reclasificó
como complementario.

> **Qué valida esto de nuestro diseño:** ninguna vista del trabajo usa IPs ni puertos como
> característica —el payload son bytes, la metadata son contadores, la ráfaga es un agregado
> temporal—, así que el pipeline es inmune a este atajo **por construcción**. No fue suerte:
> el `resp_p` se usa para *seleccionar* el subconjunto del servicio, nunca como entrada del
> clasificador.

#### Qué del estado del arte merece incorporarse

- **Nada de lo probado mejora lo que tenemos.** Los ensembles no ganan fuera de su día.
- **Lo que sí conviene adoptar son sus métricas y sus avisos:** reportar **FPR** además de
  F1 (el documento insiste: con 80-90 % de tráfico benigno, la accuracy engaña), y las
  etiquetas **«Attempted»** de Engelen para los ataques que nunca transmitieron carga —que
  es **exactamente nuestro HALLAZGO 16**, encontrado de forma independiente.
- **Lo que queda como trabajo futuro con fundamento:** Mamba/SSM sobre bytes, que es la
  familia que el documento sitúa como punta de lanza y que ataca la misma limitación que
  nuestro byte-CNN (coste y contexto largo), y las GNN para el movimiento lateral de la
  Infiltration, que es justo el ataque que nuestro pipeline no ve (HALLAZGO 16).

---

### [24 de agosto] - El componente de IA: arquitecturas, ablación e hiperparámetros

> Motivado por una pregunta directa: *«es un TFG del grado de IA, tiene que tener una parte
> importante de IA»*. La respuesta obligó a probar lo que el trabajo **no** había probado.

#### Qué es aportación de este TFG y qué viene del estado del arte

Esta separación es deliberada y se mantiene en toda la memoria. **Nada de lo que se presenta
como propio está tomado de la literatura, y nada de lo que se toma de la literatura se
presenta como propio.**

| | **Aportación de este TFG** | **Tomado del estado del arte** |
|---|---|---|
| **Arquitecturas** | `ByteCNN` (CNN 1D multi-kernel sobre bytes), `ByteLSTM`, `HybridNet` (dos ramas con **fusión tardía** de *embeddings* aprendidos) | `ByteTransformer` (autoatención, familia ET-BERT/DeBERTav2), `CrossAttentionNet` (fusión por **atención cruzada**, familia CPS-IDS), Random Forest, XGBoost |
| **Método** | La **ground-truth verificada empíricamente** sobre las capturas; el **mapa de cuatro regímenes**; la **ráfaga** y el **inter-arribo** como vistas; el protocolo de **evasión bien hecha** (HALLAZGO 17); la **generalización entre días del mismo régimen** | La validación **entre datasets**; el aviso de **fuga de IPs** (Engelen et al., WTMC2021); las **métricas de calibración** (ECE, Brier) y **Platt scaling**; las etiquetas *«Attempted»* |
| **Hallazgos** | Los 18 HALLAZGOS CLAVE del diario, incluidos los tres que **corrigen afirmaciones propias anteriores** | — |
| **Confirmaciones cruzadas** | — | El HALLAZGO 14 (descalibración) lo corrobora de forma independiente *Cross-Dataset Transformer-IDS* (2026); el HALLAZGO 16 coincide con las etiquetas *«Attempted»* de Engelen |

Dicho de otro modo: **la contribución de este trabajo es metodológica, no arquitectónica.**
Las redes propias son deliberadamente modestas; lo que se aporta es *cómo se mide*, y los
experimentos de abajo existen precisamente para comprobar si las arquitecturas del estado del
arte mejorarían el resultado. **No lo hacen.**

#### Experimento 1 — ¿Gana el Transformer al byte-CNN?

Comparados **a igualdad de datos, partición y presupuesto de parámetros** (30k-52k). Si el
modelo del estado del arte ganara solo por ser más grande, no probaría nada sobre la
arquitectura. El `ByteTransformer` va **sin preentrenar y sin tokenizador**, sobre el alfabeto
de 256 bytes.

| Día | Modelo | macro-F1 | Parámetros | Tiempo |
|---|---|---:|---:|---:|
| **22-02 Web** *(203/clase)* | byte-CNN *(este TFG)* | **0,9975** | 29.762 | **4 s** |
| | byte-LSTM *(este TFG)* | 0,8296 | 52.482 | 14 s |
| | byte-Transformer *(SOTA)* | 0,9778 | 41.922 | 144 s |
| **02-03 Bot** *(4000/clase)* | byte-CNN *(este TFG)* | **1,0000** | 29.762 | **65 s** |
| | byte-LSTM *(este TFG)* | 0,9999 | 52.482 | 313 s |
| | byte-Transformer *(SOTA)* | 1,0000 | 41.922 | **3.191 s** |

**El Transformer nunca gana.** Con pocos datos es **peor** (0,9778 frente a 0,9975); con datos
suficientes **empata**; y siempre cuesta entre **36 y 49 veces más tiempo** — 53 minutos frente
a poco más de uno en el día grande. El **coste cuadrático** de la autoatención que el documento
señala como su penalización queda aquí **medido**, no solo citado.

> **Límite honesto de este experimento:** se contrasta la **arquitectura**, no el
> **preentrenamiento**. Un ET-BERT preentrenado sobre millones de trazas es otra cosa y **no
> se ha probado**; hacerlo excede lo que cabe en un TFG con estos recursos.

#### Experimento 2 — ¿Gana la atención cruzada a nuestra fusión tardía?

| Día | Fusión | macro-F1 | AUC | Parámetros | Tiempo |
|---|---|---:|---:|---:|---:|
| 22-02 Web | **tardía** *(este TFG)* | **0,9828** | 0,9994 | 31.042 | **4 s** |
| | atención cruzada *(SOTA)* | 0,9828 | 0,9992 | 72.066 | 6 s |
| 02-03 Bot | **tardía** *(este TFG)* | **1,0000** | 1,0000 | 31.042 | **64 s** |
| | atención cruzada *(SOTA)* | 0,9999 | 1,0000 | 72.066 | 137 s |

**Empate en los dos días**, con **2,3 veces más parámetros** y el doble de tiempo. La
sofisticación de la fusión no compra nada en estos datos. Es un resultado negativo, y por eso
mismo vale: **justifica la elección arquitectónica del Eje B en vez de dejarla sin comprobar.**

#### Experimento 3 — Ablación: y una corrección a nosotros mismos

Se había escrito que `cv_local` —el coeficiente de variación de los intervalos— era *«LA
característica del beaconing»*. Eso era **interpretación, no medida**. La ablación la desmiente:

| Característica | F1 sin ella | Caída | F1 **ella sola** |
|---|---:|---:|---:|
| `media_local` | 0,9789 | **+0,0125** | 0,9638 |
| `cv_local` | 0,9835 | +0,0079 | 0,9355 |
| `frac_cerca_mediana` | 0,9887 | +0,0026 | 0,9336 |
| `dt_prev` | 0,9896 | +0,0018 | **0,9669** |
| `dt_next` | 0,9900 | +0,0014 | 0,9641 |
| **`regularidad`** | **0,9949** | **−0,0035** | 0,9062 |

**Falsa por partida doble.** En *leave-one-out* la más importante es **`media_local`**, no
`cv_local`; y por sí sola la mejor es **`dt_prev`**, un intervalo crudo. Además **`regularidad`
estorba**: quitarla **mejora** el resultado y en solitario es la peor. Debería eliminarse.

Y un segundo hallazgo, sobre los grupos: **ráfaga e inter-arribo no son aditivos.**

| Vista | macro-F1 |
|---|---:|
| metadatos | 0,9985 |
| metadatos + ráfaga | **0,9991** |
| metadatos + inter-arribo | 0,9989 |
| metadatos + ráfaga + inter-arribo | 0,9989 |
| inter-arribo solo (6 caract.) | 0,9914 |
| ráfaga sola (3 caract.) | 0,9909 |

Juntarlas da **menos** que la ráfaga sola sobre metadatos: **miden lo mismo por dos vías**. Eso
matiza el HALLAZGO 17 — el inter-arribo es una vista *alternativa* y compacta, no *adicional*.

#### Experimento 4 — Búsqueda de hiperparámetros

Hasta esta fecha **todos** los modelos del trabajo usaban valores fijos elegidos a mano, sin
una sola búsqueda. Es una carencia obvia en un TFG de IA. Se corrige con `RandomizedSearchCV`
(30 combinaciones), y —esto es importante— **solo con validación cruzada dentro del día de
entrenamiento**: si se ajustara mirando el día de test, la comparación quedaría contaminada,
que es justo el error que este trabajo denuncia en otros sitios.

| Día, vista metadatos | Modelo | Por defecto | Mejor | Ganancia | Coste de ajustar |
|---|---|---:|---:|---:|---:|
| 22-02 Web | MLP *(nuestro)* | 0,9107 | **0,9383** | +0,0275 | 37 s |
| | XGBoost *(SOTA)* | 0,9556 | **0,9679** | +0,0122 | 46 s |
| 15-02 DoS | MLP *(nuestro)* | 0,9556 | **0,9619** | +0,0063 | **2.624 s** |
| | XGBoost *(SOTA)* | 0,9814 | **0,9819** | +0,0005 | **38 s** |

Tres conclusiones:

- **La carencia era real:** ambos modelos dejaban rendimiento sin recoger, hasta +0,0275.
- **Pero no explica la ventaja del ensemble**, y en ninguno de los dos días: la brecha baja de
  0,0449 a 0,0296 en el 22-02 y de 0,0258 a 0,0200 en el 15-02, y **persiste siempre**. Era
  una diferencia entre modelos, no entre ajustes.
- **La ganancia depende mucho del día** (+0,0275 frente a +0,0063), y en el 15-02 la mejor
  configuración del MLP resultó ser **(256,128), exactamente el valor por defecto** del
  trabajo: solo mejoraba la tasa de aprendizaje.

> **Asimetría práctica que conviene citar:** ajustar el MLP costó **2.624 s** frente a los
> **38 s** de XGBoost en el mismo día — **69 veces más**. En un despliegue real, donde hay que
> reajustar por dominio (y el HALLAZGO 14 dice que hay que hacerlo), eso pesa tanto como la
> exactitud.

#### Lectura de conjunto para la memoria

Los cuatro experimentos apuntan en la misma dirección, y conviene decirlo sin adornos:
**ninguna de las arquitecturas avanzadas del estado del arte mejora los resultados de este
trabajo en estos datos**, y dos de ellas cuestan entre 2 y 49 veces más. Eso **no** es un
argumento contra el estado del arte —sus modelos están pensados para escalas y escenarios
mayores—, sino la constatación de que **en este problema el cuello de botella no está en la
capacidad del modelo, sino en la calidad del dato y en cómo se mide**: la ground-truth, la
contaminación del benigno, la fuga de IPs, la calibración entre dominios y la evasión. Que es
exactamente donde este TFG ha trabajado.

---

### [24 de agosto] - Redactando el capítulo 4 aparece un fallo de métrica en lo que se citaba

Al escribir las secciones 4.1 y 4.2 de la memoria (`DIF_Dissertation_2026/chapters/04_regimenes.tex`)
hubo que contrastar cada cifra contra este README, y el contraste destapó **dos problemas que no
eran de redacción sino de los datos que se venían citando**.

**Problema 1 — lo que llamábamos macro-F1 del "caso difícil" es exactitud en validación cruzada.**
Las cifras `0.9908 / 0.9793 / 1.0000` de `CASO_DIFICIL_SSH` salen de `honest_by_service_rich.py`,
que llama a `cross_val_score(..., scoring="accuracy")`. No son macro-F1. Y el otro diccionario,
`CASO_DIFICIL_SSH_F1`, es el F1 de la clase ataque sobre **un único test held-out**, donde las tres
vistas saturan a `1.0000` y el ranking entre ellas desaparece. El problema no es cosmético: el
capítulo dedica una sección a explicar **por qué la exactitud engaña** con clases desbalanceadas,
y acto seguido iba a citar exactitud presentándola como macro-F1.

**Problema 2 — el escenario "contaminado" ya no es reproducible.** La corrección del límite de
ventana (HALLAZGO 14) no filtró los 1.589 flujos del atacante en tiempo de evaluación: los
**reetiquetó como ataque en el propio `.npz`**. Hoy `Benign & IP_atacante` bajo el servicio SSH es
el conjunto vacío, así que las cifras del escenario contaminado son **históricas** (etiquetado
anterior) y no pueden ponerse en la misma tabla que las actuales sin mentir por omisión.

**Qué se ha hecho.** Script nuevo [ic_caso_dificil.py](scripts/zeek/ic_caso_dificil.py): macro-F1 y
recall de la clase ataque **out-of-fold**, con **IC 95% por bootstrap de 2.000 remuestreos** sobre
las predicciones out-of-fold. Detecta además si el escenario contaminado es reproducible y lo hace
constar en el resumen en vez de imprimir dos tablas idénticas. Resultado sobre
`Wednesday-14-02-2018`, servicio `ssh` por DPI (358 benignos genuinos, balanceo 1:1 → 716 flujos):

| Vista | Macro-F1 [IC 95%] | Recall ataque |
|---|---|---|
| payload (histograma + entropía) | 0.9818 [0.9707, 0.9916] | 1.0000 |
| metadatos de flujo | 0.9902 [0.9818, 0.9972] | 1.0000 |
| **conducta (metadatos + ráfaga)** | **0.9986** [0.9958, 1.0000] | 1.0000 |

**Y el resultado cambia la lectura en dos puntos.** Primero: **el recall es 1.0000 en las tres
vistas**, así que toda la diferencia se juega en los falsos positivos sobre los 358 benignos, no en
ataques que se escapen. Segundo, y esto no se esperaba: **los metadatos de flujo (0.9902) superan al
payload (0.9818)**, invirtiendo el orden que sugerían las cifras de exactitud. La ventaja es
pequeña y los IC se solapan, así que no se sostiene con fuerza; pero desmiente la lectura intuitiva
de que en régimen cifrado el contenido degradado siga siendo la fuente principal. Lo que sí queda
firme es que **la conducta gana con IC que no se solapa con el del payload** — la tesis del
HALLAZGO 3 se mantiene, ahora con la métrica correcta y con intervalo.

Añadido `CASO_DIFICIL_SSH_IC` a [resultados.py](scripts/figuras/resultados.py), con un comentario
que marca los dos diccionarios antiguos como **exactitud CV / test held-out** para que nadie los
vuelva a citar como macro-F1.

**Las figuras no tenían el fallo, pero sí quedan incoherentes con la memoria.** Comprobado: F14
([fig_metodologia.py](scripts/figuras/fig_metodologia.py)) y F19
([fig_regimenes.py](scripts/figuras/fig_regimenes.py)) rotulan su eje como `accuracy (5-Fold CV)`,
que es exactamente lo que grafican — el error era de quien las iba a citar, no de ellas. Pero la
memoria declara macro-F1 como métrica, así que quedan dos cosas por resolver:

- **F19** (la inversión SSH↔web) debe regenerarse con **macro-F1 + IC**, para que la figura que
  sostiene el HALLAZGO 4 use la misma métrica que el texto. Depende de tener antes el macro-F1 del
  día web (ver el párrafo anterior).
- **F14** (contaminado vs genuino) **no puede regenerarse**: el escenario contaminado ya no existe
  en el `.npz`. Se queda con exactitud y hay que rotularla explícitamente como **comparación
  histórica, con el etiquetado anterior a la corrección de la ventana**, o retirarla de la memoria y
  contar el episodio solo con las cifras de composición (1.589 del atacante frente a 433 de
  terceros), que es lo que hace ahora mismo la sección 4.1.

**Consecuencia para el resto de la memoria:** las cifras del HALLAZGO 4 (día web, `0,9877` payload y
`0,9286` metadatos) **también son exactitud CV**. Antes de escribir la sección 4.3 hay que relanzar
`ic_caso_dificil.py` sobre `Thursday-22-02-2018 --service http`. Con 203 flujos de ataque el IC va a
salir ancho, y eso hay que decirlo en el texto en vez de esconderlo.

**Otras dos correcciones de redacción**, menores pero del mismo tipo: había escrito que el
FTP-BruteForce no deja payload porque "el protocolo rechaza las credenciales antes de transferir
contenido" (falso: el servicio FTP estaba **caído**, es un accidente de esta captura y no una
propiedad de FTP), y había dado las 162.801 conexiones del atacante como si todas fueran `REJ`
(son 162.801 en total, de las que **134.945** están en `REJ`).

**Convenio de tablas fijado** para toda la memoria, documentado en la cabecera de
`04_regimenes.tex`: flotante `table` con `\caption` arriba, `\label{tab:<slug>}` después del
caption y `booktabs`; nunca bloques `center` sueltos, que no se numeran ni entran en el índice de
tablas. Presupuesto de páginas rebalanceado (cap. 1: 6→5, cap. 4: 13→15, cap. 6: 7→6; total 60).

### [24 de agosto] - HALLAZGO 19: la evaluación intra-día está saturada, y eso reordena el capítulo 4

Todo esto sale de intentar escribir la sección 4.3 de la memoria. Al reformular el HALLAZGO 4 hizo
falta medir la vista conductual en el día web —que nunca se había medido— y, ya puestos, medir **las
tres vistas con la misma métrica y el mismo protocolo en los seis días**. El resultado obliga a
reordenar el argumento del capítulo 4.

#### El defecto que lo destapó: F19 comparaba peras con manzanas

La figura que sostenía la inversión SSH↔web tenía dos barras rotuladas igual, `Metadatos (conducta)`,
que **no contenían las mismas características**: el lado SSH usaba `meta-rica` (con ráfaga, 1,000) y
el lado web `build_meta_features` (sin ráfaga, 0,9286). La caída que hacía espectacular la inversión
era, en buena parte, la diferencia entre dos conjuntos de características.

#### La medición uniforme

Macro-F1 **out-of-fold** (5-Fold), benigno genuino de terceros, balanceo 1:1 con tope de 5.000 por
clase, media de 10 submuestreos, IC 95% agrupando 2.000 remuestreos de bootstrap. Script:
[ic_caso_dificil.py](scripts/zeek/ic_caso_dificil.py).

| Día / régimen | Payload | Metadatos | Conducta |
|---|---|---|---|
| 14-02 SSH — cifrado | 0,9842 | 0,9906 | **0,9985** |
| 22-02 Web — en claro | 0,9734 | 0,9186 | **0,9823** |
| 16-02 Hulk — volumétrico | **1,0000** | 0,9715 | 0,9999 |
| 15-02 GoldenEye+Slowloris | **0,9998** | 0,9621 | 0,9967 |
| 20-02 LOIC — DDoS diluido | **1,0000** | 0,9987 | 0,9984 |
| 02-03 Bot — periodicidad | **0,9990** | 0,9981 | 0,9983 |

#### HALLAZGO CLAVE 19: dentro del día no se distingue nada, y la causa es el atajo del dataset

**«Ninguna vista gana en los cuatro regímenes» es falso tal y como estaba medido.** El payload no
baja de 0,973 en ningún día y es el mejor o empata en cuatro de los seis; la conducta no baja de
0,982. Tres de las cuatro filas del antiguo `REGIMENES` afirmaban un ganador que la medición
uniforme desmiente: decía `meta + ráfaga` en el volumétrico (mide payload 1,0000 frente a conducta
0,9999) y «ninguna vista mide la firma» en el día del Bot (miden las tres 0,998).

**La evaluación intra-día no discrimina entre vistas**, y un 0,99 ahí no significa que el problema
esté resuelto: significa que la pregunta está mal planteada.

> **Sobre la causa, ojo:** la primera explicación que se propuso aquí fue que cada día tiene un solo
> host atacante y que cualquier vista memorizaría ese host (el atajo de Engelen, WTMC 2021). **Esa
> hipótesis se contrastó y resultó FALSA** — ver el HALLAZGO 20, más abajo. El mecanismo que queda
> en pie es la **herramienta**, no la identidad del host.

Encaja además con algo que ya estaba en este diario y que entonces no se supo leer: **ninguna
arquitectura del estado del arte mejoraba los resultados**. No los mejoraba porque dentro del día no
quedaba nada que mejorar.

#### Dónde SÍ se discrimina

En la robustez, que es justo el material del capítulo 5. El recall del payload al camuflar los
primeros bytes: Bot **1,0000 → 0,0025**, LOIC **1,0000 → 0,0108**, Hulk **1,0000 → 0,0417**, SSH
**1,0000 → 0,3538**. La conducta es **invariante** en todos (no mira un solo byte). Y el día web es
la excepción que confirma la regla: con un prefijo de 24 bytes, que no toca la inyección, el payload
aguanta en **0,8852**, porque ahí su firma es contenido genuino y no huella de herramienta.

A eso se suman la transferencia entre días y datasets, la calibración, y la **ceguera** del payload
en el FTP del 14-02 y en Infiltration, que no es una métrica peor sino la ausencia de datos que
analizar.

#### Qué se ha cambiado

- **`REGIMENES`** conserva las cuatro filas como marco **descriptivo** (dónde vive la firma de cada
  ataque, que es un hecho sobre el ataque) y **pierde la columna «vista ganadora»**, que era una
  afirmación sobre la medición y es la que no se sostiene.
- **`SATURACION_INTRADIA`**, `SATURACION_RECALL` y `SATURACION_CONTEXTO` nuevos en
  [resultados.py](scripts/figuras/resultados.py).
- **F16 reescrita.** Era «Ninguna vista gana en los cuatro regímenes» y mezclaba exactitud CV con
  macro-F1 de fuentes distintas (lo decía su propia nota al pie). Ahora es «Dentro del día no se
  distingue nada: todo satura»: una rejilla uniformemente alta, y bajo cada celda lo único que
  distingue unas de otras —cuánto queda tras la evasión.
- **F19 reescrita** con las tres vistas, misma métrica en ambos lados y barras de error: la única
  inversión real es el desplome de los metadatos per-flujo (−7,2 puntos, IC sin solapar).
- **F14 retirada de la memoria** (decisión del autor). Su escenario contaminado ya no es
  reproducible: la corrección del límite de ventana reetiquetó esos 1.589 flujos en el propio
  `.npz`. La función se conserva documentada como excluida.
- **`ic_caso_dificil.py`** generalizado: deduce las etiquetas de ataque de los datos, toma las IPs
  atacantes de `attack_metadata`, promedia sobre 10 submuestreos y materializa **solo las filas que
  evalúa** (3.884 de 2,2 M en el día SSH), lo que permite correr los días de millones de flujos sin
  agotar la RAM.

#### HALLAZGO CLAVE 20: el atajo NO es la identidad del host

El mecanismo que el HALLAZGO 19 daba por bueno era contrastable, y había que contrastarlo. El DDoS
del 20-02 es el **único día con más de un atacante**: tiene **diez hosts** con ~29.000 flujos cada
uno. Si el éxito intra-día se debiera a memorizar el host, evaluar sobre un atacante **nunca visto**
debería hundirlo.

Script: [loao_eval.py](scripts/zeek/loao_eval.py). Cada pliegue aparta un host atacante entero **y**
un grupo disjunto de hosts benignos; se entrena con 5.000 flujos por clase y se evalúa sobre 2.000.
**Control negativo:** partición aleatoria de idéntico tamaño, porque una caída podría deberse al
tamaño del entrenamiento. **Control positivo:** una cuarta vista tramposa —los cuatro octetos de la
IP de origen— que no puede sino memorizar el host, y que debe desplomarse si el test es sensible.

| Vista | Control aleatorio | Atacante no visto | Diferencia |
|---|---|---|---|
| payload (histograma + entropía) | 1,0000 ± 0,0000 | 1,0000 ± 0,0000 | +0,0000 |
| metadatos de flujo | 0,9991 ± 0,0005 | 0,9992 ± 0,0006 | +0,0001 |
| conducta (metadatos + ráfaga) | 0,9986 ± 0,0006 | 0,9990 ± 0,0007 | +0,0004 |
| *[control] octetos de la IP* | 0,9999 ± 0,0001 | 0,9332 ± 0,2000 | −0,0667 |

**La hipótesis era falsa.** Apartar un host atacante entero **no degrada ninguna** de las tres
vistas. Lo que aprenden no es la identidad del host.

**Y el control positivo dice algo que su media esconde.** Cae a 0,9332 pero con desviación 0,2000:
el efecto está concentrado en **un solo pliegue**. Nueve de los diez atacantes están en el rango
`18.2xx.x.x` y el benigno en `172.31.x.x`, así que apartar uno deja otros nueve del mismo rango y
**el primer octeto sigue separando** — es la fuga del HALLAZGO 18, medida aquí a nivel de **subred**
y no de host. El pliegue decisivo es `52.14.136.135`, la única atacante fuera de ese rango: ahí el
control se hunde a **0,3333** y las tres vistas reales siguen dando **1,0000 / 0,9987 / 0,9990**.
En el único pliegue donde se demuestra que un atajo por identidad de host **falla**, las vistas
reales aguantan intactas.

**Qué explica entonces la saturación: la HERRAMIENTA.** Los diez atacantes ejecutan el mismo
programa, y cada ataque de cada día está generado por una única herramienta. Lo confirma la evasión
sobre ese mismo día: camuflar los primeros bytes hunde el payload de 1,0000 a **0,0108**. Los dos
experimentos se complementan con precisión: **el leave-one-attacker-out dice que no es el host; la
evasión dice que es la herramienta.**

**Efecto secundario, y es una buena noticia:** queda **desmentida con datos** la reserva sobre la
vista conductual. Se temía que la ráfaga, al contar conexiones por origen, funcionase como un
identificador de host disfrazado. Medida contra un atacante que nunca vio, rinde igual que contra
atacantes conocidos (0,9990 frente a 0,9986).

**Límites del test, explícitos:** solo es aplicable en uno de los seis días, así que en los otros
cinco la hipótesis del host sigue sin contrastar; y como los diez atacantes comparten herramienta,
distingue «memoriza el host» de «aprende la herramienta o la conducta», pero no «aprende la
herramienta» de «aprende el ataque».

#### Lo que queda por hacer

1. Revisar los esqueletos de los capítulos 2 y 5, que aún aluden al marco antiguo.
2. Redactar el capítulo 5, que es donde vive toda la discriminación del trabajo.

**Nota de reproducibilidad:** el punto estimado se mueve en la tercera cifra decimal según detalles
arbitrarios de implementación (el nombre de la clase positiva cambia el orden del `LabelEncoder` y
con él las particiones de `StratifiedKFold`). El IC del bootstrap (~±0,01) lo cubre. **No citar
puntos estimados a cuatro decimales como si fueran exactos.**

---

## Descarga del Dataset CIC-IDS-2018

Los PCAPs y CSVs del CSE-CIC-IDS2018 están disponibles en el bucket público de AWS S3 del proyecto. Para los PCAPs (y para sincronizar días completos) se recomienda usar la sincronización oficial (`aws s3 sync --no-sign-request`).

Si lo que necesitas son los CSVs (flujos ya procesados), a veces es más rápido descargar solo el CSV del día concreto con `curl` (si la URL directa del CSV está disponible). Ejemplo práctico para el CSV y el PCAP del 16-02-2018:

```cmd
# Descargar solo el CSV del 16-02-2018 (si existe URL directa pública)
curl -L -o "./data/raw/16-02-2018.csv" "https://cicids2018.s3.amazonaws.com/Friday-16-02-2018/Friday-16-02-2018.csv"

# Descargar el PCAP (recomendado: usar aws s3 sync para garantizar consistencia)
aws s3 sync --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/" "./data/raw/" --exclude "*" --include "*16-02-2018*"
```

Si quieres comprobar primero qué carpetas o ficheros hay disponibles en el bucket público:

```cmd
aws s3 ls --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/"
```

Notas:
- Usar `curl` en CSVs funciona cuando el objeto es público y la URL es correcta; cuando la URL devuelve XML de error o 404 (como te pasó), usa `aws s3 sync --no-sign-request` para descargar desde el bucket oficial.
- Si no tienes `aws` instalado: instala AWS CLI o usa `curl` únicamente para CSVs conocidos.

### Arranque de Zeek para Wednesday 14

La extracción de payload de la Fase 2 se apoya en el contenedor oficial
`zeek/zeek` (ver `docker_zeek.pdf`, secciones 2.3-2.4) y un script personalizado
basado en el evento `tcp_packet`. El flujo queda preparado en:

- Script Zeek: [scripts/zeek/extract_payload.zeek](scripts/zeek/extract_payload.zeek) — por cada paquete TCP con datos escribe una fila TSV (`uid`, `ts`, 5-tupla, `dir`, `len`, `payload_hex`) usando el Log framework de Zeek. El `uid` (identificador de conexión de Zeek) permite agrupar paquetes por flujo de forma exacta aunque se reutilicen los puertos de origen.
- Orquestador: [scripts/zeek/run_zeek_payload.py](scripts/zeek/run_zeek_payload.py) — recorre los PCAP del día, lanza Zeek en Docker por captura y deja la salida en `data/processed/zeek/<dia>/`.
- Saneado de PCAPs: [scripts/zeek/repair_pcap.py](scripts/zeek/repair_pcap.py) — reescribe una captura conservando solo records válidos (lo usa el orquestador antes de cada Zeek; ver nota abajo).
- Lectura/decodificación: [scripts/zeek/decode_payload.py](scripts/zeek/decode_payload.py) — vuelca el payload en texto legible o hexdump para inspección.
- Localizar una IP en las capturas: [scripts/zeek/find_host.py](scripts/zeek/find_host.py) — barrido binario rápido para saber en qué capturas aparece una IP (útil para encontrar la captura de un ataque sin procesar los 46 GB).
- Identificar al atacante **sin IP previa**: [scripts/zeek/find_attacker.py](scripts/zeek/find_attacker.py) — ejecuta Zeek (`conn.log`) sobre una captura y lista los **top-talkers** por nº de conexiones (total y hacia un puerto), con rango temporal UTC, `conn_state` y bytes. En ataques volumétricos (DoS/DDoS) el atacante domina el ranking y se identifica sin conocer su IP (complemento de `find_host.py`; ver diario del 15 de julio).
- Etiquetas (ground-truth): [scripts/zeek/attack_metadata.py](scripts/zeek/attack_metadata.py) — IPs atacante/víctima, puertos y ventanas por día.
- Constructor del dataset: [scripts/zeek/build_dataset.py](scripts/zeek/build_dataset.py) — vectoriza los TSV (histograma de bytes + entropía + secuencia) y etiqueta cada flujo (ver sección *Pipeline de Fase 2* más abajo).
- Re-etiquetado rápido: [scripts/zeek/relabel_dataset.py](scripts/zeek/relabel_dataset.py) — re-aplica las etiquetas al `dataset_*.npz`/`_meta.csv` existentes usando la 5-tupla y el `ts` ya guardados, **sin re-leer los 67 GB de TSV**. Útil al corregir la ground-truth en `attack_metadata.py` (con copia `.bak` y diff de distribución).
- Entrenador del modelo: [scripts/zeek/train_phase2.py](scripts/zeek/train_phase2.py) — balancea las clases, entrena dos MLP (histograma+entropía y secuencial), evalúa con CV + test held-out y guarda modelos/resultados en `models/`.
- Prueba honesta: [scripts/zeek/honest_check.py](scripts/zeek/honest_check.py) — audita el modelo sobre el tráfico benigno del MISMO servicio cifrado (SSH benigno vs SSH-ataque) para detectar si aprende el protocolo en vez del ataque (ver HALLAZGO CLAVE 3).
- Comparador de vistas (ventaja híbrida): [scripts/zeek/hybrid_compare.py](scripts/zeek/hybrid_compare.py) — entrena y compara payload vs metadatos vs híbrido con balanceo global + auditoría honesta por vista (paso 1, ver entrada del 16 de junio). Resumen en [models/phase2_hybrid_compare.md](models/phase2_hybrid_compare.md).
- Evaluación honesta por servicio: [scripts/zeek/honest_by_service.py](scripts/zeek/honest_by_service.py) — balancea 1:1 SSH-ataque vs SSH-benigno y mide la métrica realista de cada vista sobre el caso difícil (paso 2). Resumen en [models/phase2_by_service.md](models/phase2_by_service.md).
- Evaluación por servicio enriquecida: [scripts/zeek/honest_by_service_rich.py](scripts/zeek/honest_by_service_rich.py) — añade la feature de **ráfaga** (conexiones del mismo origen por ventana) y separa el benigno **limpio** (terceros) del contaminado (atacante fuera de ventana); demuestra que el techo de 0.61 del paso 2 era contaminación, no un límite de la metadata (paso 1 refinado, 17 de junio). Resumen en [models/phase2_by_service_rich.md](models/phase2_by_service_rich.md).
- Evaluación por servicio (día web): [scripts/zeek/honest_by_service_web.py](scripts/zeek/honest_by_service_web.py) — espejo del SSH sobre HTTP:80 (Web-Attack vs HTTP-benigno 1:1); en payload en claro el payload gana (ver HALLAZGO CLAVE 4, 7 de julio). Resumen en [models/phase2_by_service_web.md](models/phase2_by_service_web.md).
- Clasificación multi-tipo (día web): [scripts/zeek/multitype_web.py](scripts/zeek/multitype_web.py) — distingue el **tipo** de ataque web (BF/XSS/SQLi) con predicciones out-of-fold; solo la secuencia de bytes lo consigue (ver diario del 8 de julio). Resumen en [models/phase2_multitype_web.md](models/phase2_multitype_web.md).
- **Fase 3 — Deep learning:** [scripts/zeek/dl_models.py](scripts/zeek/dl_models.py) (modelos PyTorch `ByteCNN`/`ByteLSTM` + utilidades), [scripts/zeek/train_dl_payload.py](scripts/zeek/train_dl_payload.py) (Eje A: CNN/LSTM vs baselines, `--task binary|multitype`, `--cap` para días masivos), [scripts/zeek/train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py) (Eje B: híbrido de dos ramas con fusión tardía) y [scripts/zeek/eval_saliency.py](scripts/zeek/eval_saliency.py) (Eje D: interpretabilidad/saliency del banner SSH). Resúmenes `models/phase2_dl_*.md`, `models/phase2_dlhybrid_*.md`, `models/phase2_saliency_ssh.md`.
- Firma volumétrica del DoS (Eje C): [scripts/zeek/dos_burst.py](scripts/zeek/dos_burst.py) — compara payload vs meta-básica vs **meta+ráfaga** (volumen agregado por origen) sobre el DoS-Hulk; demuestra que la firma del flood es el **agregado**, no el flujo aislado (ver HALLAZGO CLAVE 8, diario del 15 de julio). Resumen en [models/phase2_dos_burst_Friday-16-02-2018.md](models/phase2_dos_burst_Friday-16-02-2018.md).
- Salida generada: `data/processed/zeek/wednesday-14-02-2018/<pcap>.payload.tsv`

**Requisitos:** Docker en marcha y la imagen descargada (`docker pull zeek/zeek`).

```cmd
:: Prueba rápida: las 3 capturas más pequeñas del miércoles
python scripts\zeek\run_zeek_payload.py --limit 3 --smallest

:: Una captura concreta
python scripts\zeek\run_zeek_payload.py --only UCAP172.31.69.18

:: Todas las capturas del día (46 GB, puede tardar mucho)
python scripts\zeek\run_zeek_payload.py

:: Leer los payloads en claro (p.ej. HTTP) de una captura ya procesada
python scripts\zeek\decode_payload.py data\processed\zeek\wednesday-14-02-2018\<pcap>.payload.tsv --port 80 -n 10
```

Cada TSV es un log estándar de Zeek (cabecera `#fields`/`#types` + filas separadas
por tabuladores), cargable con `pandas.read_csv(sep="\t", comment="#", names=[...])`.

**Saneado obligatorio de capturas (corrección importante del 7 de mayo):** las
capturas de CSE-CIC-IDS2018 contienen records que rompen la lectura. Inicialmente
se creyó que Zeek solo se cortaba en el último record (sin pérdida), pero **es
falso**: en `UCAP172.31.69.25` Zeek se detenía a las **18:05 UTC** por un record
intermedio que libpcap rechaza, perdiendo **toda la tarde en silencio** — solo
129.546 paquetes extraídos frente a **2.924.653 reales**, y con ello **toda la
ventana del SSH-Bruteforce**. Por eso `run_zeek_payload.py` ahora **sanea siempre**
cada captura con `repair_pcap.py` (reescribe una copia solo con records válidos) y
ejecuta Zeek sobre esa copia, que se procesa entera (exit 0). El saneado no altera
la parte válida del archivo; solo descarta el record ilegible final.

---

## Pipeline de Fase 2: Vectorización y Etiquetado del Payload

> Esta sección documenta de forma autocontenida el estado del análisis de payload
> para que cualquier persona (o agente) pueda continuar el trabajo sin contexto
> previo. **Días incorporados: miércoles 14-02-2018** (Brute Force FTP/SSH,
> payload cifrado), **jueves 22-02-2018** (Web Attacks, payload en claro; ver el
> diario del 7 de julio) y **viernes 16-02-2018** (DoS-Hulk, firma volumétrica; ver el
> diario del 15 de julio). Se incorporan de uno en uno, ya que cada día ocupa >30 GB
> de PCAP; tras vectorizar un día a `.npz`+`_meta.csv` (~1 GB, autocontenido) se
> pueden borrar su PCAP crudo y sus TSV para liberar disco (son re-derivables).

### Flujo completo (de PCAP a dataset etiquetado)

```text
PCAP  --extract_payload.zeek (Docker)-->  <pcap>.payload.tsv  (payload por paquete)
       --build_dataset.py-->  dataset_<dia>.npz + dataset_<dia>_meta.csv  (flujos vectorizados + etiqueta)
                                  ^
                                  |__ attack_metadata.py (ground-truth de etiquetas)
```

1. **Extraer payload** (una o varias capturas):
   ```cmd
   python scripts\zeek\run_zeek_payload.py --only UCAP172.31.69.25
   ```
2. **Construir el dataset** (lee todos los `*.payload.tsv` del día):
   ```cmd
   conda run -n tfg_ia python scripts\zeek\build_dataset.py
   ```

### El problema del etiquetado: el CSV no tiene IPs

Los CSV de CICFlowMeter (`data/raw/14-02-2018.csv`) **no contienen las IPs** de
origen/destino: solo `Dst Port`, `Protocol`, `Timestamp`, estadísticos de flujo y
`Label`. Por tanto **no se puede hacer un join exacto por 5-tupla** entre los
payloads (que sí tienen IPs) y las etiquetas del CSV. La solución estándar es
etiquetar por la **ground-truth documentada del ataque** (IP atacante, IP víctima,
puerto y ventana temporal), codificada en [scripts/zeek/attack_metadata.py](scripts/zeek/attack_metadata.py).

### Zona horaria (crítico para las ventanas temporales)

- Los timestamps de los **PCAP/TSV están en EPOCH UTC**.
- Los timestamps del **CSV y de la documentación oficial están en hora local
  UTC-4**. Verificado: el CSV del 14-02 empieza a las `08:31:01` y el primer
  paquete del PCAP cae a las `12:30 UTC` (12:30 − 4 h = 08:30 local).
- `attack_metadata.py` guarda las ventanas en hora local y las convierte a UTC con
  `tz_offset_hours = -4`.

### Ground-truth verificada del 14-02-2018 (Brute Force)

| Ataque | Atacante | Víctima | Puerto | Ventana (local) | Estado |
|--------|----------|---------|--------|-----------------|--------|
| FTP-BruteForce | `18.221.219.4` | `172.31.69.25` | 21 | 10:32–12:09 | **verificado** |
| SSH-Bruteforce | `13.58.98.64` | `172.31.69.25` | 22 | 14:01–15:33 | **verificado** |

> **Corrección 17-jun:** el fin de la ventana del SSH se amplió de 15:31 a **15:33
> local** (19:33 UTC). El ataque seguía 90 s tras el fin documentado (rango real
> verificado 18:01:50–19:32:30 UTC, ráfaga continua sin huecos), y esos 1.589 flujos
> de cola contaminaban el "SSH benigno". Ver la entrada del 17 de junio.

> **Ojo: el atacante del SSH es una IP DISTINTA de la del FTP** (`13.58.98.64` vs
> `18.221.219.4`; ambas son hosts atacantes en AWS us-east-2). La víctima es la
> misma (`172.31.69.25`). La del SSH se descubrió empíricamente (no estaba en la
> documentación que asumía un único atacante).

Etiquetas en el CSV del día: `Benign` (667.626), `FTP-BruteForce` (193.360),
`SSH-Bruteforce` (187.589). Verificación con `conn.log` sobre `UCAP172.31.69.25`:
162.801 conexiones `18.221.219.4 → 172.31.69.25:21` (FTP) y 94.207 flujos
`13.58.98.64 → 172.31.69.25:22` (SSH, 18:01–19:32 UTC) tras sanear la captura.

### Ground-truth verificada del 22-02-2018 (Web Attacks — payload en claro)

| Ataque | Atacante | Víctima | Puerto | Ventana (local) | Estado |
|--------|----------|---------|--------|-----------------|--------|
| Brute Force -Web | `18.218.115.60` | `172.31.69.28` | 80 | 10:13–11:24 | **verificado** |
| Brute Force -XSS | `18.218.115.60` | `172.31.69.28` | 80 | 13:50–14:29 | **verificado** |
| SQL Injection | `18.218.115.60` | `172.31.69.28` | 80 | 16:10–16:28 | **verificado** |

> Verificado el 7-jul con [find_host.py](scripts/zeek/find_host.py) + Zeek: el
> atacante `18.218.115.60` aparece en una única captura (`UCAP172.31.69.28`) y **todo
> su tráfico va a `172.31.69.28:80`** (app vulnerable **DVWA**, HTTP en claro). Los 3
> sub-ataques forman clústeres temporales disjuntos (con huecos entre ellos) que casan
> con las ventanas documentadas y con las firmas de bytes (login POST / `<script>` /
> `union select`). Un mismo par {atacante, víctima}:80 con ventanas disjuntas: cada
> flujo cae en su sub-ataque por su `ts`. Etiquetas en el CSV (parcial, solo mañana):
> `Brute Force -Web` (249), `Brute Force -XSS` (79), `SQL Injection` (34), resto `Benign`.
>
> **Contraste con el 14-02:** el SSH es payload **cifrado** (bytes = azar, firma en la
> conducta/ráfaga); el web es payload **en claro** (el ataque está en los bytes). Es la
> otra mitad del argumento híbrido. *(Matiz del 24-ago, HALLAZGO 19: el contraste > entre ambos regímenes es real y se comprueba inspeccionando los bytes, pero **no** > se traduce en que cada vista gane en el suyo — medidas igual, dentro del día todas > saturan.)*

### Ground-truth verificada del 15-02-2018 (DoS — dos herramientas, perfiles opuestos)

| Ataque | Atacante | Víctima | Puerto | Ventana (local) | Estado |
|--------|----------|---------|--------|-----------------|--------|
| DoS-GoldenEye | `18.219.211.138` | `172.31.69.25` | 80 | 09:27–10:12 | **verificado** |
| DoS-Slowloris | `18.217.165.70` | `172.31.69.25` | 80 | 11:00–11:42 | **verificado** |

> Verificado el 21-ago con [find_attacker.py](scripts/zeek/find_attacker.py) sobre
> `UCAP172.31.69.25` (38.536 conexiones). Los dos atacantes copan el ranking sin IP previa
> (29.696 y 7.248 conexiones frente a 131 del tercero) y hablan **exclusivamente** con la
> víctima por el `:80`, así que las ventanas anchas no pueden mal-etiquetar nada.
>
> **Perfiles conductuales opuestos dentro del mismo régimen:** GoldenEye va **a oleadas**
> (huecos de hasta 8,8 min entre ráfagas, picos de 9.018 conexiones en 5 min, `conn_state`
> RSTO dominante); Slowloris es **continuo** (hueco máximo 9,8 s) con un **goteo plano** de
> ~800-850 conexiones cada 5 min y `conn_state` RSTR + S0 — mantiene conexiones abiertas.
> Que ambos sean «DoS volumétrico» y se comporten así de distinto es un aviso de que el
> régimen **no es una categoría homogénea**.
>
> **OJO — reutilización de infraestructura:** `18.219.211.138` es **la misma IP que el C2 de
> la botnet del 02-03**. Segundo caso tras `18.218.115.60` (web 22-02 y DDoS 20-02). No
> contamina nuestras vistas (la IP no es una *feature*), pero invalidaría cualquier
> experimento que incluyera identificadores de red.

### Ground-truth verificada del 16-02-2018 (DoS — firma volumétrica)

| Ataque | Atacante | Víctima | Puerto | Ventana (local) | Estado |
|--------|----------|---------|--------|-----------------|--------|
| DoS-Hulk | `18.219.193.20` | `172.31.69.25` | 80 | 13:45–**13:59** *(corregida 11-ago)* | **verificado** |
| DoS-SlowHTTPTest | `13.59.126.31` | `172.31.69.25` | 21 | 10:12–11:06 | **verificado** |

> **Corrección del 11 de agosto (mismo error de límite de ventana que el SSH el 17-jun):**
> el fin de ventana original (13:53) se fijó con el `conn.log` de **una sola captura**
> (`UCAP...-part1`). Sobre el dataset **completo**, el flood del atacante es **continuo**
> hasta las **17:58:22 UTC = 13:58:22 local** (1.803.160 flujos a `:80`, **gap máximo de
> 0,2 s**, ningún hueco > 60 s). Con la ventana corta, **740.821 flujos del propio
> atacante —el 65,1% del "benigno" HTTP del día— quedaban etiquetados `Benign`**. Ampliada
> a 13:59 y dataset re-etiquetado con `relabel_dataset.py`. Ver el diario del 11 de agosto.

> Verificado el 14-jul con [find_attacker.py](scripts/zeek/find_attacker.py) (top-talkers
> del `conn.log`, **sin conocer la IP de antemano** — en un DoS el atacante aplasta el
> ranking). Hallazgos empíricos frente a la doc: el **SlowHTTPTest ataca el puerto 21, no
> el 80**, y el **Hulk** hace **999.007 conexiones** a `:80` en ~7 min (17:45:27–17:52:34
> UTC) — un flood HTTP **en claro**. La captura de la víctima venía en **pcapng** (Zeek la
> lee de forma nativa, sin el saneado clásico). Misma víctima que el 14-02 pero otro día;
> el emparejamiento por par {atacante, víctima}:puerto + ventana impide colisiones.
>
> **Régimen distinto de los otros dos días:** el DoS no vive en los bytes (un GET de Hulk
> ≈ un GET benigno) ni en el flujo aislado, sino en el **volumen agregado por origen**
> (ver **HALLAZGO CLAVE 8** y el diario del 15 de julio). El SlowHTTPTest (:21), como el
> FTP-BruteForce, no deja payload analizable (0 flujos) → invisible al análisis de bytes.

### Ground-truth verificada del 20-02-2018 (DDoS — volumétrico DISTRIBUIDO)

| Ataque | Atacantes | Víctima | Puerto | Ventana (local) | Estado |
|--------|-----------|---------|--------|-----------------|--------|
| DDoS-LOIC-HTTP | **10 IPs** *(ver abajo)* | `172.31.69.25` | 80 | 10:13–13:16 | **verificado** |

Atacantes: `18.219.9.1`, `18.218.229.235`, `52.14.136.135`, `18.216.200.189`,
`18.218.55.126`, `18.219.5.43`, `18.216.24.42`, `18.218.11.51`, `18.219.32.43`,
`18.218.115.60`.

> Verificado el 18-ago con [find_attacker.py](scripts/zeek/find_attacker.py) sobre
> `UCAP172.31.69.25` (291.917 conexiones). Los diez copan el ranking con **27.897–29.749
> conexiones cada uno**; el 11.º origen tiene 52, así que se identifican sin IP previa.
> `conn_state` **RSTO en el ~97%** — firma de LOIC.
>
> **Ventana fijada por análisis de huecos, no por el CSV.** El ataque **no es continuo**:
> son **tres episodios** — flood principal 10:13:54–11:16:48 (continuo, hueco máximo
> **1,1 s**, ~289.500 conexiones), un **blip de 66 conexiones a las 11:40:08**, y una
> segunda ráfaga 13:14:17–13:15:16 (1.463). Entre 11:16 y 13:14 hay **94 minutos sin una
> sola conexión**. Se usa **una ventana ancha** que cubre los tres: esas diez IPs **solo**
> hablan con la víctima por el `:80` (290.956 TCP + 100 UDP + 10 ICMP, cero tráfico
> benigno), así que ensanchar no mal-etiqueta nada y evita dejar el blip como `Benign`
> siendo del propio atacante — el error del SSH (17-jun) y del Hulk (11-ago).
>
> El CSV del día solo etiqueta 10:15–11:16 y 13:14–13:29 (estas 797 filas aparecen como
> `01:14–01:29` por el **bug 12h/24h de CICFlowMeter**) y deja fuera el blip. La doc oficial
> sitúa además un `DDoS-LOIC-UDP` en la franja de tarde, pero en los datos esa segunda
> ráfaga va contra el `:80` y el CSV la etiqueta `LOIC-HTTP`.
>
> **Anomalía sin explicar:** `18.218.115.60` hace 27.897 conexiones pero solo **31 MB** de
> bytes de aplicación, frente a los 252–402 MB de los otros nueve.

### Ground-truth verificada del 02-03-2018 (Bot — firma de periodicidad)

| Ataque | C2 (atacante) | Víctimas | Puerto | Ventana (local) | Estado |
|--------|---------------|----------|--------|-----------------|--------|
| Bot (Ares) | `18.219.211.138` | **10 bots** *(ver abajo)* | 8080 | 10:13–15:54 | **verificado** |

Bots, todos en `172.31.69.x`: `.6`, `.8`, `.10`, `.12`, `.14`, `.17`, `.23`, `.26`, `.29`,
`.30`.

> **Verificado el 21-ago sobre los TSV de payload de las 442 capturas, no con
> `find_attacker.py`:** ese script busca *top-talkers hacia una víctima*, y aquí no hay
> víctima única — la estructura es un **C2 externo y muchos internos infectados**. Se
> extrajo primero el payload del día completo y el C2 se localizó después, buscando destinos
> comunes en el `:8080` que el CSV señala como puerto del Bot (281.634 de 286.191 flujos).
>
> El C2 usa **exclusivamente el 8080** (438.825 paquetes, ningún otro puerto). Nueve bots
> baten ~15.000 flujos cada uno; **`172.31.69.12` solo 4.988** (un tercio).
>
> **Ventana continua**: hueco máximo **32,6 s** en 5 h 40 min. La doc oficial la parte en
> dos franjas (10:11–11:35 y 14:24–15:55) y en los datos **no hay tal corte**.
>
> **Seguro para el `issubset` de `DayLabeler`:** 0 paquetes bot↔bot con `:8080` en origen o
> destino, así que meter los diez bots como `victim_ips` no puede etiquetar como `Bot` un
> flujo interno entre dos infectados.
>
> **Defecto del dataset:** el host `172.31.69.24` **no tiene captura** — el archivo oficial
> trae un acceso directo de Windows de 697 B en su lugar.
>
> **Régimen nuevo:** la firma no está en el payload ni en el volumen sino en la
> **periodicidad** (meseta de ~8.035 paquetes cada 10 min durante 4 h). Ver **HALLAZGO
> CLAVE 15** y el diario del 19-21 de agosto.

### HALLAZGO CLAVE 1: el FTP-BruteForce no tiene payload, el SSH-Bruteforce sí

Los dos ataques de fuerza bruta del día se comportan de forma **opuesta** respecto
al payload, y esto es directamente relevante para la tesis:

- **FTP-BruteForce → sin payload.** De las **162.801 conexiones del atacante** en el
  `conn.log`, **134.945 están en estado `REJ` con 0 bytes** (el servicio FTP del host
  estaba caído y rechazó todos los intentos) y **el resto tampoco exporta datos de
  aplicación**: el resultado neto es **0 flujos FTP con payload en el dataset**. **No hay
  datos de aplicación**, así que este ataque es **invisible
  para el análisis de payload**. Demuestra empíricamente que el enfoque de payload
  tiene puntos ciegos cuando el ataque no llega a intercambiar datos (conexiones
  rechazadas/fallidas) y debe complementarse con metadatos/flujo.
- **SSH-Bruteforce → con payload.** **94.207 flujos `SF`** (`13.58.98.64 →
  172.31.69.25:22`) con handshakes SSH cifrados reales (~2,9 M paquetes con datos).
  Aquí el análisis de payload **sí** tiene material (alta entropía por el cifrado).

> **Segundo ejemplo de ataque payload-ciego (día 16-02, verificado el 15-jul):** el
> **DoS-SlowHTTPTest** (`13.59.126.31 → 172.31.69.25:21`) deja **0 flujos con payload**
> en todo el dataset —a ningún puerto ni destino— pese a existir en el `conn.log`
> (105.550 conexiones). Es una herramienta de ataque lento HTTP apuntada al puerto **21
> (FTP)**, que no habla HTTP: las conexiones se abren pero no intercambian datos de
> aplicación, exactamente como el FTP-BruteForce. Con **dos** ejemplos independientes de
> ataques invisibles al análisis de bytes, el punto ciego del payload queda demostrado de
> forma robusta: hay ataques que **solo** son detectables por flujo/`conn.log`. *(El
> `conn_state` exacto —REJ vs S0— no se reconfirma aquí porque el PCAP crudo se borró tras
> vectorizar; lo daría el Eje E de una pasada de `conn.log`.)*

### HALLAZGO CLAVE 2: pérdida silenciosa de datos por truncatura intermedia

El SSH-Bruteforce **no aparecía** hasta que se corrigió el saneado: Zeek se detenía
a las 18:05 UTC en `UCAP172.31.69.25` por un record que libpcap rechaza, perdiendo
toda la tarde (y con ella la ventana SSH) en silencio. Al **sanear la captura antes
de Zeek**, se recuperan los 2,9 M de paquetes y aparece el ataque SSH completo. Ver
la nota «Saneado obligatorio» más arriba. Lección: validar siempre la cobertura
temporal de lo extraído frente al rango real de la captura.

### HALLAZGO CLAVE 3: el payload es ciego al brute-force cifrado, y el 99,96% es un espejismo (modelo del 9 de mayo)

El primer modelo de Deep Learning ([train_phase2.py](scripts/zeek/train_phase2.py))
revela el problema en dos actos:

- **Con dataset parcial (solo la víctima, benigno = SSH), el payload no discrimina:**
  5-Fold CV ≈ 0.566 / 0.573 (≈ azar). El benigno de esa captura es **también SSH
  cifrado** (1.821/1.864 al puerto 22) con entropía casi idéntica a la del ataque
  (7.27 vs 7.38, ±0.01); al estar ambos cifrados, los bytes no tienen señal.
- **Con el día completo (2,2 M flujos, benigno diverso), accuracy ≈ 0.9996... falso:**
  como el benigno balanceado es 99,9% NO-SSH (RDP/HTTPS/HTTP/SMB), el modelo solo
  separa "SSH cifrado" de "otros protocolos". La **prueba honesta**
  ([honest_check.py](scripts/zeek/honest_check.py)) lo destapa: evaluado solo sobre
  el **SSH benigno** (puerto 22, 2.022 flujos), marca como ataque al **96,0%
  (histograma) / 79,5% (secuencial)** de los usuarios SSH **legítimos** — falsos
  positivos catastróficos.

**La firma del SSH-Bruteforce vive en los metadatos de flujo (ráfaga de conexiones,
duración, nº de paquetes), no en el payload.** Junto al HALLAZGO 1 (FTP sin
payload), demuestra que el análisis de bytes tiene puntos ciegos y **debe
combinarse con metadatos**. Es el "Cae el mito del 99.99%" de la Fase 1 repetido
desde el payload: ninguna vista por separado basta; el enfoque híbrido es necesario.

### HALLAZGO CLAVE 4: en payload EN CLARO el resultado se invierte — el payload gana (día 22-02, 7 de julio)

El día de Web Attacks (22-02) es el **contraejemplo exacto** del SSH y cierra el
argumento. Evaluación honesta por servicio análoga (HTTP:80, Web-Attack vs
HTTP-benigno 1:1; [honest_by_service_web.py](scripts/zeek/honest_by_service_web.py)):

| Vista | HTTP en claro (22-02) | SSH cifrado (14-02) |
|-------|----------------------|---------------------|
| **payload** | **CV 0.9877, F1 ataque 1.00** | CV 0.5732 (azar) |
| metadatos | CV 0.9286 | CV 0.6093 |
| híbrido | CV 0.9926 | CV 0.5776 |

Como el ataque web viaja **sin cifrar** (contra DVWA: `POST /login.php`, `<script>`,
`union select`), el contenido malicioso está **en los bytes** y el **payload gana**
(detección perfecta del ataque en test); la metadata de flujo, que dominaba en el
SSH cifrado, es aquí la vista **más débil**.

> **[Corregido el 24-ago — HALLAZGO 19.]** Las cifras de arriba son **exactitud en
> validación cruzada**, y esta comparación medía `meta-rica` (con ráfaga) en el lado
> SSH contra `build_meta_features` (sin ráfaga) en el lado web. Con las tres vistas
> medidas igual (macro-F1 out-of-fold, IC 95%), **la evaluación intra-día está
> saturada**: payload 0,9842 y conducta 0,9985 en el SSH; payload 0,9734 y conducta
> 0,9823 en el web. **Lo único que se invierte son los metadatos per-flujo**
> (0,9906 → 0,9186, la única diferencia con IC sin solapar). La tesis de que
> ninguna vista basta sola **sigue en pie, pero no la sostiene esta comparación**:
> la sostienen la evasión, la transferencia entre dominios y la ceguera del payload
> ante los ataques que no exportan datos. Ver el diario del 24 de agosto.

*(Caveat: la clase de ataque web son 203 flujos —ataque de bajo volumen—; señal
nítida en test pero N reducido.)*

### Representación vectorial (lo que produce `build_dataset.py`)

Cada **flujo TCP** (agrupado por `uid`) genera una muestra con:

- `X_hist` (256, float32): **histograma de bytes normalizado** del payload del flujo.
- `entropy` (float32): **entropía de Shannon** (bits/byte). Útil para detectar
  cifrado/ofuscación; el tráfico SSH benigno da ~8.0 (máximo).
- `X_seq` (256, uint8): **secuencia de los primeros 256 bytes** del payload
  (relleno con 0), para modelos secuenciales / sliding-window.
- Escalares: `n_pkts`, `tot_bytes`, `seq_len`.
- Metadatos: `uid`, `ts`, `orig_h`, `orig_p`, `resp_h`, `resp_p`, `service`.
- `y`: etiqueta, según la ground-truth del día (miércoles 14-02: `Benign` /
  `FTP-BruteForce` / `SSH-Bruteforce`; jueves 22-02: `Benign` / `Brute Force -Web` /
  `Brute Force -XSS` / `SQL Injection`).

Parámetros en `build_dataset.py`: `SEQ_LEN = 256`, `MAX_FLOW_BYTES = 65536` (tope
de bytes por flujo para el histograma, acota memoria en flujos voluminosos).

**Unidad de ejemplo:** una muestra = **una conexión TCP**, no un paquete. `FlowAcc`
agrega *todos* los paquetes con datos del flujo (`n_pkts` es su recuento), acumulando el
histograma hasta 64 KB y quedándose con los primeros 256 bytes como secuencia.

**Añadidos el 11 de agosto (revisión del tutor):**

- `service` (str): **servicio identificado por las reglas de Zeek** (`c$service`, por DPI
  sobre el contenido). Sustituye al puerto como criterio de "servicio" —el puerto depende
  de la configuración de la red y no es un atributo *context independent*—. Los días
  extraídos antes de esta fecha no lo traen; para ellos
  [service_id.py](scripts/zeek/service_id.py) lo deriva de `X_seq` con firmas
  equivalentes, sin re-descargar los PCAP.
- **19 atributos del payload de la literatura** derivados a demanda desde `X_hist`,
  `entropy` y `X_seq` por [payload_features.py](scripts/zeek/payload_features.py)
  (PAYL, Anagram, entropía/χ²/índice de coincidencia, ratio de compresión, composición
  léxica). No se almacenan en el `.npz`: se calculan sobre el subconjunto evaluado.

### Formato de salida y cómo cargarlo

No se usa Parquet porque el entorno `tfg_ia` no tiene `pyarrow`. Se generan:

- `dataset_<dia>.npz` — arrays NumPy (cargar con `numpy.load(path, allow_pickle=True)`).
- `dataset_<dia>_meta.csv` — una fila por flujo con metadatos + escalares +
  etiqueta (sin las columnas anchas), para inspección con pandas.

```python
import numpy as np
d = np.load("data/processed/zeek/wednesday-14-02-2018/dataset_Wednesday-14-02-2018.npz", allow_pickle=True)
X_hist, X_seq, entropy, y = d["X_hist"], d["X_seq"], d["entropy"], d["y"]
```

### Estado actual del dataset (día completo, 9 de mayo)

Procesadas las **449 capturas** del miércoles (46 GB, 445 ok / 0 errores) →
**2.202.231 flujos con payload**:

| Etiqueta | Flujos | Entropía media | Notas |
|----------|--------|----------------|-------|
| Benign | 2.109.613 | 6.97 | diverso: RDP (3389), HTTPS (443), HTTP (80), SMB (445)... solo 0,1% SSH |
| SSH-Bruteforce | 92.618 | 7.38 | `13.58.98.64 → 172.31.69.25:22`, handshakes cifrados |
| FTP-BruteForce | 0 | — | sin payload (REJ); el ataque no exporta datos |

> **Actualización 17-jun (re-etiquetado):** tras corregir la ventana del SSH
> ([relabel_dataset.py](scripts/zeek/relabel_dataset.py)), 1.589 flujos de la cola
> pasan de `Benign` a `SSH-Bruteforce`. El `.npz` **actual** contiene por tanto
> **2.108.024 `Benign` + 94.207 `SSH-Bruteforce`** (mismo total, 2.202.231). La tabla
> de arriba refleja el estado del 9 de mayo, previo a esa corrección.

Dataset **fuertemente desbalanceado** (el benigno domina ahora). Se balancea por
undersampling a la clase minoritaria (92.618 c/u → 185.236) antes de entrenar, como
en la Fase 1. **Ojo:** balancear solo por clase no basta — al ser el benigno casi
todo NO-SSH, infla el accuracy (ver HALLAZGO CLAVE 3 y `honest_check.py`).

### Modelo entrenado (9 de mayo) y resultado

Hay un **primer modelo de Deep Learning** entrenado con
[train_phase2.py](scripts/zeek/train_phase2.py): dos MLP (histograma+entropía y
secuencial) balanceados por undersampling. Sobre el día completo el accuracy es
**0.9996** (CV y test held-out)... pero es un **espejismo**: la prueba honesta
([honest_check.py](scripts/zeek/honest_check.py)) muestra que sobre SSH benigno real
el modelo da **96% / 79,5% de falsos positivos**. Aprende el protocolo, no el
ataque (ver **HALLAZGO CLAVE 3**). Resumen y matrices en
[models/phase2_results.md](models/phase2_results.md).

```cmd
:: 1) extraer payload de todas las capturas del día (46 GB, Docker)
conda run -n tfg_ia python scripts\zeek\run_zeek_payload.py
:: 2) consolidar el dataset etiquetado
conda run -n tfg_ia python scripts\zeek\build_dataset.py
:: 3) entrenar los dos MLP y, 4) auditar con la prueba honesta
conda run -n tfg_ia python scripts\zeek\train_phase2.py
conda run -n tfg_ia python scripts\zeek\honest_check.py
```

### Próximos pasos (Fase 2)

- [x] **Cuantificar la ventaja híbrida** (paso 1, hecho el 16 de junio,
  [hybrid_compare.py](scripts/zeek/hybrid_compare.py)): payload, metadatos e híbrido
  resultaron **equivalentes** bajo balanceo global por clase (~0.9996 acc, ~78% FP
  sobre SSH benigno). El espejismo es **del balanceo**, no de la vista. Ver
  [models/phase2_hybrid_compare.md](models/phase2_hybrid_compare.md).
- [x] **Evaluación honesta por servicio** (paso 2, hecho el 16 de junio,
  [honest_by_service.py](scripts/zeek/honest_by_service.py)): aislado el caso difícil
  (SSH-ataque vs SSH-benigno 1:1), el **payload cae al azar (CV 0.57)** y los
  **metadatos ganan (CV 0.61)** — la firma vive en el comportamiento de flujo, no en
  los bytes. Ver [models/phase2_by_service.md](models/phase2_by_service.md).
- [x] **Enriquecer la metadata de flujo con la ráfaga** (paso 1 refinado, hecho el
  17 de junio, [honest_by_service_rich.py](scripts/zeek/honest_by_service_rich.py)):
  el 0.61 del paso 2 era un **artefacto de contaminación** (el 78,6% del "SSH benigno"
  era el propio atacante fuera de ventana). Con la feature de **ráfaga** y el benigno
  **limpio** (terceros), la vista conductual separa el ataque **casi perfecta (CV 1.0)**;
  el payload también acierta pero por una **huella de herramienta** (`paramiko`),
  evadible. Ver [models/phase2_by_service_rich.md](models/phase2_by_service_rich.md).
- [x] **Limpiar el etiquetado en origen** (17 de junio): era un error de límite de
  ventana (el ataque seguía 90 s tras el fin documentado). Ampliada la ventana del SSH
  en [attack_metadata.py](scripts/zeek/attack_metadata.py) y re-etiquetado el dataset
  con [relabel_dataset.py](scripts/zeek/relabel_dataset.py) **sin reprocesar los 67 GB**
  (1.589 flujos `Benign`→`SSH-Bruteforce`; SSH benigno ahora 433 genuinos, 0 del atacante).
- [x] **Día 2 — Web Attacks (payload en claro), el espejo del SSH** (7 de julio,
  [honest_by_service_web.py](scripts/zeek/honest_by_service_web.py)): sobre HTTP:80, el
  **payload gana (CV 0.99, F1 ataque 1.00)** y la metadata es la vista más débil (0.93),
  **invirtiendo** el resultado del SSH cifrado (payload 0.57, metadata 0.61). Cada vista
  gana en su régimen; solo el **híbrido** es robusto en ambos. Es el **HALLAZGO CLAVE 4**
  y el cierre del argumento híbrido. Ver [models/phase2_by_service_web.md](models/phase2_by_service_web.md)
  y el diario del 7 de julio.
- [x] **Multi-tipo del ataque web: el tipo vive en la secuencia** (8 de julio,
  [multitype_web.py](scripts/zeek/multitype_web.py)): clasificando los 203 flujos de
  ataque en sus 3 tipos (BF-Web/XSS/SQLi), la vista **payload-seq** (secuencia de bytes)
  identifica el tipo casi perfecto (**macro-F1 0.95**), mientras que el **histograma**
  (0.75) y la **metadata** (0.77) no —el histograma difumina los tokens y la metadata
  solo separa por volumen (ambas fallan el SQLi). Matiz honesto: la ventaja diferencial
  del payload en claro (identificar el tipo) exige la **representación secuencial**, no el
  histograma. Ver [models/phase2_multitype_web.md](models/phase2_multitype_web.md) y el
  diario del 8 de julio.

**Cerrada la validación empírica de la tesis (Fases 1-2), el trabajo continúa en la
Fase 3**: profundizar en el componente de IA (deep learning de verdad sobre los bytes)
y escalar a más días. Ver la sección siguiente.

---

## Fase 3: Profundización en IA y Escalado a Más Días

> **Estado: Ejes A, B, C y D ejecutados** (A/B/D-saliency el 8 de julio, C el 15 de julio y
> ampliado el 19-21 de agosto, D-cruzado entre días el 19 de agosto; ver el diario). Quedan
> las **curvas PR / calibración** —que el HALLAZGO 14 ha vuelto necesarias— y el **Eje E**,
> que el día Bot ha dejado de hacer marginal. Las Fases 1-2 demostraron *empíricamente* la
> tesis con modelos simples (MLP de scikit-learn); la Fase 3 la eleva con **deep learning
> real sobre la secuencia de bytes**, un **híbrido de dos ramas** con fusión aprendida,
> **interpretabilidad** (saliency) y un **dataset multidía / multiataque** de **seis días
> con cuatro regímenes de firma**: cifrado, claro, volumétrico y **periodicidad**.

### Prerrequisito: framework de deep learning — HECHO

**PyTorch 2.13 (CPU) instalado** en `tfg_ia`. (El entorno ya tenía scikit-learn/XGBoost.)

```cmd
conda run -n tfg_ia pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Modelos y utilidades DL compartidas en [dl_models.py](scripts/zeek/dl_models.py)
(`ByteCNN` multi-kernel estilo *Deep Packet*, `ByteLSTM`, bucle de entrenamiento y
predicción out-of-fold).

### Eje A — Deep learning sobre el payload en bytes — HECHO

- [x] **Byte-embedding + 1D-CNN** y **BiLSTM** sobre `X_seq`, comparados con los baselines
  shallow en la misma partición ([train_dl_payload.py](scripts/zeek/train_dl_payload.py)).
  **El byte-CNN es el mejor** (multi-tipo web macro-F1 **0.968**, detección web **1.00**);
  el BiLSTM infra-ajusta con N pequeño. Ver el diario del 8 de julio (HALLAZGO 5) y los
  resúmenes `models/phase2_dl_*.md`.

### Eje B — Híbrido de dos ramas (la fusión, hecha bien) — HECHO

- [x] Red de **dos ramas** (CNN de payload + MLP de metadatos, **fusión tardía** de los
  embeddings aprendidos) en [train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py).
  **Robusto en ambos regímenes** (web claro 0.998, SSH cifrado 1.00) y **corrige la
  dilución** de la fusión ingenua (0.968→0.901 en multi-tipo). Diario del 8 de julio
  (HALLAZGO 6) y `models/phase2_dlhybrid_*.md`.

### Eje C — Más datos: dataset multidía / multiataque — HECHO (5 días, 4 regímenes)

- [x] **Tercer día procesado: `Friday-16-02-2018` (DoS-Hulk)** el 15 de julio (ver el diario).
  Aporta un **tercer régimen de firma** —**volumétrico**— que completa el mapa: per-flujo
  ninguna vista sirve (≤0.74), y solo el **agregado de volumen por origen** (ráfaga) separa
  el flood (**0.81**, [dos_burst.py](scripts/zeek/dos_burst.py)). **HALLAZGO CLAVE 8.** Con tres
  días (SSH cifrado → conducta, web claro → payload, DoS → volumen) queda demostrada la
  **generalidad** de la tesis: cada régimen esconde su firma en una vista distinta.

- [x] **Cuarto día: `Tuesday-20-02-2018` (DDoS-LOIC-HTTP)** el 19-ago. Volumétrico pero
  **distribuido en 10 orígenes**, así que la ráfaga por origen es ~34× menor que en el Hulk
  y **deja de aportar** (0.9982 frente a 0.9985 de la metadata sola). Es el **cuarto día
  homólogo** que desbloqueó la generalización cruzada del Eje D. 2.837.519 flujos.
- [x] **Quinto día: `Friday-02-03-2018` (Bot, Ares)** el 21-ago. Aporta un **cuarto régimen
  de firma —la periodicidad (*beaconing*)—** que **ninguna vista actual mide**.
  **HALLAZGO CLAVE 15.** 3.347.221 flujos. Obligó a invertir el método de ground-truth
  (primero extraer, después localizar el C2 sobre los TSV), porque no hay víctima única.

- [x] **`Wednesday-28-02-2018` (Infiltration): analizado y NO procesado, a propósito** el
  21-ago. El pipeline de payload es **ciego al 94,4%** de este ataque (**HALLAZGO CLAVE
  16**): el reconocimiento interno son 182.323 conexiones **sin un solo byte** de
  aplicación. El día se documenta como **resultado negativo**, que es donde está su valor.

- [x] **Sexto día: `Thursday-15-02-2018` (DoS-GoldenEye + Slowloris)** el 22-ago. Su CSV
  llevaba descargado desde el 24-abr-2026 **sin usarse** (aparecio auditando que dias se
  había descargado). Es el **tercer día volumétrico**, y con él el HALLAZGO 14 pasó de un
  par de días a **seis pares dirigidos** — lo que obligó a **corregirlo**. 1.997.325 flujos.

Todo el pipeline es **genérico** (acepta `--day`), así que añadir más días es puramente
operativo. **No quedan candidatos con valor claro:** `Thursday-01-03-2018` (Infiltration) se
descarta porque repetiría el HALLAZGO 16 con ~49 GB más y sin régimen nuevo, y los días
`21-02` y `23-02` repiten regímenes ya cubiertos (DDoS y Web).
Procedimiento (validado con los seis días ya hechos; para días que no quepan en disco, usar
`run_zeek_payload_batched.py`):

```cmd
:: 1) descargar y extraer el día (borrar el zip tras extraer)
aws s3 sync --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/" "./data/raw/" --exclude "*" --include "*16-02-2018*"
:: 2) VERIFICAR la ground-truth empíricamente (lección del SSH) antes de etiquetar.
::    Si NO se conoce la IP del atacante (típico en DoS/DDoS), find_attacker.py la revela
::    por los top-talkers del conn.log; si SÍ se conoce, find_host.py localiza su captura:
python scripts\zeek\find_attacker.py --day Friday-16-02-2018 --capture UCAP172.31.69.25-part1.pcap --port 80
:: 3) añadir el día verificado (par atacante→víctima:puerto + ventanas) a attack_metadata.py
:: 4) extraer payload (largo), vectorizar, y liberar disco (borrar PCAP+TSV, queda el .npz)
conda run -n tfg_ia python scripts\zeek\run_zeek_payload.py --day Friday-16-02-2018
conda run -n tfg_ia python scripts\zeek\build_dataset.py --day Friday-16-02-2018
:: 5) evaluar: per-flujo (DL) y, para ataques volumétricos/conductuales, el agregado de ráfaga
conda run -n tfg_ia python scripts\zeek\train_dl_payload.py --day Friday-16-02-2018 --port 80 --task binary --cap 4000
conda run -n tfg_ia python scripts\zeek\dos_burst.py --day Friday-16-02-2018 --port 80 --cap 4000
```

> **Nota de escala (días masivos):** el DoS tiene **4,04 M de flujos**; `train_dl_payload.py`
> / `train_dl_hybrid.py` ya no materializan las vistas completas (evita OOM con 16 GB de RAM)
> y aceptan `--cap N` para subsamplear por clase. Las capturas pcapng (p. ej. la víctima del
> DoS) se detectan (`is_pcapng`) y se pasan directas a Zeek sin el saneado clásico.

### Eje D — Evaluación rigurosa y generalización — PARCIAL

- [x] **Interpretabilidad (saliency)** ([eval_saliency.py](scripts/zeek/eval_saliency.py)):
  demostrado que el byte-CNN "ve" el SSH cifrado por el **banner en claro** (`paramiko`),
  no por el cifrado (HALLAZGO 7, 8 de julio). `models/phase2_saliency_ssh.{md,png}`.
- [x] **Generalización cruzada entre datasets** (2018 → 2017, HALLAZGOS 9 y 10, 4-6 de
  agosto). *Reclasificado el 11 de agosto como **trabajo futuro / validación
  complementaria** por indicación del tutor: la prioridad es profundizar en el 2018.*
- [x] **Generalización cruzada entre días del mismo régimen** (19-ago, **HALLAZGO CLAVE
  14**): con el DDoS del 20-02 como cuarto día homólogo, 16-02 ↔ 20-02 en ambas direcciones.
  El **byte-CNN colapsa a 0.5000 con recall de ataque 0.0000** (degenerado) mientras el
  **histograma transfiere** (1.0000 / 0.9928). El modelo más expresivo generaliza peor.
  `models/phase2_crossdataset_*_p80.md`.
- [x] **Curvas PR / calibración** (22-ago, [cross_calibration.py](scripts/zeek/cross_calibration.py)):
  hechas, y **cambiaron el HALLAZGO 14**. El byte-CNN tiene **AUC ≥ 0,9724 en los seis
  pares**, así que su representación sí transfiere; lo que no transfiere es el **umbral**, y
  recalibrar recupera F1 ≥ 0,9849 en los cuatro colapsos. El que tiene un techo real es el
  histograma (AUC 0,67 y 0,80 en la dirección «→ 15-02»). Ver F38 y
  `models/phase3_calibracion_*.json`.

### Eje E — (Opcional) Metadata de flujo completa (conn.log)

- [x] **Inter-arribo como vista, y prueba de evasion** (22-ago,
  [interarrival_eval.py](scripts/zeek/interarrival_eval.py)): **HECHO**, ver
  **HALLAZGO CLAVE 17**. Seis características temporales calculadas desde el `.npz`
  (`ts` + `orig_h`), **sin `conn.log`**, dan recall 0,9900 en el Bot y son inmunes a la
  evasión. *No* mejoran a la ráfaga; su valor es ser compactas, inmunes, y demostrar que
  el *beaconing* del HALLAZGO 15 es **usable**.
- [ ] **`conn_state` y abanico de destinos vía `conn.log`.** Es la mitad del Eje E que
  sigue necesitando re-pasar Zeek: son las señales del **HALLAZGO CLAVE 16** (82 % de SYN
  sin respuesta, un origen contra 612 destinos) y no están en los `.npz`, porque el
  pipeline solo guarda flujos **con payload** — justo los que la Infiltration no genera.

### Plan de cierre — re-priorizado el 21 de agosto por el autor

> **Orden vigente (21 de agosto, decisión del autor):** **1)** descargar y procesar más
> días, **2)** estado del arte, **3)** rehacer gráficos y contenido para la memoria,
> **4)** escribir la memoria.
>
> **Invierte el orden del tutor del 11 de agosto**, que era: primero la memoria, y las
> experimentaciones nuevas añadidas sobre una memoria ya existente. Se deja constancia de
> ambos órdenes por trazabilidad. Las fechas no cambian: primera versión para **finales de
> agosto** (el tutor la revisa entonces), entrega el **6 de septiembre**.

**Estado de la prioridad de días (22 de agosto):**

| Día | Ataque | Estado |
|-----|--------|--------|
| `Tuesday-20-02-2018` | DDoS-LOIC-HTTP | ✅ procesado (2.837.519 flujos) |
| `Friday-02-03-2018` | Bot (Ares) | ✅ procesado (3.347.221 flujos) |
| `Wednesday-28-02-2018` | Infiltration | ✅ analizado; **no procesado a propósito** (HALLAZGO 16) |
| `Thursday-01-03-2018` | Infiltration | ❌ descartado (repetiría el HALLAZGO 16) |
| `Thursday-15-02-2018` | DoS-GoldenEye/Slowloris | ✅ procesado (1.997.325 flujos). Su CSV llevaba sin usarse desde el 24-abr-2026; es el 3.er día volumétrico y **obligó a corregir el HALLAZGO 14** |
| `Wednesday-21-02` / `Friday-23-02` | DDoS / Web | ❌ descartados: repiten regímenes ya cubiertos |

**Con esto, la prioridad 1 del autor (más días) queda cerrada:** seis días procesados, cuatro
regímenes, y los días restantes del dataset no aportarían un régimen nuevo.

**La prioridad 2 (estado del arte) también queda cerrada** (22-ago): taxonomía de siete
familias sintetizada desde `Machine Learning en NIDS.pdf`, y sus dos afirmaciones falsables
**comprobadas sobre nuestros datos** — los ensembles **no** mejoran nuestra transferencia
entre días, y la fuga de IPs que denuncia Engelen **sobrevive a la validación cruzada entre
días** (**HALLAZGO CLAVE 18**). Ver el diario del 22 de agosto.

**Orden original del tutor (11 de agosto), conservado para referencia:**

1. **[PRIORIDAD 1] Memoria (LaTeX), primera versión.** El trabajo ya tiene material de
   sobra: tres regímenes de firma, byte-CNN, híbrido de dos ramas, interpretabilidad,
   robustez ante evasión, detección no supervisada y rigor estadístico con IC al 95%.
2. **[PRIORIDAD 2] Estado del arte** (punto 3 del tutor): búsqueda bibliográfica propia y
   **síntesis de estrategias de ML aplicadas a *network IDS***. No hay artículos de
   partida más allá del libro facilitado; los trabajos del tutor sobre KDDCup99 (2009)
   están desfasados y no sirven como base.
3. **[PRIORIDAD 3] Más días y ataques del CSE-CIC-IDS2018** (punto 2 del tutor:
   *profundizar en esta base de datos*). Candidatos: **DDoS (20-21/02)**, **Bot (02/03)**,
   **Infiltration (28/02 y 01/03)**. El pipeline es genérico (`--day`), así que es trabajo
   puramente operativo; el procedimiento validado está en el Eje C. El DDoS 20-21/02 tiene
   además valor doble: es el **cuarto día homólogo** que faltaba para la generalización
   cruzada *entre días del mismo régimen* (Eje D).
4. **Re-ejecutar con `--service`** las evaluaciones que se citen en la memoria, para que
   las cifras publicadas no dependan de la convención de puertos (corrección del 11-ago).

### Trabajo futuro (explícitamente aplazado por el tutor)

- **Otros datasets.** El trabajo con **CIC-IDS2017** y la generalización cruzada entre
  datasets (HALLAZGOS 9 y 10, 4-6 de agosto) **está hecho y se conserva**, pero el tutor
  indica dejar la validación en otras bases de datos como **trabajo futuro**: se presentará
  en la memoria como validación complementaria y línea de continuación, no como eje
  central. Lo mismo aplica a **UNSW-NB15** y **Malware-Traffic-Analysis.net**, que nunca
  llegaron a descargarse.
- **Eje E — metadata de flujo completa (`conn.log`).** `duration` / inter-arribo /
  `conn_state` para enriquecer la rama de metadatos del híbrido. Exigiría re-descargar
  ~150 GB de PCAP de 2018 y re-pasar Zeek, con retorno marginal (la ráfaga ya captura el
  grueso de la firma conductual). Aplazado. *Nota: una futura extracción traería ya el
  campo `service` de Zeek, añadido el 11 de agosto a `extract_payload.zeek`.*

---

## Guía de Consulta de Comandos (Windows CMD)

| Categoría | Comando | Uso |
|-----------|---------|-----|
| Entorno | `conda activate tfg_ia` | Activa el entorno antes de programar |
| Sistema | `dir` | Lista archivos y verifica tamaños en disco |
| Editor | `code .` | Abre el proyecto en VS Code |
| Git | `git add .` | Prepara los cambios del día para guardar |
| Git | `git commit -m "msg"` | Registra los avances localmente |
| Git | `git push origin master` | Sincroniza el código con GitHub |
| AWS | `aws s3 sync --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/" "./data/raw/"` | Descarga el dataset público completo en `data/raw/` |
| AWS | `aws s3 ls --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/"` | Lista el contenido disponible del bucket público |

---

## Tecnologías y Herramientas

- **Lenguaje:** Python 3.x
- **Entorno:** Miniconda (`tfg_ia`)
- **Notebooks:** Jupyter
- **Librerías principales:** Pandas, NumPy, Scikit-learn, XGBoost, Matplotlib, imbalanced-learn
- **Deep learning (Fase 3):** PyTorch (CPU) — byte-CNN, BiLSTM e híbrido de dos ramas
- **Infraestructura y soporte:** Docker (Zeek), AWS CLI, Git/GitHub
- **Documentación:** LaTeX (compilado en local, VS Code)

## Estructura del Repositorio

- `data/raw/`: CSV originales del dataset.
- `data/processed/`: Datos tratados y preparados.
- `notebooks/`: Cuadernos de exploración, limpieza y benchmark.
- `models/`: Modelos entrenados o artefactos derivados.
- `scripts/zeek/`: Pipeline de la Fase 2 (extracción de payload con Zeek, vectorización, etiquetado y evaluación de modelos). Módulos transversales añadidos el 11 de agosto:
  - [service_id.py](scripts/zeek/service_id.py): identificación del **servicio por contenido** (reglas equivalentes a los analizadores de Zeek) y selección de subconjuntos con `--service` en lugar de `--port`.
  - [payload_features.py](scripts/zeek/payload_features.py): **19 atributos del payload** tomados de la literatura (PAYL, Anagram, entropía/χ², compresión, composición léxica).
  - [payload_attrs_eval.py](scripts/zeek/payload_attrs_eval.py): evaluación de la **unión payload + características de Zeek**.
  - [run_zeek_payload_batched.py](scripts/zeek/run_zeek_payload_batched.py) *(19-ago)*: extracción por lotes con **borrado incremental del PCAP**, para días que no caben en disco (los TSV ocupan ~1,48× el PCAP). Idempotente: reanuda solo.
- `figuras/`: **42 figuras + 12 tablas** para la memoria, generadas de forma reproducible desde `models/*.md` y los `.npz` (`scripts/figuras/generar_todo.py`). `figuras/README.md` es el catálogo y dice qué falta.
- `DIF_Dissertation_2026/`: plantilla LaTeX de la UPV/EHU para la memoria. **Todavía sin empezar** (chap1/chap2 son el manual de la plantilla; la bibliografía trae las entradas de ejemplo). Entrega el 6 de septiembre.

---

*Desarrollado por Iñaki Moreno - TFG Grado en Inteligencia Artificial (UPV/EHU)*

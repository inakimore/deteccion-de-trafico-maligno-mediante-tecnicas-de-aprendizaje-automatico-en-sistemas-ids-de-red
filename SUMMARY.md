# SUMMARY — Resumen del Proyecto TFG (IDS Híbrido: Payload + Metadatos)

> Mapa cronológico y de navegación del TFG. El **diario detallado y vivo** está en
> [README.md](README.md); este documento es el resumen ejecutivo: qué se hizo, con qué
> datos, qué es cada archivo y los hallazgos clave. Autor: Iñaki Moreno — Grado en IA
> (UPV/EHU), convocatoria de septiembre 2026.

---

## 1. La tesis en una frase

Un IDS sobre **CSE-CIC-IDS2018** en el que se demuestra **empíricamente** que
**ninguna vista basta por sí sola**: según el ataque, la firma vive en el **payload**
(bytes), en la **conducta de flujo** (metadatos) o en el **volumen agregado**. La
detección robusta exige **combinar payload + metadatos** (enfoque híbrido).

Se valida con **tres días** que cubren **tres regímenes opuestos**:

| Día | Ataque | Régimen | ¿Dónde está la firma? | Vista ganadora |
|-----|--------|---------|-----------------------|----------------|
| 14-02 | SSH-Bruteforce | **cifrado** | conducta / ráfaga de conexiones | metadata+ráfaga (~1.0) |
| 22-02 | Web (BF/XSS/SQLi) | **en claro** | contenido en los bytes | payload-seq / byte-CNN (0.95–1.0) |
| 16-02 | DoS-Hulk | **volumétrico** | volumen agregado por origen | metadata+ráfaga (0.81) |

---

## 2. Cronología

### Fase 1 — Baseline con metadatos de flujo (CSV) · marzo–abril

- **26-mar:** Infraestructura (conda `tfg_ia`, Git, AWS CLI). Descarga del primer día.
- **31-mar:** Baseline RandomForest binario (Fuerza Bruta vs Benigno). Detectada **fuga
  de datos** (`Dst Port` como atajo); "análisis honesto" sin variables-atajo.
- **27-abr:** Benchmark **multiclase** (Decision Tree / RF / XGBoost, 5-Fold CV) →
  ~0.9999 acc. **Prueba de robustez** (undersampling + quitar firmas mecánicas): el
  ataque sigiloso **Slowloris cae a 0.80** (20% falsos positivos). **"Cae el mito del
  99.99%":** los metadatos son frágiles ante evasión → justifica la Fase 2.

### Fase 2 — Análisis de payload en crudo (PCAP → Zeek) · abril–julio

- **28-abr:** Aprobación del tutor. Estrategia: **Zeek sobre Docker** (no Scapy) +
  vectorización (histograma/entropía y secuencia de bytes).
- **5-may:** Pipeline **PCAP → Zeek → TSV** montado ([extract_payload.zeek](scripts/zeek/extract_payload.zeek),
  [run_zeek_payload.py](scripts/zeek/run_zeek_payload.py)). Decodificado HTTP real.
- **6-may:** Vectorización y **etiquetado por ground-truth** ([build_dataset.py](scripts/zeek/build_dataset.py),
  [attack_metadata.py](scripts/zeek/attack_metadata.py)). El CSV **no trae IPs** → no hay
  join por 5-tupla; se etiqueta por IP+puerto+ventana. **HALLAZGO 1** (parte FTP).
- **7-may:** Recuperado el SSH-Bruteforce. **HALLAZGO 2**: pérdida silenciosa de datos por
  truncatura intermedia → **saneado obligatorio** del PCAP antes de Zeek.
- **9-may:** Primer modelo DL (MLP). Día completo (2,2 M flujos). **HALLAZGO 3**: el
  0.9996 es un **espejismo del desbalanceo de servicios**; sobre SSH benigno real da 96%
  de falsos positivos. La firma del brute-force cifrado **no está en los bytes**.
- **16-jun:** Comparación payload vs metadatos vs híbrido ([hybrid_compare.py](scripts/zeek/hybrid_compare.py),
  [honest_by_service.py](scripts/zeek/honest_by_service.py)). Aislado el caso difícil, el
  payload cae al azar (0.57) y la metadata gana débilmente (0.61).
- **17-jun:** **Metadata de ráfaga** ([honest_by_service_rich.py](scripts/zeek/honest_by_service_rich.py)).
  El 0.61 era **contaminación** (78,6% del "SSH benigno" era el atacante fuera de ventana).
  Corregido el etiquetado ([relabel_dataset.py](scripts/zeek/relabel_dataset.py)); con
  benigno limpio la ráfaga separa **casi perfecto (1.0)**. El "éxito" del payload era un
  *fingerprint* del cliente (`paramiko`), evadible.
- **7-jul:** **Día 2 (22-02, Web Attacks, payload en claro)** ([honest_by_service_web.py](scripts/zeek/honest_by_service_web.py)).
  **HALLAZGO 4**: el resultado se **invierte** — el payload gana (0.99), la metadata es la
  peor (0.93). Cada vista gana en su régimen.
- **8-jul:** **Multi-tipo web** ([multitype_web.py](scripts/zeek/multitype_web.py)): el
  **tipo** de ataque (BF/XSS/SQLi) solo lo identifica la **secuencia** de bytes (0.95), ni
  el histograma (0.75) ni la metadata (0.77). La representación importa.

### Fase 3 — Deep learning y escalado a más días · julio

- **8-jul (Ejes A/B/D):** **PyTorch (CPU)**. [dl_models.py](scripts/zeek/dl_models.py)
  (`ByteCNN` multi-kernel estilo *Deep Packet*, `ByteLSTM`).
  - **Eje A** ([train_dl_payload.py](scripts/zeek/train_dl_payload.py)): el **byte-CNN es
    el mejor** (multitipo 0.968, web 1.00). **HALLAZGO 5**.
  - **Eje B** ([train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py)): **híbrido de dos
    ramas** con fusión tardía, robusto en ambos regímenes y corrige la dilución de la
    fusión ingenua. **HALLAZGO 6**.
  - **Eje D** ([eval_saliency.py](scripts/zeek/eval_saliency.py)): la saliency prueba que
    el CNN "ve" el SSH cifrado por el **banner `paramiko` en claro**, no por el cifrado.
    **HALLAZGO 7**.
- **15-jul (Eje C):** **Día 3 (16-02, DoS-Hulk, volumétrico)**. Atacantes verificados sin
  IP previa ([find_attacker.py](scripts/zeek/find_attacker.py)). Per-flujo todas las vistas
  débiles (≤0.74); solo el **agregado de ráfaga** separa el flood (**0.81**,
  [dos_burst.py](scripts/zeek/dos_burst.py)). **HALLAZGO 8**: el tercer régimen cierra la
  **generalidad** de la tesis. Segundo ataque payload-ciego (SlowHTTPTest :21, 0 flujos,
  como el FTP).

### Punto 1 — Segundo dataset (CIC-IDS2017) y generalización cruzada · agosto

- **4-ago (infraestructura):** se añade **CIC-IDS2017** como segundo dataset (requisito del
  plan oficial) para la **generalización cruzada** (entrenar en 2018, testear en 2017), la
  prueba directa contra el *"100% sospechoso"*. Nuevos: ground-truth 2017 en
  [attack_metadata.py](scripts/zeek/attack_metadata.py), `--pcap-dir` en
  [run_zeek_payload.py](scripts/zeek/run_zeek_payload.py) y
  [find_attacker.py](scripts/zeek/find_attacker.py) (sin tocar el flujo 2018), y
  [cross_dataset_eval.py](scripts/zeek/cross_dataset_eval.py) (train A → test B; vistas
  payload-hist / metadatos / byte-CNN).
- **4-ago (día web procesado y resultado):** descargado `Thursday-WorkingHours.pcap` (8,3 GB
  pcapng). **GT verificada con `find_attacker.py`** (2 correcciones vs. la doc, como en 2018):
  el atacante sale como **`172.16.0.1`** (NAT, no `205.174.165.73`) → `192.168.10.50:80`, y la
  **tz es UTC-3** (confirmada). Dataset: 83.886 flujos, **174 de ataque web** (143/22/9 BF/XSS/
  SQLi), análogo del 22-02-2018. **HALLAZGO 9 (generalización cruzada):** el **byte-CNN
  entrenado en 2018 detecta el web de 2017 con 0.991 y 0 falsos positivos** → la firma del
  payload en claro es **real, no memorización de DVWA**; los **metadatos caen al azar (0.53)**
  (específicos del laboratorio). Asimetría honesta: **2017→2018 colapsa (0.50)** por menor
  diversidad del ataque de 2017 (incluso con 30 épocas) → la generalización depende de la
  amplitud de los datos, que es justo el argumento pro-multidataset. Resúmenes
  `models/phase2_crossdataset_*.md`.
- **5-6 ago (SSH y DoS cruzados — HALLAZGO 10):** procesados **Tuesday** (SSH-Patator, 2.979
  ataque) y **Wednesday** (DoS-Hulk, 170.032 ataque) de 2017; GT verificada (mismo NAT
  `172.16.0.1`, tz −3). **byte-CNN train 2018→test 2017: web 0.991, SSH 0.999, DoS 0.966**;
  metadatos al azar en los tres (0.43–0.53). **Matiz clave (verificado en los bytes):** el
  payload transfiere por motivos distintos — web = **contenido intrínseco** (`union select`,
  `<script>`, robusto); SSH = **banner `paramiko` compartido** por ambos brute-forcers
  (fingerprint, evadible; confirma HALLAZGO 7); DoS = **User-Agents/cabeceras del tool Hulk/
  GoldenEye compartidos** (fingerprint, evadible; la firma robusta sigue siendo el agregado,
  HALLAZGO 8). **Lección:** no basta con que generalice; hay que ver *por qué* — solo el web es
  robusto, SSH/DoS son fingerprints evadibles → refuerza que la robustez exige combinar vistas.

### Puntos 3/4/6 — Robustez, no supervisado y rigor (sin datos nuevos) · agosto

- **7-ago (HALLAZGO 11, evasión):** [evasion_test.py](scripts/zeek/evasion_test.py) — camuflando
  los primeros bytes (banner/petición), el recall del payload se desploma (**SSH 1.0→0.35, DoS
  0.72→0.43**) mientras la **conducta meta+ráfaga es invariante (~1.0)**: prueba activa de que las
  firmas de payload son *fingerprints* evadibles y la conductual no.
- **7-ago (HALLAZGO 12, no supervisado/zero-day):** [anomaly_detection.py](scripts/zeek/anomaly_detection.py)
  — entrenando **solo con benigno** (IsolationForest/autoencoder), ROC-AUC: web payload≤0.79 y
  meta+ráfaga 0.91; **SSH payload 0.57 (falla) pero ráfaga 1.0**; **DoS el más duro** (todo ≤0.54,
  un GET de Hulk es más normal que el benigno). Replica la tesis sin etiquetas; el zero-day
  volumétrico es intrínsecamente difícil.
- **7-ago (Punto 6, rigor):** [rigor_metrics.py](scripts/zeek/rigor_metrics.py) — ROC/PR-AUC con
  **IC 95% bootstrap** + curvas PNG. Web/SSH ~1.0 (IC estrechos), DoS 0.68–0.84 (bien acotado).
  Resúmenes `models/phase2_{evasion,anomaly,rigor}_*.md` (+`.png`).

**Pendiente:** Punto 2 (estado del arte, a la señal del autor); (opcional) más días/datasets del
plan (DDoS, UNSW-NB15, Malware-Traffic) y Eje E (`conn.log`) — requieren descargas o retorno
marginal; memoria LaTeX (al cierre, bajo orden explícita).

---

## 3. Los 8 hallazgos clave

1. **Ataques sin payload:** FTP-BruteForce (REJ) y DoS-SlowHTTPTest (:21) dejan **0 bytes
   analizables** → invisibles al payload. Solo detectables por flujo/`conn.log`.
2. **Pérdida silenciosa de datos:** Zeek se cortaba en un record intermedio; **sanear el
   PCAP antes** es obligatorio (se perdía la tarde entera del SSH).
3. **El 99,96% es un espejismo:** con benigno diverso el modelo separa "protocolo", no
   "ataque"; sobre SSH benigno real da 96% de falsos positivos.
4. **En payload EN CLARO el payload gana:** el web invierte el SSH (payload 0.99 vs
   metadata 0.93). Cada vista gana en su régimen; solo el híbrido es robusto en ambos.
5. **El byte-CNN es el modelo más fuerte:** la convolución aprende n-gramas de bytes;
   gana en detección y en identificar el *tipo* de ataque.
6. **La fusión bien hecha (dos ramas) es robusta:** ~1.0 en claro y en cifrado; corrige
   la dilución de concatenar vistas a ciegas.
7. **El "éxito" del payload sobre el cifrado es un fingerprint** del cliente (banner
   `paramiko`), señal real pero **evadible**; la firma robusta es conductual.
8. **La firma del DoS es volumétrica:** per-flujo nada sirve (un GET de Hulk ≈ un GET
   benigno); solo el **volumen agregado por origen** (ráfaga) lo separa (0.81).

---

## 4. Datos

### Días del dataset CSE-CIC-IDS2018 usados

| Día (carpeta) | Ataque | Régimen | Flujos con payload | Estado en disco |
|---------------|--------|---------|-------------------:|-----------------|
| `Wednesday-14-02-2018` | FTP/SSH-Bruteforce | cifrado | 2.202.231 (94.207 SSH) | `.npz`+`meta` (PCAP/TSV borrados) |
| `Thursday-22-02-2018` | Web (BF/XSS/SQLi) | en claro | 2.777.898 (203 ataque) | `.npz`+`meta` (PCAP/TSV borrados) |
| `Friday-16-02-2018` | DoS-Hulk / SlowHTTPTest | volumétrico | 4.041.078 (1.062.339 Hulk) | `.npz`+`meta` (PCAP/TSV borrados) |

- **CSV originales** (Fase 1, metadatos de flujo de CICFlowMeter): `data/raw/*.csv`
  (14-02, 15-02, 16-02, 22-02). **No contienen IPs** → por eso el etiquetado del payload
  es por ground-truth, no por join.
- **Patrón de disco:** tras vectorizar un día a `dataset_<dia>.npz` (~1 GB, autocontenido:
  histograma/secuencia/entropía/5-tupla/`ts`/label por flujo) + `_meta.csv`, se **borran
  su PCAP crudo y TSV** (re-derivables desde S3+Zeek). El `_meta.csv` permite derivar
  features (p. ej. ráfaga) sin re-leer los TSV.

### Ground-truth verificada (empíricamente, no de la doc)

| Día | Ataque | Atacante → Víctima:puerto | Ventana (local −4) |
|-----|--------|---------------------------|--------------------|
| 14-02 | FTP-BruteForce | `18.221.219.4` → `172.31.69.25:21` | 10:32–12:09 |
| 14-02 | SSH-Bruteforce | `13.58.98.64` → `172.31.69.25:22` | 14:01–15:33 |
| 22-02 | Web BF/XSS/SQLi | `18.218.115.60` → `172.31.69.28:80` | 10:13 / 13:50 / 16:10 |
| 16-02 | DoS-Hulk | `18.219.193.20` → `172.31.69.25:80` | 13:45–13:53 |
| 16-02 | DoS-SlowHTTPTest | `13.59.126.31` → `172.31.69.25:21` | 10:12–11:06 |

---

## 5. Inventario de archivos

### `scripts/zeek/` — Pipeline (extracción, vectorización, evaluación)

**Extracción y datos:**
- [extract_payload.zeek](scripts/zeek/extract_payload.zeek) — script Zeek: una fila TSV por
  paquete TCP con datos (`uid`, `ts`, 5-tupla, `dir`, `len`, `payload_hex`).
- [run_zeek_payload.py](scripts/zeek/run_zeek_payload.py) — orquestador Python+Docker;
  recorre los PCAP del día, sanea cada captura y lanza Zeek. Soporta pcapng.
- [repair_pcap.py](scripts/zeek/repair_pcap.py) — sanea PCAP (solo records válidos);
  `is_pcapng()` detecta pcapng (Zeek los lee nativamente).
- [decode_payload.py](scripts/zeek/decode_payload.py) — vuelca el payload en texto/hexdump
  para inspección (filtra por puerto/dirección).
- [build_dataset.py](scripts/zeek/build_dataset.py) — vectoriza los TSV a `dataset_<dia>.npz`
  (histograma 256 + entropía + secuencia 256 B) y etiqueta cada flujo.
- [attack_metadata.py](scripts/zeek/attack_metadata.py) — ground-truth por día (IPs,
  puertos, ventanas, `tz_offset`). Extensible con `--day`.
- [relabel_dataset.py](scripts/zeek/relabel_dataset.py) — re-etiqueta el `.npz` existente
  con la 5-tupla/`ts` **sin re-leer los TSV** (al corregir la ground-truth).

**Localización de atacantes:**
- [find_host.py](scripts/zeek/find_host.py) — barrido binario: en qué capturas aparece una
  **IP conocida** (sin procesar los GB).
- [find_attacker.py](scripts/zeek/find_attacker.py) — top-talkers del `conn.log`: revela al
  atacante **sin IP previa** (útil en DoS/DDoS, donde domina el ranking).

**Modelos shallow (Fase 2, MLP scikit-learn):**
- [train_phase2.py](scripts/zeek/train_phase2.py) — dos MLP (histograma y secuencia),
  balanceo + CV + test. Primer modelo (el del espejismo 0.9996).
- [honest_check.py](scripts/zeek/honest_check.py) — audita sobre el benigno del **mismo
  servicio cifrado** (destapa el HALLAZGO 3).
- [hybrid_compare.py](scripts/zeek/hybrid_compare.py) — payload vs metadatos vs híbrido
  (balanceo global). Define `load_dataset` y `build_meta_features` (reutilizados).
- [honest_by_service.py](scripts/zeek/honest_by_service.py) — balanceo **1:1 por servicio**
  (SSH-ataque vs SSH-benigno); métrica realista del caso difícil.
- [honest_by_service_rich.py](scripts/zeek/honest_by_service_rich.py) — añade la feature de
  **ráfaga**; separa benigno limpio vs contaminado (17-jun).
- [honest_by_service_web.py](scripts/zeek/honest_by_service_web.py) — espejo del SSH sobre
  HTTP:80 (HALLAZGO 4).
- [multitype_web.py](scripts/zeek/multitype_web.py) — clasificación **multi-tipo** web
  (BF/XSS/SQLi); solo la secuencia identifica el tipo.

**Deep learning (Fase 3, PyTorch):**
- [dl_models.py](scripts/zeek/dl_models.py) — `ByteCNN` (multi-kernel 3/5/7) y `ByteLSTM`
  + bucle de entrenamiento y predicción out-of-fold.
- [train_dl_payload.py](scripts/zeek/train_dl_payload.py) — **Eje A**: CNN/LSTM vs
  baselines (`--task binary|multitype`, `--cap` para días masivos).
- [train_dl_hybrid.py](scripts/zeek/train_dl_hybrid.py) — **Eje B**: híbrido de dos ramas
  (CNN payload + MLP metadatos, fusión tardía).
- [eval_saliency.py](scripts/zeek/eval_saliency.py) — **Eje D**: saliency (|gradiente|) que
  explica el banner `paramiko` (HALLAZGO 7).
- [dos_burst.py](scripts/zeek/dos_burst.py) — **Eje C**: payload vs meta vs **meta+ráfaga**
  sobre el DoS (HALLAZGO 8).

### `notebooks/` — Fase 1

- `01_exploration.ipynb` — exploración, limpieza y baseline binario (fuga de datos).
- `02_multiclass_benchmark.ipynb` — benchmark multiclase + prueba de robustez (Slowloris).

### `models/` — Resúmenes autogenerados (`.md`) y modelos (`.joblib`/`.png`, no versionados)

- `phase2_results.md` — primer modelo (espejismo 0.9996).
- `phase2_hybrid_compare.md`, `phase2_by_service.md`, `phase2_by_service_rich.md` — SSH.
- `phase2_by_service_web.md`, `phase2_multitype_web.md` — web.
- `phase2_dl_*.md`, `phase2_dlhybrid_*.md` — DL Ejes A/B por día y tarea.
- `phase2_saliency_ssh.md` (+`.png`) — interpretabilidad.
- `phase2_dos_burst_Friday-16-02-2018.md` — DoS volumétrico (Eje C).

---

## 6. Pipeline (de PCAP a resultado)

```text
PCAP  --run_zeek_payload.py (sanea + Zeek/Docker)-->  <pcap>.payload.tsv   (payload por paquete)
      --build_dataset.py (+ attack_metadata.py)  -->  dataset_<dia>.npz + _meta.csv   (flujos vectorizados + etiqueta)
      --train_*.py / honest_*.py / dos_burst.py  -->  models/phase2_*.md   (métricas out-of-fold)
```

Cada flujo (agrupado por `uid`) → `X_hist` (256), `entropy`, `X_seq` (256 B), escalares
(`n_pkts`, `tot_bytes`, `seq_len`), 5-tupla, `ts` y `label`.

---

## 7. Entorno y gotchas

- **Entorno:** conda `tfg_ia`. Ejecutar con `conda run -n tfg_ia python scripts/zeek/<x>.py`.
- **Gotcha:** `conda run ... python -c "..."` (multilínea) **falla**; usar ficheros `.py`.
  El log de `conda run` **no hace streaming** (se vuelca al final).
- **Docker:** arrancar Docker Desktop antes de Zeek; imagen `zeek/zeek` ya presente.
- **Días masivos (DoS, 4 M flujos):** los `train_dl_*.py` no materializan las vistas
  completas (evita OOM con 16 GB RAM) y aceptan `--cap N` (subsampleo por clase).
- **Disco:** patrón vectorizar → borrar PCAP+TSV, conservar `.npz`+`meta`.
- **DL:** no dejar `.py` con nombres de stdlib en el cwd (hacen shadow y rompen torch).

---

*Documento de resumen — ver [README.md](README.md) para el diario completo y fechado.*

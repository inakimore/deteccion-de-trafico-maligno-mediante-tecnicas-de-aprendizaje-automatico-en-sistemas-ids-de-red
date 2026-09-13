# Atributos del payload (literatura) + caracteristicas de Zeek (Thursday-22-02-2018)

Subconjunto: **servicio=http (DPI)**. Balanceo 1:1 Attack/Benign (203 ataque / 459,743 benigno disponibles; 406 flujos usados tras balanceo y `--cap`).
MLP 256→128 con StandardScaler, 5-Fold CV estratificada + test held-out (20%).

Responde al punto 1b de la revision del tutor: extraer atributos concretos del
payload (entropia y los de la literatura) y **unirlos** a las caracteristicas
obtenidas con Zeek, en lugar de dejar la entropia como un escalar suelto dentro
del histograma de 256 dimensiones.

| Vista | nº features | CV accuracy | Test acc | F1 ataque |
|-------|-------------|-------------|----------|-----------|
| `payload-attrs` | 19 | 0.9606 ± 0.0093 | 0.9512 | 0.9535 |
| `payload-hist` | 257 | 0.9753 ± 0.0221 | 0.9878 | 0.9880 |
| `zeek-meta` | 7 | 0.9926 ± 0.0060 | 0.9878 | 0.9880 |
| `zeek+attrs` | 26 | 0.9877 ± 0.0078 | 0.9756 | 0.9762 |
| `zeek+hist` | 264 | 0.9877 ± 0.0001 | 0.9634 | 0.9647 |

## Atributos del payload: media por clase

Los 19 descriptores son interpretables uno a uno, a diferencia del histograma
de 256 dimensiones. Origen bibliografico de cada familia en `payload_features.py`.

| Atributo | Ataque (media) | Benigno (media) | Δ |
|----------|----------------|-----------------|---|
| `entropy_norm` | 0.8266 | 0.7528 | +0.0739 |
| `distinct_ratio` | 0.7479 | 0.5118 | +0.2361 |
| `max_freq` | 0.0514 | 0.0636 | -0.0122 |
| `top4_mass` | 0.1551 | 0.1988 | -0.0437 |
| `mean_byte` | 0.3632 | 0.3172 | +0.0460 |
| `std_byte` | 0.3814 | 0.3426 | +0.0389 |
| `l1_uniform` | 0.5330 | 0.6453 | -0.1123 |
| `chi2_uniform` | 0.5888 | 0.6338 | -0.0450 |
| `coincidence_idx` | 0.0133 | 0.0206 | -0.0073 |
| `compress_ratio` | 0.4177 | 0.4113 | +0.0063 |
| `bigram_entropy_norm` | 0.4599 | 0.4537 | +0.0062 |
| `bigram_distinct` | 0.7243 | 0.7011 | +0.0232 |
| `printable_ratio` | 0.8275 | 0.8824 | -0.0548 |
| `alnum_ratio` | 0.6171 | 0.6316 | -0.0146 |
| `ctrl_ratio` | 0.0344 | 0.0433 | -0.0089 |
| `high_ratio` | 0.1371 | 0.0739 | +0.0633 |
| `null_ratio` | 0.0034 | 0.0051 | -0.0017 |
| `longest_print_run` | 1.0000 | 1.0000 | +0.0000 |
| `transition_rate` | 0.0000 | 0.0000 | +0.0000 |

## Importancia por permutacion en la vista `zeek+attrs`

Caida de accuracy en el test held-out al permutar cada atributo (media ± desv.
sobre 5 repeticiones). Mide que aporta cada bloque en la union payload+Zeek.

| Atributo | Importancia | ± |
|----------|-------------|---|
| `bytes_per_pkt` | +0.0659 | 0.0098 |
| `bigram_entropy_norm` | +0.0537 | 0.0124 |
| `n_pkts` | +0.0390 | 0.0091 |
| `std_byte` | +0.0341 | 0.0142 |
| `burst_1s` | +0.0293 | 0.0124 |
| `ctrl_ratio` | +0.0244 | 0.0204 |
| `burst_30s` | +0.0146 | 0.0091 |
| `burst_5s` | +0.0146 | 0.0091 |
| `bigram_distinct` | +0.0049 | 0.0060 |
| `alnum_ratio` | +0.0049 | 0.0098 |
| `chi2_uniform` | +0.0024 | 0.0119 |
| `null_ratio` | +0.0024 | 0.0049 |
| `coincidence_idx` | +0.0000 | 0.0000 |
| `entropy_norm` | +0.0000 | 0.0000 |
| `distinct_ratio` | +0.0000 | 0.0000 |


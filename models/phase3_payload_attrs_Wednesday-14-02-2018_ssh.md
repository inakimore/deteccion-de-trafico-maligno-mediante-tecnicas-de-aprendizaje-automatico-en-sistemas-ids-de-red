# Atributos del payload (literatura) + caracteristicas de Zeek (Wednesday-14-02-2018)

Subconjunto: **servicio=ssh (DPI)**. Balanceo 1:1 Attack/Benign (94,207 ataque / 358 benigno disponibles; 716 flujos usados tras balanceo y `--cap`).
MLP 256→128 con StandardScaler, 5-Fold CV estratificada + test held-out (20%).

Responde al punto 1b de la revision del tutor: extraer atributos concretos del
payload (entropia y los de la literatura) y **unirlos** a las caracteristicas
obtenidas con Zeek, en lugar de dejar la entropia como un escalar suelto dentro
del histograma de 256 dimensiones.

| Vista | nº features | CV accuracy | Test acc | F1 ataque |
|-------|-------------|-------------|----------|-----------|
| `payload-attrs` | 19 | 0.9833 ± 0.0122 | 1.0000 | 1.0000 |
| `payload-hist` | 257 | 0.9847 ± 0.0142 | 0.9931 | 0.9931 |
| `zeek-meta` | 7 | 0.9986 ± 0.0028 | 1.0000 | 1.0000 |
| `zeek+attrs` | 26 | 0.9958 ± 0.0056 | 1.0000 | 1.0000 |
| `zeek+hist` | 264 | 0.9819 ± 0.0113 | 1.0000 | 1.0000 |

## Atributos del payload: media por clase

Los 19 descriptores son interpretables uno a uno, a diferencia del histograma
de 256 dimensiones. Origen bibliografico de cada familia en `payload_features.py`.

| Atributo | Ataque (media) | Benigno (media) | Δ |
|----------|----------------|-----------------|---|
| `entropy_norm` | 0.9223 | 0.8282 | +0.0941 |
| `distinct_ratio` | 1.0000 | 0.9149 | +0.0851 |
| `max_freq` | 0.0376 | 0.0544 | -0.0168 |
| `top4_mass` | 0.1309 | 0.1911 | -0.0602 |
| `mean_byte` | 0.4239 | 0.3848 | +0.0391 |
| `std_byte` | 0.5264 | 0.4593 | +0.0671 |
| `l1_uniform` | 0.3235 | 0.5072 | -0.1837 |
| `chi2_uniform` | 0.5476 | 0.6214 | -0.0738 |
| `coincidence_idx` | 0.0066 | 0.0172 | -0.0105 |
| `compress_ratio` | 0.3580 | 0.3728 | -0.0148 |
| `bigram_entropy_norm` | 0.4321 | 0.4337 | -0.0017 |
| `bigram_distinct` | 0.5768 | 0.5986 | -0.0218 |
| `printable_ratio` | 0.5757 | 0.6945 | -0.1187 |
| `alnum_ratio` | 0.4282 | 0.5430 | -0.1148 |
| `ctrl_ratio` | 0.1142 | 0.1043 | +0.0099 |
| `high_ratio` | 0.3074 | 0.1997 | +0.1077 |
| `null_ratio` | 0.0376 | 0.0501 | -0.0125 |
| `longest_print_run` | 0.5513 | 0.5691 | -0.0178 |
| `transition_rate` | 0.0536 | 0.0550 | -0.0014 |

## Importancia por permutacion en la vista `zeek+attrs`

Caida de accuracy en el test held-out al permutar cada atributo (media ± desv.
sobre 5 repeticiones). Mide que aporta cada bloque en la union payload+Zeek.

| Atributo | Importancia | ± |
|----------|-------------|---|
| `transition_rate` | +0.0056 | 0.0028 |
| `burst_30s` | +0.0042 | 0.0034 |
| `bytes_per_pkt` | +0.0000 | 0.0000 |
| `n_pkts` | +0.0000 | 0.0000 |
| `seq_len` | +0.0000 | 0.0000 |
| `burst_1s` | +0.0000 | 0.0000 |
| `burst_5s` | +0.0000 | 0.0000 |
| `tot_bytes` | +0.0000 | 0.0000 |
| `distinct_ratio` | +0.0000 | 0.0000 |
| `max_freq` | +0.0000 | 0.0000 |
| `top4_mass` | +0.0000 | 0.0000 |
| `mean_byte` | +0.0000 | 0.0000 |
| `std_byte` | +0.0000 | 0.0000 |
| `l1_uniform` | +0.0000 | 0.0000 |
| `chi2_uniform` | +0.0000 | 0.0000 |


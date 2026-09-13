# Atributos del payload (literatura) + caracteristicas de Zeek (Friday-16-02-2018)

Subconjunto: **servicio=http (DPI)**. Balanceo 1:1 Attack/Benign (1,803,160 ataque / 396,977 benigno disponibles; 8,000 flujos usados tras balanceo y `--cap`).
MLP 256→128 con StandardScaler, 5-Fold CV estratificada + test held-out (20%).

Responde al punto 1b de la revision del tutor: extraer atributos concretos del
payload (entropia y los de la literatura) y **unirlos** a las caracteristicas
obtenidas con Zeek, en lugar de dejar la entropia como un escalar suelto dentro
del histograma de 256 dimensiones.

| Vista | nº features | CV accuracy | Test acc | F1 ataque |
|-------|-------------|-------------|----------|-----------|
| `payload-attrs` | 19 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 |
| `payload-hist` | 257 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 |
| `zeek-meta` | 7 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 |
| `zeek+attrs` | 26 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 |
| `zeek+hist` | 264 | 1.0000 ± 0.0000 | 1.0000 | 1.0000 |

## Atributos del payload: media por clase

Los 19 descriptores son interpretables uno a uno, a diferencia del histograma
de 256 dimensiones. Origen bibliografico de cada familia en `payload_features.py`.

| Atributo | Ataque (media) | Benigno (media) | Δ |
|----------|----------------|-----------------|---|
| `entropy_norm` | 0.6966 | 0.7492 | -0.0527 |
| `distinct_ratio` | 0.3136 | 0.4933 | -0.1797 |
| `max_freq` | 0.0689 | 0.0653 | +0.0036 |
| `top4_mass` | 0.2236 | 0.1991 | +0.0245 |
| `mean_byte` | 0.2977 | 0.3174 | -0.0197 |
| `std_byte` | 0.2425 | 0.3380 | -0.0955 |
| `l1_uniform` | 0.7369 | 0.6502 | +0.0868 |
| `chi2_uniform` | 0.6665 | 0.6328 | +0.0336 |
| `coincidence_idx` | 0.0248 | 0.0212 | +0.0036 |
| `compress_ratio` | 0.4394 | 0.4127 | +0.0268 |
| `bigram_entropy_norm` | 0.4637 | 0.4538 | +0.0100 |
| `bigram_distinct` | 0.7592 | 0.7018 | +0.0574 |
| `printable_ratio` | 1.0000 | 0.8856 | +0.1144 |
| `alnum_ratio` | 0.6331 | 0.6298 | +0.0033 |
| `ctrl_ratio` | 0.0000 | 0.0415 | -0.0415 |
| `high_ratio` | 0.0000 | 0.0724 | -0.0724 |
| `null_ratio` | 0.0000 | 0.0054 | -0.0054 |
| `longest_print_run` | 1.0000 | 0.9997 | +0.0003 |
| `transition_rate` | 0.0000 | 0.0001 | -0.0001 |

## Importancia por permutacion en la vista `zeek+attrs`

Caida de accuracy en el test held-out al permutar cada atributo (media ± desv.
sobre 5 repeticiones). Mide que aporta cada bloque en la union payload+Zeek.

| Atributo | Importancia | ± |
|----------|-------------|---|
| `alnum_ratio` | +0.0014 | 0.0005 |
| `burst_30s` | +0.0009 | 0.0006 |
| `bytes_per_pkt` | +0.0006 | 0.0007 |
| `n_pkts` | +0.0006 | 0.0004 |
| `longest_print_run` | +0.0005 | 0.0002 |
| `transition_rate` | +0.0005 | 0.0002 |
| `mean_byte` | +0.0002 | 0.0003 |
| `max_freq` | +0.0002 | 0.0003 |
| `ctrl_ratio` | +0.0002 | 0.0003 |
| `null_ratio` | +0.0002 | 0.0003 |
| `burst_5s` | +0.0001 | 0.0002 |
| `distinct_ratio` | +0.0000 | 0.0000 |
| `entropy_norm` | +0.0000 | 0.0000 |
| `burst_1s` | +0.0000 | 0.0000 |
| `seq_len` | +0.0000 | 0.0000 |


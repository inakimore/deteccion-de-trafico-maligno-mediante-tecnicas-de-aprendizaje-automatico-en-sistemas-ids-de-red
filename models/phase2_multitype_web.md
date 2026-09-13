# Fase 2 - Clasificacion MULTI-TIPO del ataque web (Thursday-22-02-2018)

Solo flujos de ataque (puerto 80), problema de 3 clases: distinguir el TIPO
de ataque web. Flujos: 142 `Brute Force -Web`, 42 `Brute Force -XSS`, 19 `SQL Injection` (total 203).

Resultado (honesto, con matiz): quien identifica el tipo es la REPRESENTACION
SECUENCIAL del payload en claro (payload-seq, macro-F1 0.95), no el histograma
de bytes (0.75) ni la metadata de flujo (0.77). El histograma difumina los
tokens (`<script>` y `union select` tienen distribuciones de bytes parecidas) y
la metadata solo separa por volumen (falla en SQL Injection, recall 0.26); solo
la secuencia captura los tokens caracteristicos e identifica los 3 tipos,
incluido SQLi. Leccion: para identificar el TIPO no basta el payload en claro,
hace falta la representacion adecuada (secuencia/tokens, no histograma).

Predicciones out-of-fold (5-Fold Stratified, sin fuga); N pequeno (ataque de
bajo volumen, SQLi solo 19 flujos). Clases: `[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]`. MLP 256->128.

| Vista | Macro-F1 (out-of-fold) |
|-------|------------------------|
| payload-hist | 0.7462 |
| payload-seq | 0.9505 |
| metadatos | 0.7695 |

## payload-hist

- **Macro-F1 (out-of-fold):** 0.7462

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9648    0.9648    0.9648       142
Brute Force -XSS     0.7500    1.0000    0.8571        42
   SQL Injection     1.0000    0.2632    0.4167        19

        accuracy                         0.9064       203
       macro avg     0.9049    0.7426    0.7462       203
    weighted avg     0.9236    0.9064    0.8912       203

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[137   5   0]
 [  0  42   0]
 [  5   9   5]]
```

## payload-seq

- **Macro-F1 (out-of-fold):** 0.9505

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9859    0.9859    0.9859       142
Brute Force -XSS     0.9545    1.0000    0.9767        42
   SQL Injection     0.9412    0.8421    0.8889        19

        accuracy                         0.9754       203
       macro avg     0.9605    0.9427    0.9505       203
    weighted avg     0.9752    0.9754    0.9749       203

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[140   1   1]
 [  0  42   0]
 [  2   1  16]]
```

## metadatos

- **Macro-F1 (out-of-fold):** 0.7695

```
                  precision    recall  f1-score   support

Brute Force -Web     0.8974    0.9859    0.9396       142
Brute Force -XSS     0.9524    0.9524    0.9524        42
   SQL Injection     1.0000    0.2632    0.4167        19

        accuracy                         0.9113       203
       macro avg     0.9499    0.7338    0.7695       203
    weighted avg     0.9184    0.9113    0.8933       203

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[140   2   0]
 [  2  40   0]
 [ 14   0   5]]
```

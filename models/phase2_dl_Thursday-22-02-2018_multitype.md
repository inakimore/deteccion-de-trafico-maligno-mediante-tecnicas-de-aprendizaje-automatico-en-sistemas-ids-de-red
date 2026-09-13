# Fase 3 (Eje A) - Deep learning sobre bytes: tipo de ataque (multiclase) (Thursday-22-02-2018)

Tarea `multitype`. Flujos: 142 `Brute Force -Web`, 42 `Brute Force -XSS`, 19 `SQL Injection` (total 203).
Clases: `[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 0.9852 | 0.9679 |
| byte-LSTM (torch) | 0.8030 | 0.4859 |
| mlp-seq (sklearn) | 0.9754 | 0.9505 |
| mlp-hist (sklearn) | 0.9064 | 0.7462 |
| metadatos (sklearn) | 0.9113 | 0.7695 |

## byte-CNN (torch)

- **Accuracy:** 0.9852 | **Macro-F1:** 0.9679

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9793    1.0000    0.9895       142
Brute Force -XSS     1.0000    1.0000    1.0000        42
   SQL Injection     1.0000    0.8421    0.9143        19

        accuracy                         0.9852       203
       macro avg     0.9931    0.9474    0.9679       203
    weighted avg     0.9855    0.9852    0.9847       203

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[142   0   0]
 [  0  42   0]
 [  3   0  16]]
```

## byte-LSTM (torch)

- **Accuracy:** 0.8030 | **Macro-F1:** 0.4859

```
                  precision    recall  f1-score   support

Brute Force -Web     0.8503    1.0000    0.9191       142
Brute Force -XSS     0.5833    0.5000    0.5385        42
   SQL Injection     0.0000    0.0000    0.0000        19

        accuracy                         0.8030       203
       macro avg     0.4779    0.5000    0.4859       203
    weighted avg     0.7155    0.8030    0.7543       203

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[142   0   0]
 [ 21  21   0]
 [  4  15   0]]
```

## mlp-seq (sklearn)

- **Accuracy:** 0.9754 | **Macro-F1:** 0.9505

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

## mlp-hist (sklearn)

- **Accuracy:** 0.9064 | **Macro-F1:** 0.7462

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

## metadatos (sklearn)

- **Accuracy:** 0.9113 | **Macro-F1:** 0.7695

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

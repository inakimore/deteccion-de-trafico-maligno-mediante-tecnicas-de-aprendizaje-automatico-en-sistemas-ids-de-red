# Fase 3 (Eje A) - Deep learning sobre bytes: ataque vs benigno por servicio (Tuesday-20-02-2018)

Tarea `binary`. Flujos: 4000 `Attack`, 4000 `Benign` (total 8000).
Clases: `[np.str_('Attack'), np.str_('Benign')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 1.0000 | 1.0000 |
| byte-LSTM (torch) | 1.0000 | 1.0000 |
| mlp-seq (sklearn) | 1.0000 | 1.0000 |
| mlp-hist (sklearn) | 1.0000 | 1.0000 |
| metadatos (sklearn) | 0.9985 | 0.9985 |

## byte-CNN (torch)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000      4000
      Benign     1.0000    1.0000    1.0000      4000

    accuracy                         1.0000      8000
   macro avg     1.0000    1.0000    1.0000      8000
weighted avg     1.0000    1.0000    1.0000      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   0 4000]]
```

## byte-LSTM (torch)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000      4000
      Benign     1.0000    1.0000    1.0000      4000

    accuracy                         1.0000      8000
   macro avg     1.0000    1.0000    1.0000      8000
weighted avg     1.0000    1.0000    1.0000      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   0 4000]]
```

## mlp-seq (sklearn)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000      4000
      Benign     1.0000    1.0000    1.0000      4000

    accuracy                         1.0000      8000
   macro avg     1.0000    1.0000    1.0000      8000
weighted avg     1.0000    1.0000    1.0000      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   0 4000]]
```

## mlp-hist (sklearn)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000      4000
      Benign     1.0000    1.0000    1.0000      4000

    accuracy                         1.0000      8000
   macro avg     1.0000    1.0000    1.0000      8000
weighted avg     1.0000    1.0000    1.0000      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   0 4000]]
```

## metadatos (sklearn)

- **Accuracy:** 0.9985 | **Macro-F1:** 0.9985

```
              precision    recall  f1-score   support

      Attack     0.9970    1.0000    0.9985      4000
      Benign     1.0000    0.9970    0.9985      4000

    accuracy                         0.9985      8000
   macro avg     0.9985    0.9985    0.9985      8000
weighted avg     0.9985    0.9985    0.9985      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [  12 3988]]
```

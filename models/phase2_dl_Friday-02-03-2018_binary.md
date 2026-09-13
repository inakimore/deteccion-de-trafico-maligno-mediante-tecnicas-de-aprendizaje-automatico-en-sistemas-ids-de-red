# Fase 3 (Eje A) - Deep learning sobre bytes: ataque vs benigno por servicio (Friday-02-03-2018)

Tarea `binary`. Flujos: 4000 `Attack`, 4000 `Benign` (total 8000).
Clases: `[np.str_('Attack'), np.str_('Benign')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 1.0000 | 1.0000 |
| byte-LSTM (torch) | 0.9999 | 0.9999 |
| mlp-seq (sklearn) | 1.0000 | 1.0000 |
| mlp-hist (sklearn) | 0.9992 | 0.9992 |
| metadatos (sklearn) | 0.9986 | 0.9986 |

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

- **Accuracy:** 0.9999 | **Macro-F1:** 0.9999

```
              precision    recall  f1-score   support

      Attack     0.9998    1.0000    0.9999      4000
      Benign     1.0000    0.9998    0.9999      4000

    accuracy                         0.9999      8000
   macro avg     0.9999    0.9999    0.9999      8000
weighted avg     0.9999    0.9999    0.9999      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   1 3999]]
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

- **Accuracy:** 0.9992 | **Macro-F1:** 0.9992

```
              precision    recall  f1-score   support

      Attack     0.9995    0.9990    0.9992      4000
      Benign     0.9990    0.9995    0.9993      4000

    accuracy                         0.9992      8000
   macro avg     0.9993    0.9992    0.9992      8000
weighted avg     0.9993    0.9992    0.9992      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[3996    4]
 [   2 3998]]
```

## metadatos (sklearn)

- **Accuracy:** 0.9986 | **Macro-F1:** 0.9986

```
              precision    recall  f1-score   support

      Attack     0.9987    0.9985    0.9986      4000
      Benign     0.9985    0.9988    0.9986      4000

    accuracy                         0.9986      8000
   macro avg     0.9986    0.9986    0.9986      8000
weighted avg     0.9986    0.9986    0.9986      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[3994    6]
 [   5 3995]]
```

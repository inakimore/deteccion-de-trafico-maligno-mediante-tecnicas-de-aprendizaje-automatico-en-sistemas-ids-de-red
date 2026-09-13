# Fase 3 (Eje A) - Deep learning sobre bytes: ataque vs benigno por servicio (Thursday-22-02-2018)

Tarea `binary`. Flujos: 203 `Attack`, 203 `Benign` (total 406).
Clases: `[np.str_('Attack'), np.str_('Benign')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 1.0000 | 1.0000 |
| byte-LSTM (torch) | 0.9951 | 0.9951 |
| mlp-seq (sklearn) | 0.9754 | 0.9754 |
| mlp-hist (sklearn) | 0.9901 | 0.9901 |
| metadatos (sklearn) | 0.9187 | 0.9184 |

## byte-CNN (torch)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000       203
      Benign     1.0000    1.0000    1.0000       203

    accuracy                         1.0000       406
   macro avg     1.0000    1.0000    1.0000       406
weighted avg     1.0000    1.0000    1.0000       406

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[203   0]
 [  0 203]]
```

## byte-LSTM (torch)

- **Accuracy:** 0.9951 | **Macro-F1:** 0.9951

```
              precision    recall  f1-score   support

      Attack     0.9951    0.9951    0.9951       203
      Benign     0.9951    0.9951    0.9951       203

    accuracy                         0.9951       406
   macro avg     0.9951    0.9951    0.9951       406
weighted avg     0.9951    0.9951    0.9951       406

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[202   1]
 [  1 202]]
```

## mlp-seq (sklearn)

- **Accuracy:** 0.9754 | **Macro-F1:** 0.9754

```
              precision    recall  f1-score   support

      Attack     0.9849    0.9655    0.9751       203
      Benign     0.9662    0.9852    0.9756       203

    accuracy                         0.9754       406
   macro avg     0.9756    0.9754    0.9754       406
weighted avg     0.9756    0.9754    0.9754       406

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[196   7]
 [  3 200]]
```

## mlp-hist (sklearn)

- **Accuracy:** 0.9901 | **Macro-F1:** 0.9901

```
              precision    recall  f1-score   support

      Attack     0.9807    1.0000    0.9902       203
      Benign     1.0000    0.9803    0.9900       203

    accuracy                         0.9901       406
   macro avg     0.9903    0.9901    0.9901       406
weighted avg     0.9903    0.9901    0.9901       406

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[203   0]
 [  4 199]]
```

## metadatos (sklearn)

- **Accuracy:** 0.9187 | **Macro-F1:** 0.9184

```
              precision    recall  f1-score   support

      Attack     0.8728    0.9803    0.9234       203
      Benign     0.9775    0.8571    0.9134       203

    accuracy                         0.9187       406
   macro avg     0.9252    0.9187    0.9184       406
weighted avg     0.9252    0.9187    0.9184       406

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[199   4]
 [ 29 174]]
```

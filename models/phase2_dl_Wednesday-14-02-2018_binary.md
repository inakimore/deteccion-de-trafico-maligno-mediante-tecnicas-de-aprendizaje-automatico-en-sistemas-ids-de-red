# Fase 3 (Eje A) - Deep learning sobre bytes: ataque vs benigno por servicio (Wednesday-14-02-2018)

Tarea `binary`. Flujos: 433 `Attack`, 433 `Benign` (total 866).
Clases: `[np.str_('Attack'), np.str_('Benign')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 0.9988 | 0.9988 |
| byte-LSTM (torch) | 0.9988 | 0.9988 |
| mlp-seq (sklearn) | 0.9988 | 0.9988 |
| mlp-hist (sklearn) | 0.9896 | 0.9896 |
| metadatos (sklearn) | 0.9931 | 0.9931 |

## byte-CNN (torch)

- **Accuracy:** 0.9988 | **Macro-F1:** 0.9988

```
              precision    recall  f1-score   support

      Attack     0.9977    1.0000    0.9988       433
      Benign     1.0000    0.9977    0.9988       433

    accuracy                         0.9988       866
   macro avg     0.9988    0.9988    0.9988       866
weighted avg     0.9988    0.9988    0.9988       866

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  1 432]]
```

## byte-LSTM (torch)

- **Accuracy:** 0.9988 | **Macro-F1:** 0.9988

```
              precision    recall  f1-score   support

      Attack     0.9977    1.0000    0.9988       433
      Benign     1.0000    0.9977    0.9988       433

    accuracy                         0.9988       866
   macro avg     0.9988    0.9988    0.9988       866
weighted avg     0.9988    0.9988    0.9988       866

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  1 432]]
```

## mlp-seq (sklearn)

- **Accuracy:** 0.9988 | **Macro-F1:** 0.9988

```
              precision    recall  f1-score   support

      Attack     0.9977    1.0000    0.9988       433
      Benign     1.0000    0.9977    0.9988       433

    accuracy                         0.9988       866
   macro avg     0.9988    0.9988    0.9988       866
weighted avg     0.9988    0.9988    0.9988       866

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  1 432]]
```

## mlp-hist (sklearn)

- **Accuracy:** 0.9896 | **Macro-F1:** 0.9896

```
              precision    recall  f1-score   support

      Attack     0.9796    1.0000    0.9897       433
      Benign     1.0000    0.9792    0.9895       433

    accuracy                         0.9896       866
   macro avg     0.9898    0.9896    0.9896       866
weighted avg     0.9898    0.9896    0.9896       866

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  9 424]]
```

## metadatos (sklearn)

- **Accuracy:** 0.9931 | **Macro-F1:** 0.9931

```
              precision    recall  f1-score   support

      Attack     0.9863    1.0000    0.9931       433
      Benign     1.0000    0.9861    0.9930       433

    accuracy                         0.9931       866
   macro avg     0.9932    0.9931    0.9931       866
weighted avg     0.9932    0.9931    0.9931       866

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  6 427]]
```

# Fase 3 (Eje A) - Deep learning sobre bytes: ataque vs benigno por servicio (Friday-16-02-2018)

Tarea `binary`. Flujos: 4000 `Attack`, 4000 `Benign` (total 8000).
Clases: `[np.str_('Attack'), np.str_('Benign')]`. Evaluacion out-of-fold (5-Fold Stratified).

Modelos profundos sobre la SECUENCIA de bytes (byte-CNN, byte-LSTM) frente a
los baselines shallow de la Fase 2 (MLP sobre secuencia plana, histograma y
metadatos de flujo), todos en la MISMA particion.

| Vista / Modelo | Accuracy | Macro-F1 |
|----------------|----------|----------|
| byte-CNN (torch) | 0.6072 | 0.6072 |
| byte-LSTM (torch) | 0.6532 | 0.6299 |
| mlp-seq (sklearn) | 0.6586 | 0.6303 |
| mlp-hist (sklearn) | 0.7375 | 0.7375 |
| metadatos (sklearn) | 0.6617 | 0.6186 |

## byte-CNN (torch)

- **Accuracy:** 0.6072 | **Macro-F1:** 0.6072

```
              precision    recall  f1-score   support

      Attack     0.6048    0.6188    0.6117      4000
      Benign     0.6098    0.5958    0.6027      4000

    accuracy                         0.6072      8000
   macro avg     0.6073    0.6073    0.6072      8000
weighted avg     0.6073    0.6072    0.6072      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[2475 1525]
 [1617 2383]]
```

## byte-LSTM (torch)

- **Accuracy:** 0.6532 | **Macro-F1:** 0.6299

```
              precision    recall  f1-score   support

      Attack     0.6020    0.9042    0.7228      4000
      Benign     0.8077    0.4022    0.5370      4000

    accuracy                         0.6532      8000
   macro avg     0.7049    0.6532    0.6299      8000
weighted avg     0.7049    0.6532    0.6299      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[3617  383]
 [2391 1609]]
```

## mlp-seq (sklearn)

- **Accuracy:** 0.6586 | **Macro-F1:** 0.6303

```
              precision    recall  f1-score   support

      Attack     0.6021    0.9355    0.7326      4000
      Benign     0.8555    0.3817    0.5279      4000

    accuracy                         0.6586      8000
   macro avg     0.7288    0.6586    0.6303      8000
weighted avg     0.7288    0.6586    0.6303      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[3742  258]
 [2473 1527]]
```

## mlp-hist (sklearn)

- **Accuracy:** 0.7375 | **Macro-F1:** 0.7375

```
              precision    recall  f1-score   support

      Attack     0.7410    0.7302    0.7356      4000
      Benign     0.7341    0.7448    0.7394      4000

    accuracy                         0.7375      8000
   macro avg     0.7375    0.7375    0.7375      8000
weighted avg     0.7375    0.7375    0.7375      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[2921 1079]
 [1021 2979]]
```

## metadatos (sklearn)

- **Accuracy:** 0.6617 | **Macro-F1:** 0.6186

```
              precision    recall  f1-score   support

      Attack     0.5967    0.9980    0.7469      4000
      Benign     0.9939    0.3255    0.4904      4000

    accuracy                         0.6617      8000
   macro avg     0.7953    0.6618    0.6186      8000
weighted avg     0.7953    0.6617    0.6186      8000

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Attack'), np.str_('Benign')]:
[[3992    8]
 [2698 1302]]
```

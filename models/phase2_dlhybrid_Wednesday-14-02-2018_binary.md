# Fase 3 (Eje B) - Hibrido de dos ramas: fusion tardia payload+metadatos (Wednesday-14-02-2018, binary)

Flujos: 433 `Attack`, 433 `Benign` (total 866). Clases: `[np.str_('Attack'), np.str_('Benign')]`.
Evaluacion out-of-fold (5-Fold Stratified).

La red de DOS RAMAS (CNN de payload + MLP de metadatos, fusion tardia de
embeddings) frente a las vistas sueltas y a la fusion INGENUA (early concat de
features crudas). La tesis: el hibrido debe ser robusto en ambos regimenes.

| Modelo | Accuracy | Macro-F1 |
|--------|----------|----------|
| hibrido 2-ramas (torch) | 1.0000 | 1.0000 |
| fusion ingenua (concat) | 0.9988 | 0.9988 |
| solo-payload (byte-CNN) | 0.9988 | 0.9988 |
| solo-metadatos (MLP) | 0.9931 | 0.9931 |

## hibrido 2-ramas (torch)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000       433
      Benign     1.0000    1.0000    1.0000       433

    accuracy                         1.0000       866
   macro avg     1.0000    1.0000    1.0000       866
weighted avg     1.0000    1.0000    1.0000       866

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  0 433]]
```

## fusion ingenua (concat)

- **Accuracy:** 0.9988 | **Macro-F1:** 0.9988

```
              precision    recall  f1-score   support

      Attack     0.9977    1.0000    0.9988       433
      Benign     1.0000    0.9977    0.9988       433

    accuracy                         0.9988       866
   macro avg     0.9988    0.9988    0.9988       866
weighted avg     0.9988    0.9988    0.9988       866

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  1 432]]
```

## solo-payload (byte-CNN)

- **Accuracy:** 0.9988 | **Macro-F1:** 0.9988

```
              precision    recall  f1-score   support

      Attack     0.9977    1.0000    0.9988       433
      Benign     1.0000    0.9977    0.9988       433

    accuracy                         0.9988       866
   macro avg     0.9988    0.9988    0.9988       866
weighted avg     0.9988    0.9988    0.9988       866

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  1 432]]
```

## solo-metadatos (MLP)

- **Accuracy:** 0.9931 | **Macro-F1:** 0.9931

```
              precision    recall  f1-score   support

      Attack     0.9863    1.0000    0.9931       433
      Benign     1.0000    0.9861    0.9930       433

    accuracy                         0.9931       866
   macro avg     0.9932    0.9931    0.9931       866
weighted avg     0.9932    0.9931    0.9931       866

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[433   0]
 [  6 427]]
```

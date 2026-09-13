# Fase 3 (Eje B) - Hibrido de dos ramas: fusion tardia payload+metadatos (Thursday-22-02-2018, binary)

Flujos: 203 `Attack`, 203 `Benign` (total 406). Clases: `[np.str_('Attack'), np.str_('Benign')]`.
Evaluacion out-of-fold (5-Fold Stratified).

La red de DOS RAMAS (CNN de payload + MLP de metadatos, fusion tardia de
embeddings) frente a las vistas sueltas y a la fusion INGENUA (early concat de
features crudas). La tesis: el hibrido debe ser robusto en ambos regimenes.

| Modelo | Accuracy | Macro-F1 |
|--------|----------|----------|
| hibrido 2-ramas (torch) | 0.9975 | 0.9975 |
| fusion ingenua (concat) | 0.9803 | 0.9803 |
| solo-payload (byte-CNN) | 1.0000 | 1.0000 |
| solo-metadatos (MLP) | 0.9187 | 0.9184 |

## hibrido 2-ramas (torch)

- **Accuracy:** 0.9975 | **Macro-F1:** 0.9975

```
              precision    recall  f1-score   support

      Attack     0.9951    1.0000    0.9975       203
      Benign     1.0000    0.9951    0.9975       203

    accuracy                         0.9975       406
   macro avg     0.9975    0.9975    0.9975       406
weighted avg     0.9975    0.9975    0.9975       406

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[203   0]
 [  1 202]]
```

## fusion ingenua (concat)

- **Accuracy:** 0.9803 | **Macro-F1:** 0.9803

```
              precision    recall  f1-score   support

      Attack     0.9899    0.9704    0.9801       203
      Benign     0.9710    0.9901    0.9805       203

    accuracy                         0.9803       406
   macro avg     0.9805    0.9803    0.9803       406
weighted avg     0.9805    0.9803    0.9803       406

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[197   6]
 [  2 201]]
```

## solo-payload (byte-CNN)

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000       203
      Benign     1.0000    1.0000    1.0000       203

    accuracy                         1.0000       406
   macro avg     1.0000    1.0000    1.0000       406
weighted avg     1.0000    1.0000    1.0000       406

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[203   0]
 [  0 203]]
```

## solo-metadatos (MLP)

- **Accuracy:** 0.9187 | **Macro-F1:** 0.9184

```
              precision    recall  f1-score   support

      Attack     0.8728    0.9803    0.9234       203
      Benign     0.9775    0.8571    0.9134       203

    accuracy                         0.9187       406
   macro avg     0.9252    0.9187    0.9184       406
weighted avg     0.9252    0.9187    0.9184       406

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[199   4]
 [ 29 174]]
```

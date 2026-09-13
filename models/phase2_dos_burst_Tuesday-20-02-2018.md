# Fase 3 (Eje C) - Agregado de rafaga por origen (Tuesday-20-02-2018, servicio=http (DPI))

DDoS-LOIC-HTTP vs benigno del mismo servicio, balanceado 1:1 ({'Attack': 4000, 'Benign': 4000}), out-of-fold 5-Fold.
Ventanas de rafaga (s): 1.0, 5.0, 30.0.

| Vista | Accuracy | Macro-F1 |
|-------|----------|----------|
| payload-hist | 1.0000 | 1.0000 |
| meta-basica | 0.9985 | 0.9985 |
| meta+rafaga | 0.9982 | 0.9982 |
## payload-hist

- **Accuracy:** 1.0000 | **Macro-F1:** 1.0000

```
              precision    recall  f1-score   support

      Attack     1.0000    1.0000    1.0000      4000
      Benign     1.0000    1.0000    1.0000      4000

    accuracy                         1.0000      8000
   macro avg     1.0000    1.0000    1.0000      8000
weighted avg     1.0000    1.0000    1.0000      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   0 4000]]
```

## meta-basica

- **Accuracy:** 0.9985 | **Macro-F1:** 0.9985

```
              precision    recall  f1-score   support

      Attack     0.9970    1.0000    0.9985      4000
      Benign     1.0000    0.9970    0.9985      4000

    accuracy                         0.9985      8000
   macro avg     0.9985    0.9985    0.9985      8000
weighted avg     0.9985    0.9985    0.9985      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [  12 3988]]
```

## meta+rafaga

- **Accuracy:** 0.9982 | **Macro-F1:** 0.9982

```
              precision    recall  f1-score   support

      Attack     0.9980    0.9985    0.9983      4000
      Benign     0.9985    0.9980    0.9982      4000

    accuracy                         0.9982      8000
   macro avg     0.9983    0.9983    0.9982      8000
weighted avg     0.9983    0.9982    0.9982      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3994    6]
 [   8 3992]]
```

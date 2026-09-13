# Fase 3 (Eje C) - Agregado de rafaga por origen (Friday-02-03-2018, servicio=http (DPI))

Bot vs benigno del mismo servicio, balanceado 1:1 ({'Attack': 4000, 'Benign': 4000}), out-of-fold 5-Fold.
Ventanas de rafaga (s): 1.0, 5.0, 30.0.

| Vista | Accuracy | Macro-F1 |
|-------|----------|----------|
| payload-hist | 0.9992 | 0.9992 |
| meta-basica | 0.9986 | 0.9986 |
| meta+rafaga | 0.9964 | 0.9964 |
## payload-hist

- **Accuracy:** 0.9992 | **Macro-F1:** 0.9992

```
              precision    recall  f1-score   support

      Attack     0.9995    0.9990    0.9992      4000
      Benign     0.9990    0.9995    0.9993      4000

    accuracy                         0.9992      8000
   macro avg     0.9993    0.9992    0.9992      8000
weighted avg     0.9993    0.9992    0.9992      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3996    4]
 [   2 3998]]
```

## meta-basica

- **Accuracy:** 0.9986 | **Macro-F1:** 0.9986

```
              precision    recall  f1-score   support

      Attack     0.9987    0.9985    0.9986      4000
      Benign     0.9985    0.9988    0.9986      4000

    accuracy                         0.9986      8000
   macro avg     0.9986    0.9986    0.9986      8000
weighted avg     0.9986    0.9986    0.9986      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3994    6]
 [   5 3995]]
```

## meta+rafaga

- **Accuracy:** 0.9964 | **Macro-F1:** 0.9964

```
              precision    recall  f1-score   support

      Attack     0.9972    0.9955    0.9964      4000
      Benign     0.9955    0.9972    0.9964      4000

    accuracy                         0.9964      8000
   macro avg     0.9964    0.9964    0.9964      8000
weighted avg     0.9964    0.9964    0.9964      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3982   18]
 [  11 3989]]
```

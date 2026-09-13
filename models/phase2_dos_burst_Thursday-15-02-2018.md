# Fase 3 (Eje C) - Agregado de rafaga por origen (Thursday-15-02-2018, servicio=http (DPI))

DoS-GoldenEye + DoS-Slowloris vs benigno del mismo servicio, balanceado 1:1 ({'Attack': 4000, 'Benign': 4000}), out-of-fold 5-Fold.
Ventanas de rafaga (s): 1.0, 5.0, 30.0.

| Vista | Accuracy | Macro-F1 |
|-------|----------|----------|
| payload-hist | 0.9998 | 0.9997 |
| meta-basica | 0.9589 | 0.9588 |
| meta+rafaga | 0.9964 | 0.9964 |
## payload-hist

- **Accuracy:** 0.9998 | **Macro-F1:** 0.9997

```
              precision    recall  f1-score   support

      Attack     0.9995    1.0000    0.9998      4000
      Benign     1.0000    0.9995    0.9997      4000

    accuracy                         0.9998      8000
   macro avg     0.9998    0.9998    0.9997      8000
weighted avg     0.9998    0.9998    0.9997      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[4000    0]
 [   2 3998]]
```

## meta-basica

- **Accuracy:** 0.9589 | **Macro-F1:** 0.9588

```
              precision    recall  f1-score   support

      Attack     0.9336    0.9880    0.9600      4000
      Benign     0.9873    0.9297    0.9576      4000

    accuracy                         0.9589      8000
   macro avg     0.9604    0.9589    0.9588      8000
weighted avg     0.9604    0.9589    0.9588      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3952   48]
 [ 281 3719]]
```

## meta+rafaga

- **Accuracy:** 0.9964 | **Macro-F1:** 0.9964

```
              precision    recall  f1-score   support

      Attack     0.9975    0.9952    0.9964      4000
      Benign     0.9953    0.9975    0.9964      4000

    accuracy                         0.9964      8000
   macro avg     0.9964    0.9964    0.9964      8000
weighted avg     0.9964    0.9964    0.9964      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3981   19]
 [  10 3990]]
```

# Fase 3 (Eje C) - La firma del DoS es volumetrica (Friday-16-02-2018, :80)

DoS-Hulk vs HTTP-benigno, balanceado 1:1 ({'Attack': 4000, 'Benign': 4000}), out-of-fold 5-Fold.
Ventanas de rafaga (s): 1.0, 5.0, 30.0.

| Vista | Accuracy | Macro-F1 |
|-------|----------|----------|
| payload-hist | 1.0000 | 1.0000 |
| meta-basica | 0.9714 | 0.9714 |
| meta+rafaga | 1.0000 | 1.0000 |

La rafaga (volumen agregado por origen) es la firma del DoS: las vistas
per-flujo (payload e incluso metadata basica) se quedan debiles porque un
flujo de Hulk es indistinguible de un GET benigno; solo el agregado de
volumen lo separa. Analogo al SSH-Bruteforce (17-jun).

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

- **Accuracy:** 0.9714 | **Macro-F1:** 0.9714

```
              precision    recall  f1-score   support

      Attack     0.9482    0.9972    0.9721      4000
      Benign     0.9971    0.9455    0.9706      4000

    accuracy                         0.9714      8000
   macro avg     0.9726    0.9714    0.9714      8000
weighted avg     0.9726    0.9714    0.9714      8000

Matriz de confusion labels=[np.str_('Attack'), np.str_('Benign')]:
[[3989   11]
 [ 218 3782]]
```

## meta+rafaga

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

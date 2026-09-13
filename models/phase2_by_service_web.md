# Fase 2 - Evaluacion honesta por servicio: Web-ataque vs HTTP-benigno (Thursday-22-02-2018)

Espejo del SSH. Conjunto balanceado 1:1 sobre el servicio atacado (puerto
80, HTTP): 203 `Web-Attack` (colapsa ['Brute Force -Web', 'Brute Force -XSS', 'SQL Injection']) vs 203 `Benign`, ambos HTTP en claro. A diferencia del SSH cifrado, aqui el ataque
esta en los bytes, asi que se espera que el payload gane.

Clases: `[np.str_('Benign'), np.str_('Web-Attack')]`. Tres MLP (256->128), 5-Fold CV + test held-out.

## payload

- **5-Fold CV accuracy:** 0.9877 ± 0.0078

```
              precision    recall  f1-score   support

      Benign     1.0000    1.0000    1.0000        41
  Web-Attack     1.0000    1.0000    1.0000        41

    accuracy                         1.0000        82
   macro avg     1.0000    1.0000    1.0000        82
weighted avg     1.0000    1.0000    1.0000        82

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('Web-Attack')]:
[[41  0]
 [ 0 41]]
```

## metadatos

- **5-Fold CV accuracy:** 0.9286 ± 0.0237

```
              precision    recall  f1-score   support

      Benign     1.0000    0.8293    0.9067        41
  Web-Attack     0.8542    1.0000    0.9213        41

    accuracy                         0.9146        82
   macro avg     0.9271    0.9146    0.9140        82
weighted avg     0.9271    0.9146    0.9140        82

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('Web-Attack')]:
[[34  7]
 [ 0 41]]
```

## hibrido

- **5-Fold CV accuracy:** 0.9926 ± 0.0099

```
              precision    recall  f1-score   support

      Benign     0.9535    1.0000    0.9762        41
  Web-Attack     1.0000    0.9512    0.9750        41

    accuracy                         0.9756        82
   macro avg     0.9767    0.9756    0.9756        82
weighted avg     0.9767    0.9756    0.9756        82

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('Web-Attack')]:
[[41  0]
 [ 2 39]]
```

# Fase 2 - Primer modelo de Deep Learning (Wednesday-14-02-2018)

Redes neuronales (MLPClassifier) entrenadas sobre el dataset de payload
etiquetado, con balanceo por undersampling a la clase minoritaria.

> Nota: el entorno `tfg_ia` no tiene TensorFlow/PyTorch; el modelo
> "secuencial" es un MLP denso sobre los 256 bytes (no un CNN/RNN). Ambos
> son redes neuronales multicapa entrenadas por backprop.

## histograma+entropia

- Clases balanceadas: `['Benign', 'SSH-Bruteforce']` (185236 muestras).
- **5-Fold CV accuracy:** 0.99952 ± 0.00007  (folds: [0.9994 0.9995 0.9995 0.9996 0.9996])

Test held-out (20%):

```
                precision    recall  f1-score   support

        Benign     1.0000    0.9992    0.9996     18524
SSH-Bruteforce     0.9992    1.0000    0.9996     18524

      accuracy                         0.9996     37048
     macro avg     0.9996    0.9996    0.9996     37048
  weighted avg     0.9996    0.9996    0.9996     37048

Matriz de confusion (filas=real, cols=pred):
labels: ['Benign', 'SSH-Bruteforce']
[[18509    15]
 [    0 18524]]
```

![matriz de confusion histograma+entropia](models/phase2_cm_histogramaentropia.png)

## secuencial

- Clases balanceadas: `['Benign', 'SSH-Bruteforce']` (185236 muestras).
- **5-Fold CV accuracy:** 0.99959 ± 0.00009  (folds: [0.9995 0.9996 0.9995 0.9996 0.9997])

Test held-out (20%):

```
                precision    recall  f1-score   support

        Benign     1.0000    0.9993    0.9996     18524
SSH-Bruteforce     0.9993    1.0000    0.9996     18524

      accuracy                         0.9996     37048
     macro avg     0.9996    0.9996    0.9996     37048
  weighted avg     0.9996    0.9996    0.9996     37048

Matriz de confusion (filas=real, cols=pred):
labels: ['Benign', 'SSH-Bruteforce']
[[18511    13]
 [    0 18524]]
```

![matriz de confusion secuencial](models/phase2_cm_secuencial.png)

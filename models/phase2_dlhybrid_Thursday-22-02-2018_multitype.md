# Fase 3 (Eje B) - Hibrido de dos ramas: fusion tardia payload+metadatos (Thursday-22-02-2018, multitype)

Flujos: 142 `Brute Force -Web`, 42 `Brute Force -XSS`, 19 `SQL Injection` (total 203). Clases: `[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]`.
Evaluacion out-of-fold (5-Fold Stratified).

La red de DOS RAMAS (CNN de payload + MLP de metadatos, fusion tardia de
embeddings) frente a las vistas sueltas y a la fusion INGENUA (early concat de
features crudas). La tesis: el hibrido debe ser robusto en ambos regimenes.

| Modelo | Accuracy | Macro-F1 |
|--------|----------|----------|
| hibrido 2-ramas (torch) | 0.9803 | 0.9628 |
| fusion ingenua (concat) | 0.9557 | 0.9009 |
| solo-payload (byte-CNN) | 0.9852 | 0.9679 |
| solo-metadatos (MLP) | 0.9113 | 0.7695 |

## hibrido 2-ramas (torch)

- **Accuracy:** 0.9803 | **Macro-F1:** 0.9628

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9792    0.9930    0.9860       142
Brute Force -XSS     0.9767    1.0000    0.9882        42
   SQL Injection     1.0000    0.8421    0.9143        19

        accuracy                         0.9803       203
       macro avg     0.9853    0.9450    0.9628       203
    weighted avg     0.9806    0.9803    0.9798       203

Matriz de confusion labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[141   1   0]
 [  0  42   0]
 [  3   0  16]]
```

## fusion ingenua (concat)

- **Accuracy:** 0.9557 | **Macro-F1:** 0.9009

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9858    0.9789    0.9823       142
Brute Force -XSS     0.9111    0.9762    0.9425        42
   SQL Injection     0.8235    0.7368    0.7778        19

        accuracy                         0.9557       203
       macro avg     0.9068    0.8973    0.9009       203
    weighted avg     0.9552    0.9557    0.9550       203

Matriz de confusion labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[139   1   2]
 [  0  41   1]
 [  2   3  14]]
```

## solo-payload (byte-CNN)

- **Accuracy:** 0.9852 | **Macro-F1:** 0.9679

```
                  precision    recall  f1-score   support

Brute Force -Web     0.9793    1.0000    0.9895       142
Brute Force -XSS     1.0000    1.0000    1.0000        42
   SQL Injection     1.0000    0.8421    0.9143        19

        accuracy                         0.9852       203
       macro avg     0.9931    0.9474    0.9679       203
    weighted avg     0.9855    0.9852    0.9847       203

Matriz de confusion labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[142   0   0]
 [  0  42   0]
 [  3   0  16]]
```

## solo-metadatos (MLP)

- **Accuracy:** 0.9113 | **Macro-F1:** 0.7695

```
                  precision    recall  f1-score   support

Brute Force -Web     0.8974    0.9859    0.9396       142
Brute Force -XSS     0.9524    0.9524    0.9524        42
   SQL Injection     1.0000    0.2632    0.4167        19

        accuracy                         0.9113       203
       macro avg     0.9499    0.7338    0.7695       203
    weighted avg     0.9184    0.9113    0.8933       203

Matriz de confusion labels=[np.str_('Brute Force -Web'), np.str_('Brute Force -XSS'), np.str_('SQL Injection')]:
[[140   2   0]
 [  2  40   0]
 [ 14   0   5]]
```

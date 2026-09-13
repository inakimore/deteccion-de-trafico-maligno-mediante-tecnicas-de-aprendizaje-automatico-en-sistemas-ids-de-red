# Generalizacion cruzada entre datasets: train Tuesday-04-07-2017 -> test Wednesday-14-02-2018 (:22)

Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema
binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos
(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a
cual solo memorizaba la huella del laboratorio/herramienta.

- Train (Tuesday-04-07-2017): 2088 flujos balanceados (1:1).
- Test  (Wednesday-14-02-2018): 866 flujos balanceados (1:1).

| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |
|-------|----------|----------|---------------|------------------|
| payload-hist | 0.5855 | 0.4994 | 1.0000 | 0.5467 |
| metadatos | 0.5219 | 0.3803 | 1.0000 | 0.5112 |
| byte-cnn | 0.6051 | 0.5321 | 1.0000 | 0.5587 |

**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura
la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la
huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta
o la app vulnerable). Es la prueba directa contra el "100% sospechoso".

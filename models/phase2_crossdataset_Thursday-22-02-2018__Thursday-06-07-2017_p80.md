# Generalizacion cruzada entre datasets: train Thursday-22-02-2018 -> test Thursday-06-07-2017 (:80)

Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema
binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos
(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a
cual solo memorizaba la huella del laboratorio/herramienta.

- Train (Thursday-22-02-2018): 406 flujos balanceados (1:1).
- Test  (Thursday-06-07-2017): 348 flujos balanceados (1:1).

| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |
|-------|----------|----------|---------------|------------------|
| payload-hist | 0.8391 | 0.8351 | 0.9943 | 0.7588 |
| metadatos | 0.5287 | 0.4933 | 0.7931 | 0.5188 |
| byte-cnn | 0.9914 | 0.9914 | 0.9828 | 1.0000 |

**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura
la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la
huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta
o la app vulnerable). Es la prueba directa contra el "100% sospechoso".

# Generalizacion cruzada entre datasets: train Tuesday-20-02-2018 -> test Friday-16-02-2018 (:80)

Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema
binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos
(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a
cual solo memorizaba la huella del laboratorio/herramienta.

- Train (Tuesday-20-02-2018): 8000 flujos balanceados (1:1).
- Test  (Friday-16-02-2018): 8000 flujos balanceados (1:1).

| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |
|-------|----------|----------|---------------|------------------|
| payload-hist | 0.9928 | 0.9927 | 0.9855 | 1.0000 |
| metadatos | 0.5011 | 0.3393 | 0.0063 | 0.6098 |
| byte-cnn | 0.5000 | 0.3333 | 0.0000 | 0.0000 |

**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura
la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la
huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta
o la app vulnerable). Es la prueba directa contra el "100% sospechoso".

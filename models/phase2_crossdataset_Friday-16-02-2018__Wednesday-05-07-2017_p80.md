# Generalizacion cruzada entre datasets: train Friday-16-02-2018 -> test Wednesday-05-07-2017 (:80)

Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema
binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos
(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a
cual solo memorizaba la huella del laboratorio/herramienta.

- Train (Friday-16-02-2018): 8000 flujos balanceados (1:1).
- Test  (Wednesday-05-07-2017): 8000 flujos balanceados (1:1).

| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |
|-------|----------|----------|---------------|------------------|
| payload-hist | 0.4955 | 0.3322 | 0.0010 | 0.0909 |
| metadatos | 0.4291 | 0.3005 | 0.0003 | 0.0018 |
| byte-cnn | 0.9656 | 0.9656 | 0.9313 | 1.0000 |

**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura
la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la
huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta
o la app vulnerable). Es la prueba directa contra el "100% sospechoso".

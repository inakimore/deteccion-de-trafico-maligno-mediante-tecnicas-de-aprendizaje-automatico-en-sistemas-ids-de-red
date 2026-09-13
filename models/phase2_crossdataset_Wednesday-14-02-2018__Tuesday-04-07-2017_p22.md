# Generalizacion cruzada entre datasets: train Wednesday-14-02-2018 -> test Tuesday-04-07-2017 (:22)

Entrenar en un dataset y testear en OTRO con el ataque analogo. Problema
binario Attack vs Benign sobre el servicio atacado, balanceado 1:1 en ambos
(0.5 = azar). Mide que vista GENERALIZA entre datasets (senal real) frente a
cual solo memorizaba la huella del laboratorio/herramienta.

- Train (Wednesday-14-02-2018): 866 flujos balanceados (1:1).
- Test  (Tuesday-04-07-2017): 2088 flujos balanceados (1:1).

| Vista | Accuracy | Macro-F1 | Recall ataque | Precision ataque |
|-------|----------|----------|---------------|------------------|
| payload-hist | 0.7921 | 0.7909 | 0.7136 | 0.8466 |
| metadatos | 0.5139 | 0.3776 | 0.9818 | 0.5072 |
| byte-cnn | 0.9990 | 0.9990 | 0.9981 | 1.0000 |

**Lectura:** una vista que mantiene el acierto al cambiar de dataset captura
la firma REAL del ataque; una que se desploma hacia 0.5 estaba memorizando la
huella concreta del dataset de entrenamiento (p.ej. el banner de la herramienta
o la app vulnerable). Es la prueba directa contra el "100% sospechoso".

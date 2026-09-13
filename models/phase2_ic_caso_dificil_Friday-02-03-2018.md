# IC 95% del caso dificil - Friday-02-03-2018

Servicio: servicio=http (DPI). Clase positiva: `Ataque` = {'Bot': 142921}. Metrica **out-of-fold** (5-Fold estratificado). El macro-F1 es la **media sobre 10 submuestreos 1:1 con semillas distintas** (tope 5000 por clase), y el IC 95% agrupa los 2000 remuestreos de bootstrap repartidos entre ellos: recoge la incertidumbre del tamano de muestra Y la de que flujos concretos entran en el balanceo.

Ataque 142921, Benign genuino 417009; 10000 flujos evaluados por repeticion.

| Vista | Macro-F1 [IC 95%] | sd entre repeticiones | Recall ataque [IC 95%] |
|---|---|---|---|
| payload (histograma + entropia) | 0.9990 [0.9980, 0.9997] | 0.0003 | 0.9987 [0.9965, 0.9998] |
| metadatos de flujo | 0.9981 [0.9966, 0.9993] | 0.0006 | 0.9974 [0.9950, 0.9992] |
| conducta (metadatos + rafaga) | 0.9983 [0.9970, 0.9993] | 0.0004 | 0.9988 [0.9974, 0.9998] |

El escenario **contaminado no es reproducible** desde este `.npz`: no queda ningun flujo etiquetado `Benign` procedente de una IP atacante bajo este servicio. La correccion del limite de ventana ya reetiqueto esos flujos como ataque, de modo que la contaminacion esta corregida en el propio conjunto de datos y no en tiempo de evaluacion.

**Por que este fichero existe:** las cifras que se venian citando de los casos dificiles son **exactitud en validacion cruzada**, no macro-F1, y no todas las vistas se habian medido en todos los dias (la vista conductual faltaba en el dia web). Aqui las tres vistas se miden igual en todos los dias, con la metrica que declara la memoria y con intervalo.

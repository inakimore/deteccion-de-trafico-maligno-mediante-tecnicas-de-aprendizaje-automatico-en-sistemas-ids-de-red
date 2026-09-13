# IC 95% del caso dificil - Thursday-22-02-2018

Servicio: servicio=http (DPI). Clase positiva: `Ataque` = {'Brute Force -Web': 142, 'Brute Force -XSS': 42, 'SQL Injection': 19}. Metrica **out-of-fold** (5-Fold estratificado). El macro-F1 es la **media sobre 10 submuestreos 1:1 con semillas distintas** (tope 5000 por clase), y el IC 95% agrupa los 2000 remuestreos de bootstrap repartidos entre ellos: recoge la incertidumbre del tamano de muestra Y la de que flujos concretos entran en el balanceo.

Ataque 203, Benign genuino 459743; 406 flujos evaluados por repeticion.

| Vista | Macro-F1 [IC 95%] | sd entre repeticiones | Recall ataque [IC 95%] |
|---|---|---|---|
| payload (histograma + entropia) | 0.9734 [0.9507, 0.9926] | 0.0075 | 0.9867 [0.9360, 1.0000] |
| metadatos de flujo | 0.9186 [0.8793, 0.9507] | 0.0120 | 0.9887 [0.9633, 1.0000] |
| conducta (metadatos + rafaga) | 0.9823 [0.9652, 0.9975] | 0.0065 | 0.9714 [0.9368, 1.0000] |

El escenario **contaminado no es reproducible** desde este `.npz`: no queda ningun flujo etiquetado `Benign` procedente de una IP atacante bajo este servicio. La correccion del limite de ventana ya reetiqueto esos flujos como ataque, de modo que la contaminacion esta corregida en el propio conjunto de datos y no en tiempo de evaluacion.

**Por que este fichero existe:** las cifras que se venian citando de los casos dificiles son **exactitud en validacion cruzada**, no macro-F1, y no todas las vistas se habian medido en todos los dias (la vista conductual faltaba en el dia web). Aqui las tres vistas se miden igual en todos los dias, con la metrica que declara la memoria y con intervalo.

# IC 95% del caso dificil - Wednesday-14-02-2018

Servicio: servicio=ssh (DPI). Clase positiva: `Ataque` = {'SSH-Bruteforce': 94207}. Metrica **out-of-fold** (5-Fold estratificado). El macro-F1 es la **media sobre 10 submuestreos 1:1 con semillas distintas** (tope 5000 por clase), y el IC 95% agrupa los 2000 remuestreos de bootstrap repartidos entre ellos: recoge la incertidumbre del tamano de muestra Y la de que flujos concretos entran en el balanceo.

Ataque 94207, Benign genuino 358; 716 flujos evaluados por repeticion.

| Vista | Macro-F1 [IC 95%] | sd entre repeticiones | Recall ataque [IC 95%] |
|---|---|---|---|
| payload (histograma + entropia) | 0.9842 [0.9720, 0.9958] | 0.0040 | 0.9997 [0.9947, 1.0000] |
| metadatos de flujo | 0.9906 [0.9790, 0.9986] | 0.0038 | 0.9997 [0.9947, 1.0000] |
| conducta (metadatos + rafaga) | 0.9985 [0.9944, 1.0000] | 0.0004 | 0.9997 [0.9947, 1.0000] |

El escenario **contaminado no es reproducible** desde este `.npz`: no queda ningun flujo etiquetado `Benign` procedente de una IP atacante bajo este servicio. La correccion del limite de ventana ya reetiqueto esos flujos como ataque, de modo que la contaminacion esta corregida en el propio conjunto de datos y no en tiempo de evaluacion.

**Por que este fichero existe:** las cifras que se venian citando de los casos dificiles son **exactitud en validacion cruzada**, no macro-F1, y no todas las vistas se habian medido en todos los dias (la vista conductual faltaba en el dia web). Aqui las tres vistas se miden igual en todos los dias, con la metrica que declara la memoria y con intervalo.

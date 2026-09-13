# Punto 6 - Metricas de rigor: ROC/PR-AUC + IC 95% (Friday-16-02-2018, :80)

Binario Attack vs Benign en :80, balanceado 1:1 (attack 4000 / benign 4000), out-of-fold 5-Fold. Intervalos de confianza al 95% por bootstrap (2000 remuestreos). Curvas en el PNG.

| Vista | ROC-AUC [IC95%] | PR-AUC [IC95%] |
|-------|-----------------|----------------|
| payload byte-CNN | 0.6775 [0.6650, 0.6898] | 0.6037 [0.5859, 0.6209] |
| payload histograma | 0.8422 [0.8342, 0.8505] | 0.8369 [0.8258, 0.8473] |
| conducta meta+rafaga | 0.8427 [0.8346, 0.8511] | 0.8432 [0.8328, 0.8531] |

Curvas ROC y Precision-Recall: `phase2_rigor_Friday-16-02-2018_p80.png`.

**Lectura:** con clases pequenas el ROC/PR-AUC y su IC son mas honestos que un accuracy puntual. Un IC ancho avisa de que el N es reducido (p.ej. web, 203 flujos); aun asi la vista ganadora de cada regimen se separa de forma consistente.

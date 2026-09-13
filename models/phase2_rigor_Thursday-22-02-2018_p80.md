# Punto 6 - Metricas de rigor: ROC/PR-AUC + IC 95% (Thursday-22-02-2018, :80)

Binario Attack vs Benign en :80, balanceado 1:1 (attack 203 / benign 203), out-of-fold 5-Fold. Intervalos de confianza al 95% por bootstrap (2000 remuestreos). Curvas en el PNG.

| Vista | ROC-AUC [IC95%] | PR-AUC [IC95%] |
|-------|-----------------|----------------|
| payload byte-CNN | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] |
| payload histograma | 0.9949 [0.9843, 1.0000] | 0.9786 [0.9378, 1.0000] |
| conducta meta+rafaga | 0.9998 [0.9994, 1.0000] | 0.9998 [0.9994, 1.0000] |

Curvas ROC y Precision-Recall: `phase2_rigor_Thursday-22-02-2018_p80.png`.

**Lectura:** con clases pequenas el ROC/PR-AUC y su IC son mas honestos que un accuracy puntual. Un IC ancho avisa de que el N es reducido (p.ej. web, 203 flujos); aun asi la vista ganadora de cada regimen se separa de forma consistente.

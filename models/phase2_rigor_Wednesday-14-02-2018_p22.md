# Punto 6 - Metricas de rigor: ROC/PR-AUC + IC 95% (Wednesday-14-02-2018, :22)

Binario Attack vs Benign en :22, balanceado 1:1 (attack 433 / benign 433), out-of-fold 5-Fold. Intervalos de confianza al 95% por bootstrap (2000 remuestreos). Curvas en el PNG.

| Vista | ROC-AUC [IC95%] | PR-AUC [IC95%] |
|-------|-----------------|----------------|
| payload byte-CNN | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] |
| payload histograma | 0.9958 [0.9902, 1.0000] | 0.9925 [0.9815, 1.0000] |
| conducta meta+rafaga | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] |

Curvas ROC y Precision-Recall: `phase2_rigor_Wednesday-14-02-2018_p22.png`.

**Lectura:** con clases pequenas el ROC/PR-AUC y su IC son mas honestos que un accuracy puntual. Un IC ancho avisa de que el N es reducido (p.ej. web, 203 flujos); aun asi la vista ganadora de cada regimen se separa de forma consistente.

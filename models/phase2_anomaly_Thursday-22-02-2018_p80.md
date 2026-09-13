# Punto 4 - Deteccion de anomalias no supervisada (Thursday-22-02-2018, :80)

Entrenado SOLO con benigno (fit=8000); test = benigno (4000) + ataque (203). Sin usar etiquetas de ataque para entrenar (escenario zero-day). Rafaga: SI.

| Vista (no supervisada) | ROC-AUC | Deteccion @5% FPR |
|------------------------|---------|-------------------|
| payload-IF | 0.7580 | 0.2808 |
| meta+rafaga-IF | 0.9121 | 0.5714 |
| payload-AE | 0.7920 | 0.0739 |

**Lectura:** ROC-AUC 0.5 = no distingue; 1.0 = separacion perfecta. La deteccion @5% FPR es la fraccion de ataques capturados aceptando solo 5% de falsas alarmas sobre el benigno. Cada regimen esconde su anomalia en una vista distinta (payload en el ataque en claro; rafaga/agregado en el cifrado y el volumetrico), coherente con la tesis: incluso sin etiquetas, ninguna vista unica basta.

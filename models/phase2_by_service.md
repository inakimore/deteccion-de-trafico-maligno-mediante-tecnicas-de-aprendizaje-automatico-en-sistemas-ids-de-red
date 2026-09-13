# Fase 2 - Evaluacion honesta por servicio: SSH-ataque vs SSH-benigno (Wednesday-14-02-2018)

Conjunto balanceado 1:1 sobre el CASO DIFICIL (puerto 22, SSH): 2022 `SSH-Bruteforce` vs 2022 `Benign`, ambos cifrados. Se elimina la
separacion trivial entre protocolos del paso 1; esta es la metrica realista
de cada vista sobre el ataque que de verdad importa.

Clases: `[np.str_('Benign'), np.str_('SSH-Bruteforce')]`. Tres MLP (256->128), 5-Fold CV + test held-out.

## payload

- **5-Fold CV accuracy:** 0.5732 ± 0.0131

```
                precision    recall  f1-score   support

        Benign     0.6068    0.4840    0.5385       405
SSH-Bruteforce     0.5700    0.6856    0.6225       404

      accuracy                         0.5847       809
     macro avg     0.5884    0.5848    0.5805       809
  weighted avg     0.5884    0.5847    0.5804       809

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('SSH-Bruteforce')]:
[[196 209]
 [127 277]]
```

## metadatos

- **5-Fold CV accuracy:** 0.6093 ± 0.0056

```
                precision    recall  f1-score   support

        Benign     0.6667    0.5531    0.6046       405
SSH-Bruteforce     0.6173    0.7228    0.6659       404

      accuracy                         0.6378       809
     macro avg     0.6420    0.6379    0.6352       809
  weighted avg     0.6420    0.6378    0.6352       809

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('SSH-Bruteforce')]:
[[224 181]
 [112 292]]
```

## hibrido

- **5-Fold CV accuracy:** 0.5776 ± 0.0187

```
                precision    recall  f1-score   support

        Benign     0.5780    0.4938    0.5326       405
SSH-Bruteforce     0.5572    0.6386    0.5952       404

      accuracy                         0.5661       809
     macro avg     0.5676    0.5662    0.5639       809
  weighted avg     0.5676    0.5661    0.5639       809

Matriz de confusion (filas=real, cols=pred) labels=[np.str_('Benign'), np.str_('SSH-Bruteforce')]:
[[200 205]
 [146 258]]
```

## Lectura honesta

- **payload** se queda en el azar (CV ~0.57): el SSH-Bruteforce cifrado y el
  SSH benigno cifrado tienen bytes estadisticamente indistinguibles. El
  analisis de payload es CIEGO al brute-force sobre un servicio cifrado.
- **metadatos** es la mejor vista (CV ~0.61), confirmando que la firma del
  ataque vive en el COMPORTAMIENTO de flujo, no en los bytes. Pero ~0.61 es
  aun debil: los 4 escalares disponibles (paquetes/bytes de payload por flujo)
  son pobres; falta la metadata rica de flujo (duracion, inter-arribo, estado
  de conexion, rafaga entre conexiones) que la extraccion de solo-payload
  descarta. Recuperarla (estilo conn.log) es el siguiente paso natural.
- **hibrido** NO supera a metadatos: concatenar 257 features de payload casi
  aleatorias diluye los 4 escalares utiles. La fusion ingenua no ayuda; haria
  falta ponderar/seleccionar features o enriquecer primero la metadata.

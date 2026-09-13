# Fase 2 - Evaluacion honesta por servicio ENRIQUECIDA (Wednesday-14-02-2018)

Refinamiento del paso 2. Dos correcciones sobre `honest_by_service.py`:

1. **Contaminacion del benigno:** el 78,6% del "SSH benigno" del paso 2 era
   el propio atacante `13.58.98.64` conectando al puerto 22 FUERA de la ventana
   etiquetada (mismas rafagas que el ataque). El benigno GENUINO son 433 flujos
   de 75 IPs de terceros. Se comparan dos definiciones de benigno.
2. **Metadata de rafaga:** nº de conexiones del mismo origen en ventanas causales
   de 1s, 5s, 30s (firma del brute-force),
   derivada del meta CSV sin re-procesar los 67 GB de TSV.

Vistas: `payload` (X_hist+entropy, 257), `meta-basica` (4 escalares de la Fase 2),
`meta-rica` (4 escalares + 3 rafagas). MLP 256->128, 5-Fold CV + test held-out,
balanceo 1:1 ataque/benigno.

| Escenario (benigno) | Vista | CV accuracy | F1 ataque (test) |
|---------------------|-------|-------------|------------------|
| contaminado (todos) | payload | 0.5732 ± 0.0131 | 0.6225 |
| contaminado (todos) | meta-basica | 0.6093 ± 0.0056 | 0.6659 |
| contaminado (todos) | meta-rica | 0.7841 ± 0.0144 | 0.7826 |
| limpio (terceros) | payload | 0.9908 ± 0.0069 | 1.0000 |
| limpio (terceros) | meta-basica | 0.9793 ± 0.0194 | 1.0000 |
| limpio (terceros) | meta-rica | 1.0000 ± 0.0000 | 1.0000 |

## Lectura honesta

- **Benigno contaminado (todos):** payload y meta-basica se quedan en el azar
  (~0.57 / ~0.61, reproduciendo el paso 2). El "benigno" es 78,6% el propio
  atacante fuera de ventana, indistinguible del ataque (mismas rafagas, mismos
  n_pkts/bytes). La **meta-rica sube a ~0.78** porque la rafaga rescata al menos
  los 433 benignos genuinos, pero el techo lo impone la contaminacion. **El 0.61
  del paso 2 era un artefacto del benigno contaminado, no un limite de la vista.**
- **Benigno limpio (terceros):** las tres vistas separan bien, pero por motivos
  MUY distintos (y esto es lo importante para la tesis):
  - **meta-rica (rafaga) ~1.00:** el benigno genuino abre ~1 conexion/5s y el
    ataque ~86. Es la firma del brute-force, **conductual y agnostica a la
    herramienta**: generaliza a cualquier origen de alta tasa. La vista mas robusta.
  - **meta-basica ~0.98:** n_pkts/bytes (31 vs 12) ya distinguen bastante.
  - **payload ~0.99, pero es una HUELLA DE HERRAMIENTA, no del cifrado:** el
    atacante usa un cliente fijo (`paramiko`, 2 banners SSH
    en claro distintos) frente a 81 banners de clientes
    legitimos diversos (PuTTY, libssh2, OpenSSH...). El modelo NO lee el contenido
    cifrado (entropia ~7.4 en ambos); lee el **banner del handshake en claro**. Es
    señal real pero **evadible**: basta que el atacante falsee el banner para anularla.

**Conclusion:** la tesis se confirma y se matiza. (1) El supuesto techo de 0.61 del
paso 2 era contaminacion del benigno por el atacante, no un limite de los metadatos.
(2) Con benigno limpio, la firma **robusta y generalizable** del SSH-Bruteforce vive
en el COMPORTAMIENTO de flujo (la rafaga), no en los bytes: el exito del payload es
un fingerprint de la herramienta (`paramiko`) que un atacante evade trivialmente,
mientras que la rafaga de conexiones es intrinseca al ataque. Refuerza HALLAZGO 3:
el payload no "ve" el cifrado; cuando parece verlo, esta leyendo metadatos en claro.

## Detalle: contaminado (todos)

### payload
```
                precision    recall  f1-score   support

        Benign     0.6068    0.4840    0.5385       405
SSH-Bruteforce     0.5700    0.6856    0.6225       404

      accuracy                         0.5847       809
     macro avg     0.5884    0.5848    0.5805       809
  weighted avg     0.5884    0.5847    0.5804       809

Matriz de confusion (filas=real, cols=pred):
[[196 209]
 [127 277]]
```

### meta-basica
```
                precision    recall  f1-score   support

        Benign     0.6667    0.5531    0.6046       405
SSH-Bruteforce     0.6173    0.7228    0.6659       404

      accuracy                         0.6378       809
     macro avg     0.6420    0.6379    0.6352       809
  weighted avg     0.6420    0.6378    0.6352       809

Matriz de confusion (filas=real, cols=pred):
[[224 181]
 [112 292]]
```

### meta-rica
```
                precision    recall  f1-score   support

        Benign     0.7568    0.8914    0.8186       405
SSH-Bruteforce     0.8675    0.7129    0.7826       404

      accuracy                         0.8022       809
     macro avg     0.8121    0.8021    0.8006       809
  weighted avg     0.8121    0.8022    0.8006       809

Matriz de confusion (filas=real, cols=pred):
[[361  44]
 [116 288]]
```

## Detalle: limpio (terceros)

### payload
```
                precision    recall  f1-score   support

        Benign     1.0000    1.0000    1.0000        87
SSH-Bruteforce     1.0000    1.0000    1.0000        87

      accuracy                         1.0000       174
     macro avg     1.0000    1.0000    1.0000       174
  weighted avg     1.0000    1.0000    1.0000       174

Matriz de confusion (filas=real, cols=pred):
[[87  0]
 [ 0 87]]
```

### meta-basica
```
                precision    recall  f1-score   support

        Benign     1.0000    1.0000    1.0000        87
SSH-Bruteforce     1.0000    1.0000    1.0000        87

      accuracy                         1.0000       174
     macro avg     1.0000    1.0000    1.0000       174
  weighted avg     1.0000    1.0000    1.0000       174

Matriz de confusion (filas=real, cols=pred):
[[87  0]
 [ 0 87]]
```

### meta-rica
```
                precision    recall  f1-score   support

        Benign     1.0000    1.0000    1.0000        87
SSH-Bruteforce     1.0000    1.0000    1.0000        87

      accuracy                         1.0000       174
     macro avg     1.0000    1.0000    1.0000       174
  weighted avg     1.0000    1.0000    1.0000       174

Matriz de confusion (filas=real, cols=pred):
[[87  0]
 [ 0 87]]
```

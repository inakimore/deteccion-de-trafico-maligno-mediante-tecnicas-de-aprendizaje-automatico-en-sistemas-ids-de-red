# Fase 3 (Eje D) - Interpretabilidad: por que el byte-CNN 've' el SSH cifrado (Wednesday-14-02-2018)

El byte-CNN separa SSH-ataque de SSH-benigno limpio casi perfecto (~0.99), pero
el SSH esta CIFRADO. Este analisis muestra que el modelo decide por el BANNER
del handshake (en claro), no por el contenido cifrado.

- **Saliency:** el 31.1% de la importancia media se concentra en
  los primeros 48 bytes del flujo (la zona del banner), no en el cuerpo
  cifrado. Ver `phase2_saliency_ssh.png`.

- **Banner modal del ATAQUE** (primeros 48 bytes, byte mas frecuente por
  posicion): `SSH-2.0-paramiko_2.0.0..SSH-2.0-OpenSSH_7.2p2 Ub`

- **Banners BENIGNOS** (diversos, 5 ejemplos):

```
  ..K...O....\s...h.G........^../}WC......
  SSH-2.0-libssh2_1.7.0..SSH-2.0-OpenSSH_7
  SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4.
  SSH-2.0-PUTTY..SSH-2.0-OpenSSH_7.2p2 Ubu
  SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4.
```

**Conclusion:** el exito del payload sobre el SSH cifrado es un *fingerprint* del
cliente del atacante (banner en claro), no una lectura del cifrado; es una senal
real pero EVADIBLE (basta falsear el banner). La firma robusta del brute-force
sigue siendo conductual (rafaga de conexiones). Refuerza la tesis del enfoque
hibrido: el payload aporta en claro, la conducta aporta cuando el contenido no.
# Eje E - El inter-arribo como vista, y su robustez ante evasion (Friday-16-02-2018)

Binario Attack vs Benign en servicio=http (DPI), balanceado 1:1, split 70/30. El atacante camufla los primeros **160 bytes** de cada flujo de ataque con los de un cliente benigno; el resto del flujo no cambia.

| Vista | Recall ataque (original) | Recall ataque (evadido) | Caida |
|-------|--------------------------|-------------------------|-------|
| payload (byte-CNN) | 1.0000 | 0.0417 | **0.9583** |
| meta+rafaga | 1.0000 | 1.0000 | **0.0000** |
| inter-arribo SOLO | 0.9950 | 0.9950 | **0.0000** |
| meta+inter-arribo | 0.9942 | 0.9942 | **0.0000** |

Caracteristicas de inter-arribo (6, ventana de 8 vecinos del mismo origen): `dt_prev`, `dt_next`, `media_local`, **`cv_local`** (coeficiente de variacion: ~0 en un metronomo), `regularidad` y `frac_cerca_mediana`. Se calculan desde el `.npz` (`ts` + `orig_h`), **sin necesidad del `conn.log`**.

Las tres vistas conductuales son **invariantes al spoofing de payload** por construccion: no miran el contenido de los bytes, sino cuando llegan los flujos y cuantos hay. Por eso su recall evadido es identico al original.

# Leave-one-attacker-out - Tuesday-20-02-2018

Servicio: servicio=http (DPI). Clase positiva: [np.str_('DDoS-LOIC-HTTP')]. **10 hosts atacantes** y 469 hosts benignos.

Cada pliegue aparta un host atacante entero **y** un grupo disjunto de hosts benignos, entrena con 5000 flujos por clase y evalua sobre 2000 por clase. El **control** usa exactamente los mismos tamanos con particion aleatoria por flujo, ignorando el host: sin el, una caida podria deberse al tamano del entrenamiento y no al cambio de host.

| Vista | Control (aleatorio) | LOAO (atacante no visto) | Diferencia |
|---|---|---|---|
| payload (histograma + entropia) | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 | +0.0000 |
| metadatos de flujo | 0.9991 ± 0.0005 | 0.9992 ± 0.0006 | +0.0001 |
| conducta (metadatos + rafaga) | 0.9986 ± 0.0006 | 0.9990 ± 0.0007 | +0.0004 |
| [control] octetos de la IP de origen | 0.9999 ± 0.0001 | 0.9332 ± 0.2000 | -0.0667 |

Recall de la clase de ataque:

| Vista | Control | LOAO |
|---|---|---|
| payload (histograma + entropia) | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| metadatos de flujo | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| conducta (metadatos + rafaga) | 0.9990 ± 0.0011 | 0.9992 ± 0.0010 |
| [control] octetos de la IP de origen | 1.0000 ± 0.0000 | 0.9000 ± 0.3000 |

**Como leer la tabla.** Si el exito intra-dia se debiera a memorizar el host atacante, la columna LOAO deberia hundirse frente al control.

La fila `[control] octetos de la IP de origen` **no es una vista candidata**: es un identificador de host puro, incluido para comprobar que el protocolo detecta la memorizacion cuando existe. Debe dar ~1.0 en la particion aleatoria y desplomarse en LOAO. Si no se desploma, el test no es sensible y el resultado de las otras tres vistas no significa nada.

**Matiz importante:** los diez atacantes ejecutan la MISMA herramienta (LOIC), asi que este test distingue *memorizar el host* de *aprender la herramienta o la conducta*, pero NO distingue *aprender la herramienta* de *aprender el ataque*. Para eso hacen falta la evasion y la transferencia entre dominios.

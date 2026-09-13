# Fase 3 (Eje C) - Infiltration (Wednesday-28-02-2018): resultado NEGATIVO

> **Este día se analizó pero NO se construyó su dataset, deliberadamente.** El motivo es el
> resultado: el pipeline de payload es **ciego por construcción** a la mayor parte del
> ataque. Ver **HALLAZGO CLAVE 16** en el README y el diario del 19-21 de agosto.

Fuente de los datos: `conn.log` de Zeek sobre `capEC2AMAZ-O4EL3NG-172.31.69.24-part2`
(196.699 conexiones), conservado en
`data/processed/zeek/wednesday-28-02-2018/conn_probe_victim24p2/`.
**No hay `.npz` de este día**, así que estas cifras **no** salen de `extraer_datos.py`.

## Localización de la ground-truth

El CSV del día no trae IPs y los puertos del ataque están dispersos (53: 24.522 flujos,
443: 17.000, 3389: 4.400, 80: 2.851, 445: 2.286, 135, 139, 22, 137, 123, 67...), lo que
descarta que sea un ataque contra un servicio concreto.

`find_host.py --ip 13.58.225.34` (la IP que la documentación da como atacante) la encuentra
**1.669 veces** en `capEC2AMAZ-O4EL3NG-172.31.69.24-part2` y 1-2 veces (ruido de coincidencia
binaria) en las otras 436 capturas. **Víctima: `172.31.69.24`.**

*Nota: `172.31.69.24` es el mismo host cuya captura falta en el día Bot (02-03), donde el
archivo oficial trae un acceso directo de Windows de 697 B en su lugar.*

## Las dos fases del ataque

| Fase | Conexiones | Puerto | Payload |
|------|-----------:|--------|---------|
| Canal C2 (`13.58.225.34` <-> víctima) | 5 | **31337** | **100% con payload**, 195.816 B |
| Escaneo interno (víctima -> 612 destinos) | 193.097 | 53, 135, 443, 22, 445, 3389... | **94,4% SIN payload** |

Ventana del C2: 10:45:40-14:17:21 local. Ventana de la actividad saliente de la víctima:
10:38:27-17:42:23 local.

## Visibilidad para un pipeline basado en contenido

| Métrica | Valor |
|---------|------:|
| Conexiones salientes de la víctima | 193.097 |
| Con payload de aplicación | **10.774 (5,6%)** |
| Sin payload de aplicación | **182.323 (94,4%)** |
| Sin servicio identificable por Zeek (`service = "-"`) | 183.907 |

### `conn_state` del escaneo

| Estado | Conexiones | Lectura |
|--------|-----------:|---------|
| `S0` | 158.474 (82%) | SYN sin respuesta -> **el escaneo** |
| `REJ` | 21.069 | conexión rechazada |
| `SF` | 8.505 | establecida y cerrada |
| `RSTR` | 2.255 | reset por el receptor |
| `S1` | 1.140 | establecida sin cerrar |
| `SH` | 988 | SYN + FIN sin respuesta |

## Por qué no se construye el dataset

1. **Solo el 5,6% del ataque sería visible**, así que la clase `Infilteration` resultante
   sería una muestra sesgada y no representativa del ataque real.
2. **El ataque no se puede expresar** con el modelo de `attack_metadata.py`
   (`{atacante, víctima}:puerto + ventana`): es **un origen contra 612 destinos** en decenas
   de puertos. Enumerar los 612 como `victim_ips` haría que la regla `pair.issubset(ips)` de
   `DayLabeler` etiquetase como ataque **cualquier flujo entre dos hosts internos**.
   Tampoco vale "todo lo que salga de la víctima": su ventana saliente llega a las 17:42 y
   buena parte es tráfico legítimo suyo (DNS, SSL).

Etiquetarlo correctamente exigiría una regla basada en **origen + `conn_state` + fan-out**,
no en el par de IPs. Queda como trabajo futuro explícito.

## Qué sí lo detectaría

La firma de este ataque es el **abanico** (un origen, 612 destinos distintos) y el
**`conn_state`** (82% de SYN sin respuesta). Ninguna de las dos vive en el payload y ninguna
la mide el pipeline actual: son exactamente las features del **Eje E** (`conn.log`).
Junto con el *beaconing* del Bot (HALLAZGO 15), este día convierte el Eje E de "opcional,
retorno marginal" en la ampliación pendiente con mayor retorno del trabajo.

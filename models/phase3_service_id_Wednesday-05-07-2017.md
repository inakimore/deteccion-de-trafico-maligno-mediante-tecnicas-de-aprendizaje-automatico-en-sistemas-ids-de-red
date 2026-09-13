# Servicio por contenido vs puerto (Wednesday-05-07-2017)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **263,226**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| http | 191,173 | 72.63% |
| ssl | 66,837 | 25.39% |
| other | 3,442 | 1.31% |
| ssh | 1,060 | 0.40% |
| ftp | 533 | 0.20% |
| smb | 181 | 0.07% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **260,796**
- El contenido confirma el servicio del puerto: **259,410** (99.47%)
- El contenido lo **contradice**: **1,386**

## Servicio bajo estudio: `http` (puerto 80)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 80 | 192,437 | 170,032 | 22,405 |
| servicio == http (DPI) | 191,173 | 168,817 | 22,356 |
| ambos (interseccion) | 191,164 | 168,817 | 22,347 |

- En el puerto 80 pero **sin** el contenido de `http`: **1,273** flujos (1,215 de ataque). Reparto real: `other` 1,273.
- Con contenido `http` **fuera** del puerto 80: **9** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

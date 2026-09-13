# Servicio por contenido vs puerto (Thursday-06-07-2017)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **83,886**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| ssl | 57,572 | 68.63% |
| http | 22,203 | 26.47% |
| other | 1,949 | 2.32% |
| ssh | 1,112 | 1.33% |
| ftp | 534 | 0.64% |
| smb | 516 | 0.62% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **81,352**
- El contenido confirma el servicio del puerto: **81,330** (99.97%)
- El contenido lo **contradice**: **22**

## Servicio bajo estudio: `http` (puerto 80)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 80 | 22,114 | 174 | 21,940 |
| servicio == http (DPI) | 22,203 | 174 | 22,029 |
| ambos (interseccion) | 22,104 | 174 | 21,930 |

- En el puerto 80 pero **sin** el contenido de `http`: **10** flujos (0 de ataque). Reparto real: `other` 10.
- Con contenido `http` **fuera** del puerto 80: **99** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

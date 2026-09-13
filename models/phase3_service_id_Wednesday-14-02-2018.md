# Servicio por contenido vs puerto (Wednesday-14-02-2018)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **2,202,231**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| rdp | 765,774 | 34.77% |
| ssl | 717,712 | 32.59% |
| http | 422,005 | 19.16% |
| smb | 200,548 | 9.11% |
| ssh | 94,565 | 4.29% |
| other | 1,626 | 0.07% |
| ftp | 1 | 0.00% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **2,200,888**
- El contenido confirma el servicio del puerto: **2,200,419** (99.98%)
- El contenido lo **contradice**: **469**

## Servicio bajo estudio: `ssh` (puerto 22)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 22 | 94,640 | 94,207 | 433 |
| servicio == ssh (DPI) | 94,565 | 94,207 | 358 |
| ambos (interseccion) | 94,565 | 94,207 | 358 |

- En el puerto 22 pero **sin** el contenido de `ssh`: **75** flujos (0 de ataque). Reparto real: `other` 75.
- Con contenido `ssh` **fuera** del puerto 22: **0** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

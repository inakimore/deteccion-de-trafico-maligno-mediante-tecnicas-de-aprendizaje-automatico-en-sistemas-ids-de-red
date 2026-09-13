# Servicio por contenido vs puerto (Tuesday-04-07-2017)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **100,871**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| ssl | 66,942 | 66.36% |
| http | 22,807 | 22.61% |
| ftp | 4,492 | 4.45% |
| ssh | 4,023 | 3.99% |
| other | 2,426 | 2.41% |
| smb | 181 | 0.18% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **98,154**
- El contenido confirma el servicio del puerto: **98,033** (99.88%)
- El contenido lo **contradice**: **121**

## Servicio bajo estudio: `ssh` (puerto 22)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 22 | 4,023 | 2,979 | 1,044 |
| servicio == ssh (DPI) | 4,023 | 2,979 | 1,044 |
| ambos (interseccion) | 4,023 | 2,979 | 1,044 |

- En el puerto 22 pero **sin** el contenido de `ssh`: **0** flujos (0 de ataque). Reparto real: .
- Con contenido `ssh` **fuera** del puerto 22: **0** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

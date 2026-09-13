# Servicio por contenido vs puerto (Friday-16-02-2018)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **4,041,078**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| http | 2,200,137 | 54.44% |
| rdp | 978,251 | 24.21% |
| ssl | 660,567 | 16.35% |
| smb | 198,767 | 4.92% |
| other | 2,928 | 0.07% |
| ssh | 428 | 0.01% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **4,038,401**
- El contenido confirma el servicio del puerto: **4,037,957** (99.99%)
- El contenido lo **contradice**: **444**

## Servicio bajo estudio: `http` (puerto 80)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 80 | 2,200,211 | 1,062,339 | 1,137,872 |
| servicio == http (DPI) | 2,200,137 | 1,062,339 | 1,137,798 |
| ambos (interseccion) | 2,200,076 | 1,062,339 | 1,137,737 |

- En el puerto 80 pero **sin** el contenido de `http`: **135** flujos (0 de ataque). Reparto real: `other` 135.
- Con contenido `http` **fuera** del puerto 80: **61** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

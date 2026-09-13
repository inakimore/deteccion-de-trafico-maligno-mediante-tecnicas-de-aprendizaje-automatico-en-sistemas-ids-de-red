# Servicio por contenido vs puerto (Thursday-22-02-2018)

Correccion del tutor (11-ago): el puerto depende de la configuracion de
cada red y no es un atributo *context independent*, asi que no puede
definir el servicio. Aqui el servicio se identifica por el CONTENIDO, con
las mismas firmas que usan los analizadores de Zeek para rellenar
`conn.log$service` (banner SSH, metodos HTTP, record TLS, NBSS/SMB,
TPKT/X.224, saludos SMTP/FTP/POP3/IMAP, IAC de Telnet, greeting MySQL).

Flujos analizados: **2,777,898**

## Servicios detectados

| Servicio | Flujos | % |
|----------|--------|---|
| rdp | 1,313,251 | 47.27% |
| ssl | 736,575 | 26.52% |
| http | 459,946 | 16.56% |
| smb | 258,837 | 9.32% |
| other | 8,041 | 0.29% |
| ssh | 1,248 | 0.04% |

## Acuerdo con la convencion de puertos

- Flujos con puerto conocido y con payload: **2,769,964**
- El contenido confirma el servicio del puerto: **2,769,217** (99.97%)
- El contenido lo **contradice**: **747**

## Servicio bajo estudio: `http` (puerto 80)

| Criterio de seleccion | Flujos | Ataque | Benigno |
|-----------------------|--------|--------|---------|
| puerto == 80 | 459,857 | 203 | 459,654 |
| servicio == http (DPI) | 459,946 | 203 | 459,743 |
| ambos (interseccion) | 459,746 | 203 | 459,543 |

- En el puerto 80 pero **sin** el contenido de `http`: **111** flujos (0 de ataque). Reparto real: `other` 111.
- Con contenido `http` **fuera** del puerto 80: **200** flujos (0 de ataque). Son justo los que la seleccion por puerto se dejaba fuera.

#!/usr/bin/env python3
"""Ground-truth de ataques para etiquetar payloads (TFG Fase 2/3).

Cubre DOS datasets, para el experimento de generalizacion cruzada entre ellos:
  - CSE-CIC-IDS2018 (dias 14-02, 16-02, 22-02) -> status "verified".
  - CIC-IDS2017     (dias 04/05/06-07)         -> status "documented" (VERIFICAR
    IPs/ventanas/tz con find_attacker.py antes de construir su dataset).
Ambos comparten el mismo esquema de etiquetado (par {atacante, victima} + puerto +
ventana), asi que el mismo DayLabeler sirve para los dos.

POR QUE EXISTE ESTE FICHERO
---------------------------
Los CSV del dataset (CICFlowMeter) NO contienen las IPs de origen/destino: solo
traen `Dst Port`, `Protocol`, `Timestamp` y `Label`. Por tanto NO se puede hacer
un join exacto por 5-tupla entre los payloads extraidos con Zeek (que si tienen
IPs) y las etiquetas del CSV. La estrategia robusta y estandar en la literatura
es etiquetar por la informacion documentada del ataque: IP atacante, IP victima,
puerto del servicio atacado y ventana temporal.

ZONA HORARIA (importante)
-------------------------
- Los timestamps de los PCAP (y de los TSV de payload) estan en EPOCH UTC.
- Los timestamps del CSV y de la documentacion oficial estan en hora LOCAL del
  laboratorio, que para este dataset es UTC-4. Verificado empiricamente: el CSV
  del 14-02 empieza en "08:31:01" y el primer paquete del PCAP del mismo dia cae
  en 12:30 UTC (12:30 - 4h = 08:30 local). El campo `tz_offset_hours` codifica
  ese desfase para convertir las ventanas locales a epoch UTC.

COMO EXTENDER A OTROS DIAS
--------------------------
Vamos dia a dia (cada dia ocupa >30 GB). Para anadir un dia nuevo:
  1. Anade una entrada en DAYS con su `tz_offset_hours` y su lista de `attacks`.
  2. Cada ataque necesita: label, attacker_ips, victim_ips, victim_ports y la
     ventana [start_local, end_local] (hora local, formato "YYYY-MM-DD HH:MM").
  3. Verifica las IPs reales con conn.log (ver README) antes de darlo por bueno.

El emparejamiento de un flujo a un ataque es: que el par {orig_h, resp_h}
coincida con {attacker_ip, victim_ip}, que el puerto de la victima este en
victim_ports y que el timestamp caiga en la ventana. Si no coincide con ningun
ataque -> "Benign".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Estado de verificacion de cada ataque:
#   "verified"   -> IPs/puertos confirmados con los datos (conn.log).
#   "documented" -> tomado de la documentacion oficial, aun sin confirmar en los
#                   PCAP locales (p.ej. porque la captura que lo contiene todavia
#                   no se ha procesado).
DAYS: dict[str, dict] = {
    "Wednesday-14-02-2018": {
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "FTP-BruteForce",
                "attacker_ips": ["18.221.219.4"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [21],
                "start_local": "2018-02-14 10:32",
                "end_local": "2018-02-14 12:09",
                # Confirmado: 162.801 conexiones 18.221.219.4 -> 172.31.69.25:21
                # en la captura UCAP172.31.69.25 (ventana 10:33-11:55 local).
                # HALLAZGO CLAVE: las 134.945 conexiones FTP estan en estado REJ
                # con 0 bytes (el servicio FTP del host estaba caido y rechazo
                # todos los intentos). NO hay payload de aplicacion -> este ataque
                # es INVISIBLE para el analisis de payload en esta captura.
                "status": "verified",
                "payload_note": "REJ/0 bytes: sin payload de aplicacion",
            },
            {
                "label": "SSH-Bruteforce",
                "attacker_ips": ["13.58.98.64"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [22],
                "start_local": "2018-02-14 14:01",
                "end_local": "2018-02-14 15:33",
                # Confirmado: 94.207 flujos 13.58.98.64 -> 172.31.69.25:22 con
                # payload real (handshakes SSH cifrados, ~2,9 M paquetes). OJO: el
                # atacante SSH es OTRA IP distinta de la del FTP (ambas son hosts
                # atacantes en AWS us-east-2). Solo fue visible tras REPARAR la
                # captura .25 (truncatura intermedia que hacia que Zeek se detuviera
                # a las 18:05 UTC; ver README).
                # CORRECCION 17-jun: el fin de ventana documentado (15:31 local =
                # 19:31 UTC) cortaba 90 s ANTES del final real del ataque. Verificado
                # con el meta CSV: el atacante conecta EXCLUSIVAMENTE a la victima:22
                # en una rafaga continua (gap maximo 1 s) de 18:01:50 a 19:32:30 UTC.
                # Los 1.589 flujos posteriores a 19:31 quedaban mal etiquetados como
                # Benign (contaminaban el "SSH benigno" al 78,6%; ver entrada del
                # 17-jun en README). Se amplia el fin a 15:33 local (19:33 UTC) para
                # cubrir la cola verificada. El emparejamiento por par {atacante,
                # victima} impide reetiquetar a terceros que toquen el :22.
                "status": "verified",
                "payload_note": "SF con payload cifrado (a diferencia del FTP, que es REJ)",
            },
        ],
    },
    "Thursday-22-02-2018": {
        # Web Attacks (HTTP en claro). Verificado el 07-jul con find_host + Zeek:
        # el atacante 18.218.115.60 se concentra en UNA captura (UCAP172.31.69.28,
        # 24 MB) y TODO su trafico (21.607 paquetes) va a 172.31.69.28:80 contra la
        # app vulnerable DVWA (POST /DVWA/login.php, etc.). tz -4 confirmado: el CSV
        # empieza a las 10:13 local = 14:13 UTC del primer paquete del atacante.
        #
        # A diferencia del SSH (payload cifrado -> ciego), aqui el payload esta EN
        # CLARO: se distinguen los 3 tipos de ataque a nivel de bytes (login POST,
        # <script>, union select). La actividad del atacante forma 3 clusters
        # separados por huecos que casan con las ventanas documentadas del dataset:
        #   Web-BF  10:10-11:20 | XSS 13:50-14:20 (tras gap) | SQLi 16:10-16:20 (tras gap)
        # Se codifican como 3 ataques con el MISMO par {atacante,victima}:80 y
        # ventanas disjuntas: cada flujo cae en su sub-ataque por su timestamp.
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "Brute Force -Web",
                "attacker_ips": ["18.218.115.60"],
                "victim_ips": ["172.31.69.28"],
                "victim_ports": [80],
                "start_local": "2018-02-22 10:13",
                "end_local": "2018-02-22 11:25",
                "status": "verified",
                "payload_note": "HTTP en claro: POST /DVWA/login.php (fuerza bruta web)",
            },
            {
                "label": "Brute Force -XSS",
                "attacker_ips": ["18.218.115.60"],
                "victim_ips": ["172.31.69.28"],
                "victim_ports": [80],
                "start_local": "2018-02-22 13:50",
                "end_local": "2018-02-22 14:30",
                "status": "verified",
                "payload_note": "HTTP en claro: payloads con <script>/onerror= (XSS)",
            },
            {
                "label": "SQL Injection",
                "attacker_ips": ["18.218.115.60"],
                "victim_ips": ["172.31.69.28"],
                "victim_ports": [80],
                "start_local": "2018-02-22 16:08",
                "end_local": "2018-02-22 16:30",
                "status": "verified",
                "payload_note": "HTTP en claro: payloads con union select / or 1=1 (SQLi)",
            },
        ],
    },
    "Friday-16-02-2018": {
        # DoS VOLUMETRICO. Verificado el 14-jul con find_attacker.py (conn.log de
        # la captura de la victima UCAP172.31.69.25-part1.pcap, que es pcapng ->
        # Zeek la lee de forma nativa, sin el saneado clasico). Los dos atacantes
        # aplastan el ranking de top-talkers, asi que se identifican SIN IP previa:
        #   - DoS-Hulk:         18.219.193.20 -> 172.31.69.25:80  (999.007 conex.)
        #                       UTC 17:45:27-17:52:34 = local 13:45-13:52. Flood
        #                       HTTP rapido: ~1 M de conexiones en ~7 min, payload
        #                       HTTP EN CLARO (http.log de 244 MB en una sola captura).
        #   - DoS-SlowHTTPTest: 13.59.126.31  -> 172.31.69.25:21  (105.550 conex.)
        #                       UTC 14:12:14-15:05:13 = local 10:12-11:05. Ataque
        #                       LENTO (mantiene conexiones abiertas ~53 min).
        # OJO (empirico, no de la doc): SlowHTTPTest ataca el puerto 21, no el 80.
        # Se registra lo verificado en los datos (leccion del SSH: la doc erraba).
        # Las ventanas del CSV confirman el emparejamiento (Hulk 13:45 -garbled como
        # 01:45 por el bug 12h/24h de CICFlowMeter-, SlowHTTPTest 10:12-10:58).
        # Mismo victima que el 14-02 pero distinto dia; el emparejamiento por par
        # {atacante, victima}:puerto + ventana impide colisiones.
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "DoS-Hulk",
                "attacker_ips": ["18.219.193.20"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [80],
                "start_local": "2018-02-16 13:45",
                # CORREGIDO el 11-ago (mismo error de limite de ventana que el SSH
                # el 17-jun). El fin anterior (13:53) venia del conn.log de UNA sola
                # captura (UCAP...-part1), pero sobre el dataset COMPLETO el flood
                # del atacante es continuo hasta las 17:58:22 UTC = 13:58:22 local
                # (1.803.160 flujos a 172.31.69.25:80, gap MAXIMO entre conexiones
                # de 0,2 s; ningun hueco > 60 s). Los 740.821 flujos de la cola
                # (65,1% del "benigno" HTTP del dia) estaban etiquetados Benign
                # siendo del propio atacante -> comparabamos ataque contra ataque.
                "end_local": "2018-02-16 13:59",
                "status": "verified",
                "payload_note": "HTTP en claro: flood de GET (Hulk); alto volumen + payload",
            },
            {
                "label": "DoS-SlowHTTPTest",
                "attacker_ips": ["13.59.126.31"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [21],
                "start_local": "2018-02-16 10:12",
                "end_local": "2018-02-16 11:06",
                "status": "verified",
                "payload_note": "ataque lento sobre :21 (conexiones mantenidas); firma conductual",
            },
        ],
    },

    "Tuesday-20-02-2018": {
        # DDoS DISTRIBUIDO (10 origenes). Verificado el 18-ago con find_attacker.py
        # sobre la captura de la victima UCAP172.31.69.25 (pcap clasico, 8,5 GB ->
        # saneado normal; Zeek exit 0, 291.917 conexiones). Los 10 atacantes copan
        # el ranking de top-talkers con 27.897-29.749 conexiones CADA UNO, asi que
        # se identifican SIN IP previa; el 11º origen del ranking tiene 52.
        #   - DDoS-LOIC-HTTP: 10 IPs -> 172.31.69.25:80 (290.956 conex. TCP)
        #                     UTC 14:13:54-17:15:16 = local 10:13:54-13:15:16.
        # DIFERENCIA CLAVE frente al DoS-Hulk del 16-02: aquel era UN origen con
        # ~1 M de conexiones; aqui son DIEZ con ~29 k cada uno. La rafaga POR ORIGEN
        # es ~34x menor, asi que es el caso dificil del regimen volumetrico (util
        # para contrastar dos_burst.py: el agregado por origen se diluye al repartir
        # el flood entre 10 fuentes).
        # conn_state RSTO en el ~97% de las conexiones (el originador manda RST):
        # firma conductual limpia de LOIC.
        # ANOMALIA: 18.218.115.60 hace 27.897 conexiones pero solo 31 MB de bytes de
        # aplicacion, frente a los 252-402 MB de los otros nueve. Mismo numero de
        # conexiones, un orden de magnitud menos de payload.
        #
        # VENTANA (analisis de huecos sobre el conn.log, no del CSV): el ataque NO es
        # continuo, son TRES episodios -- flood principal 10:13:54-11:16:48 (continuo,
        # hueco maximo 1,1 s, ~289.500 conex.), un blip de 66 conex. a las 11:40:08 y
        # una segunda rafaga 13:14:17-13:15:16 (1.463 conex.). Entre 11:16 y 13:14 hay
        # 94 min sin UNA sola conexion. Se usa UNA ventana ancha que cubre los tres:
        # esas 10 IPs solo hablan con la victima por el :80 (290.956 TCP + 100 UDP +
        # 10 ICMP, cero trafico benigno), asi que ensanchar NO mal-etiqueta nada y si
        # evita dejar como "Benign" el blip de las 11:40, que es del propio atacante
        # (la contaminacion del SSH el 17-jun y del Hulk el 11-ago, misma leccion).
        # El CSV del dia solo etiqueta 10:15-11:16 y 13:14-13:29 (estas ultimas 797
        # filas aparecen como "01:14-01:29" por el bug 12h/24h de CICFlowMeter), y
        # deja fuera el blip; se prefiere lo verificado en los datos.
        # OJO: la doc oficial situa un DDoS-LOIC-UDP en la franja de tarde del 20-02,
        # pero en los datos esa segunda rafaga va contra el :80 y el CSV la etiqueta
        # LOIC-HTTP. Se registra lo observado.
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "DDoS-LOIC-HTTP",
                "attacker_ips": [
                    "18.219.9.1", "18.218.229.235", "52.14.136.135",
                    "18.216.200.189", "18.218.55.126", "18.219.5.43",
                    "18.216.24.42", "18.218.11.51", "18.219.32.43",
                    "18.218.115.60",
                ],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [80],
                "start_local": "2018-02-20 10:13",
                "end_local": "2018-02-20 13:16",
                "status": "verified",
                "payload_note": "HTTP en claro (LOIC), pero DISTRIBUIDO en 10 origenes: el volumen por origen cae ~34x frente al Hulk",
            },
        ],
    },

    "Friday-02-03-2018": {
        # BOTNET (Ares). Verificado el 21-ago sobre los TSV de payload de las 442
        # capturas del dia (no con find_attacker.py: aqui NO hay una victima unica
        # que domine el ranking de top-talkers, que es lo que ese script busca; la
        # estructura es un C2 externo y muchos hosts internos infectados).
        # PROCEDIMIENTO: se extrajo primero el payload de todo el dia y el C2 se
        # localizo despues sobre los TSV, buscando destinos comunes en el :8080 que
        # el CSV del dia senala como puerto del Bot (281.634 de 286.191 flujos).
        #   - C2: 18.219.211.138, SOLO puerto 8080 (438.825 paquetes; ningun otro).
        #   - 10 bots, todos en 172.31.69.x: .6 .8 .10 .12 .14 .17 .23 .26 .29 .30
        #     Nueve baten ~15.000 flujos cada uno; 172.31.69.12 solo 4.988 (un
        #     tercio), asi que se infecto tarde o dejo de responder antes.
        # VENTANA: 10:13:28-15:53:46 local, CONTINUA -hueco maximo 32,6 s en 5 h
        # 40 min-. La doc oficial parte el Bot en dos franjas (10:11-11:35 y
        # 14:24-15:55); en los datos NO hay tal corte. Es la tercera vez que la doc
        # no cuadra con las capturas (SSH 17-jun, Hulk 11-ago), asi que se registra
        # lo verificado.
        # FIRMA (perfil temporal, ver el diario del 21-ago): de 11:40 a 15:20 el
        # trafico al C2 es una MESETA PLANA de ~8.035 paquetes cada 10 min, constante
        # hasta la tercera cifra -beaconing periodico-, con rampa previa (pico de
        # 38.000 a las 11:10-11:30) y picos de ordenes a las 14:20 y 15:30-15:50.
        # Es un regimen distinto de los tres ya cubiertos: la firma no esta en el
        # payload ni en el volumen sino en la PERIODICIDAD (engancha con el Eje E).
        # tz UTC-4 CONFIRMADA empiricamente: el 2 de marzo es aun EST (UTC-5) por
        # calendario, pero con -5 las horas no cuadran con el CSV del dia (saldrian
        # las 09-14 h y el CSV marca 10-15 h); con -4 encajan exactamente.
        # SEGURO para el issubset de DayLabeler: 0 paquetes bot<->bot con :8080 en
        # origen o destino, asi que meter los 10 bots como victim_ips no puede
        # etiquetar como Bot un flujo interno entre dos infectados.
        # OJO (defecto del dataset original): el host 172.31.69.24 NO tiene captura;
        # el archivo oficial trae en su lugar un acceso directo de Windows de 697 B
        # ("capEC2AMAZ-O4EL3NG-172.31.69.24 - Shortcut.lnk"). Si fue un bot, su
        # trafico no esta en los datos y no puede etiquetarse.
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "Bot",
                "attacker_ips": ["18.219.211.138"],
                "victim_ips": [
                    "172.31.69.6", "172.31.69.8", "172.31.69.10", "172.31.69.12",
                    "172.31.69.14", "172.31.69.17", "172.31.69.23", "172.31.69.26",
                    "172.31.69.29", "172.31.69.30",
                ],
                "victim_ports": [8080],
                "start_local": "2018-03-02 10:13",
                "end_local": "2018-03-02 15:54",
                "status": "verified",
                "payload_note": "C2 de Ares sobre HTTP:8080; la firma diferencial es el beaconing periodico, no el contenido",
            },
        ],
    },

    "Thursday-15-02-2018": {
        # DoS VOLUMETRICO (dos herramientas). Verificado el 21-ago con
        # find_attacker.py sobre UCAP172.31.69.25 (38.536 conexiones, Zeek exit 0).
        # Los dos atacantes copan el ranking sin necesidad de IP previa: 29.696 y
        # 7.248 conexiones, frente a 131 del tercero.
        #   - DoS-GoldenEye: 18.219.211.138 -> 172.31.69.25:80 (29.696 conex.)
        #                    UTC 13:27:42-14:11:45 = local 09:27:42-10:11:45.
        #                    conn_state RSTO:23272 S3:2624 OTH:2623 RSTR:964.
        #                    A OLEADAS: huecos de hasta 528,8 s (8,8 min) entre
        #                    rafagas, con picos de 9.018 conexiones en 5 min.
        #   - DoS-Slowloris: 18.217.165.70 -> 172.31.69.25:80 (7.248 conex.)
        #                    UTC 15:00:12-15:41:34 = local 11:00:12-11:41:34.
        #                    conn_state RSTR:4615 S0:2233 SF:382. CONTINUO (hueco
        #                    maximo 9,8 s) y con un goteo PLANO de ~800-850 conex.
        #                    cada 5 min: es el diseno del ataque (mantiene
        #                    conexiones abiertas a ritmo constante), no un beacon.
        # TERCER DIA VOLUMETRICO, junto al DoS-Hulk (16-02) y al DDoS-LOIC (20-02).
        # Se anade precisamente para eso: el HALLAZGO 14 (el byte-CNN no generaliza
        # entre dias del mismo regimen) descansaba en UN solo par de dias; con tres
        # dias homologos pasan a ser SEIS pares dirigidos.
        # OJO (reutilizacion de infraestructura del laboratorio): 18.219.211.138 es
        # LA MISMA IP que el C2 de la botnet del 02-03, dos semanas despues y con un
        # rol de ataque completamente distinto. No hay fuga en nuestras vistas (el
        # payload son bytes y la metadata son contadores; la IP no es una feature),
        # pero conviene tenerlo presente al interpretar cualquier cruce entre dias.
        # Mismo patron ya visto con 18.218.115.60 (web 22-02 y DDoS 20-02).
        # VENTANAS: ambos atacantes hablan EXCLUSIVAMENTE con la victima por el :80
        # (cero destinos ajenos), asi que ensanchar la ventana hasta cubrir toda su
        # actividad no puede mal-etiquetar nada -la leccion del SSH (17-jun) y del
        # Hulk (11-ago)-. Las ventanas del CSV concuerdan (GoldenEye hora 09,
        # Slowloris hora 11), y la tz UTC-4 encaja con ellas.
        "tz_offset_hours": -4,
        "attacks": [
            {
                "label": "DoS-GoldenEye",
                "attacker_ips": ["18.219.211.138"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [80],
                "start_local": "2018-02-15 09:27",
                "end_local": "2018-02-15 10:12",
                "status": "verified",
                "payload_note": "flood HTTP en claro a oleadas; homologo del Hulk (16-02) y del LOIC (20-02)",
            },
            {
                "label": "DoS-Slowloris",
                "attacker_ips": ["18.217.165.70"],
                "victim_ips": ["172.31.69.25"],
                "victim_ports": [80],
                "start_local": "2018-02-15 11:00",
                "end_local": "2018-02-15 11:42",
                "status": "verified",
                "payload_note": "ataque LENTO sobre :80 (conexiones mantenidas, goteo plano); firma conductual",
            },
        ],
    },

    # ===================================================================
    # CIC-IDS2017 (SEGUNDO dataset) -- generalizacion cruzada entre datasets
    # ===================================================================
    # Dataset DISTINTO al 2018: CIC-IDS2017 (Canadian Institute for Cybersecurity,
    # Universidad de New Brunswick). Se anade para el experimento de GENERALIZACION
    # CRUZADA: entrenar un modelo en 2018 y testearlo en 2017 (y viceversa). Si el
    # modelo sigue detectando en un dataset que no ha visto, la senal es real; si se
    # hunde, estaba memorizando el laboratorio / la herramienta concreta (justo la
    # duda del "100% sospechoso"). Los tres dias elegidos son los ANALOGOS de los
    # tres regimenes ya cubiertos en 2018:
    #     2018 SSH-Bruteforce (14-02)  <->  2017 SSH-Patator   (Tuesday :22, cifrado)
    #     2018 Web Attacks    (22-02)  <->  2017 Web Attack    (Thursday :80, claro)
    #     2018 DoS-Hulk       (16-02)  <->  2017 DoS-Hulk      (Wednesday :80, volum.)
    #
    # ZONA HORARIA (PROVISIONAL, VERIFICAR): los PCAP estan en epoch UTC; la doc/CSV
    # de 2017 estan en hora local de New Brunswick (Atlantic; en julio, ADT = UTC-3).
    # tz_offset_hours = -3 es PROVISIONAL -> confirmar empiricamente con
    # find_attacker.py ANTES de dar por bueno el etiquetado (en 2018 se confirmo -4
    # de esta misma forma; la doc no basta, ver lecciones del SSH/SlowHTTPTest).
    #
    # IPs (segun documentacion oficial de CIC-IDS2017; status = "documented"):
    #     atacante Kali  205.174.165.73   ->   victima (web/servicios)  192.168.10.50
    # OJO NAT: hay un firewall (205.174.165.80 <-> 172.16.0.1) entre la red del
    # atacante y la victima; dentro del PCAP capturado el atacante podria aparecer
    # con otra IP (p.ej. la NAT interna). VERIFICAR con find_attacker.py:
    #     python scripts/zeek/find_attacker.py --day Thursday-06-07-2017 \
    #         --pcap-dir data/raw/CIC-IDS2017/PCAPs \
    #         --capture Thursday-WorkingHours.pcap --port 80
    # y ajustar attacker_ips / victim_ips / ventanas / tz con lo observado antes de
    # cambiar el status a "verified".
    #
    # CONFIRMADO (4-ago) en Thursday-06-07-2017: el atacante aparece como 172.16.0.1
    # (NAT), NO como 205.174.165.73, y la tz real es UTC-3. Tuesday/Wednesday siguen
    # con la IP documentada y status "documented" -> muy probablemente sean tambien
    # 172.16.0.1 (mismo NAT), pero deben verificarse con find_attacker.py al procesar
    # sus PCAP antes de darlos por buenos.
    "Tuesday-04-07-2017": {
        # VERIFICADO el 5-ago con find_attacker.py sobre Tuesday-WorkingHours.pcap
        # (pcapng, 11 GB; Zeek conn.log, 323.325 conexiones). Igual que Thursday:
        #   - ATACANTE = 172.16.0.1 (NAT), NO 205.174.165.73. Par SSH-Patator real:
        #     172.16.0.1 -> 192.168.10.50:22 (2.979 conex., mayoria SF, 14 MB app).
        #   - tz UTC-3 CONFIRMADA: la rafaga del atacante va de 17:09:01 a 18:11:20
        #     UTC = 14:09-15:11 local, dentro de la ventana documentada (14:00-15:00).
        # Se amplia el fin a 15:15 local para cubrir la cola verificada (15:11). El
        # emparejamiento por par {172.16.0.1, 192.168.10.50} evita reetiquetar el SSH
        # benigno de los hosts internos 192.168.10.x -> .50:22 (que existe todo el dia).
        # FTP-Patator (:21): no reverificado por separado; se corrige su IP al NAT
        # (mismo atacante) y se deja "documented" (no se usa en el cruce SSH).
        "tz_offset_hours": -3,  # CONFIRMADO (ver arriba)
        "attacks": [
            {
                "label": "FTP-Patator",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [21],
                "start_local": "2017-07-04 09:20",
                "end_local": "2017-07-04 10:20",
                "status": "documented",
                "payload_note": "brute force FTP (analogo al FTP-BruteForce de 2018)",
            },
            {
                "label": "SSH-Patator",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [22],
                "start_local": "2017-07-04 14:00",
                "end_local": "2017-07-04 15:15",
                "status": "verified",
                "payload_note": "brute force SSH cifrado (analogo al SSH-Bruteforce de 2018)",
            },
        ],
    },
    "Wednesday-05-07-2017": {
        # VERIFICADO el 6-ago con find_attacker.py sobre Wednesday-workingHours.pcap
        # (pcapng, 13,4 GB; Zeek conn.log, 509.349 conexiones). Igual que los otros
        # dias de 2017:
        #   - ATACANTE = 172.16.0.1 (NAT), NO 205.174.165.73. Par DoS real:
        #     172.16.0.1 -> 192.168.10.50:80 con 191.161 conexiones (estados RSTO/
        #     S0/SF de flood) -> la campana DoS COMPLETA del dia (Slowloris,
        #     Slowhttptest, Hulk, GoldenEye) sale toda de esa unica IP NAT.
        #   - tz UTC-3 CONFIRMADA: arranca a las 12:01:00 UTC = 09:01 local.
        # Rango verificado del atacante: 12:01:00 .. 17:24:56 UTC (09:01-14:25 local).
        # Se usa UNA ventana amplia (09:00-14:30 local) que cubre toda la campana en
        # vez de las 4 ventanas estrechas documentadas: como el gateway NAT solo
        # fronta al Kali atacante, TODO 172.16.0.1 -> 192.168.10.50:80 es ataque;
        # ventanas estrechas dejarian flujos del atacante fuera etiquetados Benign y
        # contaminarian el benigno :80 (leccion del SSH 2018). El benigno :80 real son
        # los hosts internos 192.168.10.x -> servidores EXTERNOS (par distinto, limpio).
        # Para el cruce binario Attack/Benign el subtipo no importa; se etiqueta como
        # "DoS-Hulk" (analogo directo del DoS-Hulk de 2018, 16-02).
        "tz_offset_hours": -3,  # CONFIRMADO (ver arriba)
        "attacks": [
            {
                "label": "DoS-Hulk",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [80],
                "start_local": "2017-07-05 09:00",
                "end_local": "2017-07-05 14:30",
                "status": "verified",
                "payload_note": "campana DoS del dia (Hulk/Slowloris/Slowhttptest/GoldenEye) "
                                "desde el NAT; analogo volumetrico del DoS-Hulk 2018",
            },
        ],
    },
    "Thursday-06-07-2017": {
        # VERIFICADO el 4-ago con find_attacker.py sobre Thursday-WorkingHours.pcap
        # (pcapng, 8,3 GB; Zeek conn.log, 363.760 conexiones). Dos correcciones
        # empiricas frente a la documentacion (misma leccion que el SSH/DoS de 2018):
        #   1) ATACANTE: no es 205.174.165.73 (esa IP NO aparece en el PCAP). Por el
        #      NAT del firewall (205.174.165.80 <-> 172.16.0.1), el Kali atacante sale
        #      DENTRO del PCAP como 172.16.0.1. El par de ataque real hacia la victima
        #      web es 172.16.0.1 -> 192.168.10.50:80 (2.115 conex., mayoria SF, 12,7 MB
        #      de bytes de aplicacion -> HTTP EN CLARO real).
        #   2) ZONA HORARIA: confirmada UTC-3 (Atlantic/ADT). La actividad del atacante
        #      hacia :80 empieza a las 12:15:54 UTC = 09:15 local, justo antes de la
        #      ventana documentada de Brute Force web (9:20). Con -4 caeria a las 8:15
        #      (antes del horario laboral) -> no encaja. Por eso tz = -3.
        # Los 3 sub-ataques web (BF/XSS/SQLi) van al mismo par {172.16.0.1,
        # 192.168.10.50}:80 en ventanas disjuntas de la manana; cada flujo cae en su
        # sub-ataque por su timestamp. Analogo directo del 22-02-2018. (La Infiltration
        # de la tarde no se codifica: no es ataque de payload web y su GT es ambigua.)
        "tz_offset_hours": -3,  # CONFIRMADO empiricamente (ver arriba)
        "attacks": [
            {
                "label": "Web Attack - Brute Force",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [80],
                "start_local": "2017-07-06 09:20",
                "end_local": "2017-07-06 10:00",
                "status": "verified",
                "payload_note": "HTTP en claro: fuerza bruta web (analogo a Brute Force -Web 2018)",
            },
            {
                "label": "Web Attack - XSS",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [80],
                "start_local": "2017-07-06 10:15",
                "end_local": "2017-07-06 10:35",
                "status": "verified",
                "payload_note": "HTTP en claro: XSS (analogo a Brute Force -XSS 2018)",
            },
            {
                "label": "Web Attack - Sql Injection",
                "attacker_ips": ["172.16.0.1"],
                "victim_ips": ["192.168.10.50"],
                "victim_ports": [80],
                "start_local": "2017-07-06 10:40",
                "end_local": "2017-07-06 10:42",
                "status": "verified",
                "payload_note": "HTTP en claro: SQLi (analogo a SQL Injection 2018)",
            },
        ],
    },
}

BENIGN = "Benign"


def _to_utc_epoch(local_str: str, tz_offset_hours: int) -> float:
    """Convierte 'YYYY-MM-DD HH:MM' en hora local a epoch UTC (segundos)."""
    tz = timezone(timedelta(hours=tz_offset_hours))
    dt = datetime.strptime(local_str, "%Y-%m-%d %H:%M").replace(tzinfo=tz)
    return dt.timestamp()


class DayLabeler:
    """Etiquetador de flujos para un dia concreto del dataset."""

    def __init__(self, day: str):
        if day not in DAYS:
            raise KeyError(
                f"Dia '{day}' no definido en attack_metadata.DAYS. "
                f"Definidos: {list(DAYS)}")
        cfg = DAYS[day]
        self.day = day
        self.tz_offset = cfg["tz_offset_hours"]
        # Precalcula las ventanas en epoch UTC y conjuntos de IPs para rapidez.
        self.attacks = []
        for a in cfg["attacks"]:
            self.attacks.append({
                "label": a["label"],
                "ips": set(a["attacker_ips"]) | set(a["victim_ips"]),
                "victim_ports": set(a["victim_ports"]),
                "start": _to_utc_epoch(a["start_local"], self.tz_offset),
                "end": _to_utc_epoch(a["end_local"], self.tz_offset),
                "status": a.get("status", "documented"),
            })

    def label(self, orig_h: str, orig_p: int, resp_h: str, resp_p: int,
              ts: float) -> str:
        """Devuelve la etiqueta del flujo (o 'Benign' si no casa con un ataque).

        ts debe estar en epoch UTC (como en los TSV de payload).
        """
        pair = {orig_h, resp_h}
        for a in self.attacks:
            if pair == a["ips"] or pair.issubset(a["ips"]):
                # El puerto de la victima puede ser orig_p o resp_p segun la
                # direccion del paquete; basta con que uno este en victim_ports.
                if (resp_p in a["victim_ports"] or orig_p in a["victim_ports"]):
                    if a["start"] <= ts <= a["end"]:
                        return a["label"]
        return BENIGN

    def summary(self) -> str:
        lines = [f"Dia {self.day} (tz UTC{self.tz_offset:+d}):"]
        for a in self.attacks:
            s0 = datetime.fromtimestamp(a["start"], tz=timezone.utc)
            s1 = datetime.fromtimestamp(a["end"], tz=timezone.utc)
            lines.append(
                f"  - {a['label']:16s} [{a['status']:10s}] "
                f"IPs={sorted(a['ips'])} ports={sorted(a['victim_ports'])} "
                f"UTC[{s0:%H:%M}-{s1:%H:%M}]")
        return "\n".join(lines)


if __name__ == "__main__":
    # Imprime un resumen de todos los dias definidos.
    for d in DAYS:
        print(DayLabeler(d).summary())

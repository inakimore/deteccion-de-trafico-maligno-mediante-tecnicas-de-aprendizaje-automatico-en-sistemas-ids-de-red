##! extract_payload.zeek
##!
##! Script personalizado de Zeek para la Fase 2 del TFG (analisis de payload en
##! crudo). Recorre cada paquete TCP de una captura y, para los que transportan
##! datos (len > 0), escribe una fila en el log "payload" con:
##!
##!   uid          identificador unico de conexion de Zeek (c$uid). Permite
##!                agrupar paquetes por flujo de forma exacta aunque se reutilicen
##!                los puertos de origen (habitual en ataques de fuerza bruta).
##!   ts           timestamp del paquete (segundos epoch, UTC)
##!   orig_h       IP de la maquina que inicio la conexion
##!   orig_p       puerto de origen (numerico)
##!   resp_h       IP de la maquina que respondio
##!   resp_p       puerto de destino (numerico)
##!   service      servicio de aplicacion identificado por Zeek (c$service), p. ej.
##!                "ssh", "http", "ssl". Lo deducen los analizadores de protocolo
##!                (DPI) de Zeek a partir del CONTENIDO, no del numero de puerto.
##!                Vale "-" mientras Zeek aun no lo ha determinado (la deteccion es
##!                progresiva: los primeros segmentos de un flujo pueden salir sin
##!                servicio), por lo que build_dataset.py se queda con el ultimo
##!                valor no vacio de cada uid.
##!   dir          direccion del paquete: "orig" (cliente->servidor) o "resp"
##!   len          numero de bytes de payload
##!   payload_hex  payload TCP en hexadecimal (2 caracteres por byte)
##!
##! Nota de diseño (correccion del tutor, 11-ago): los PUERTOS no son un atributo
##! valido para el modelo —dependen de la configuracion de cada red, igual que las
##! IPs, y no son "context independent"—. Se siguen registrando como identificador
##! del flujo (trazabilidad y etiquetado), pero la nocion de "servicio" con la que
##! se selecciona y agrupa el trafico debe venir de las REGLAS DE ZEEK, que es lo
##! que aporta este campo.
##!
##! Se basa en el evento tcp_packet descrito en docker_zeek.pdf (seccion 2.4),
##! que expone directamente la cabecera y el cuerpo (payload) de cada segmento.
##! En lugar de "print" (que escapa los tabuladores), usamos el Log framework
##! de Zeek, que genera un TSV limpio (payload.log) con cabecera #fields, tal y
##! como se describe en la documentacion de logs referenciada en el material.
##!
##! Uso (dentro del contenedor zeek/zeek):
##!   zeek -C -r captura.pcap extract_payload.zeek   # genera payload.log
##!
##! La opcion -C ignora los checksums invalidos (habituales por el offloading
##! de las NIC de captura), tal y como recomienda el material de la asignatura.

module PayloadExtract;

export {
    # Identificador del nuevo stream de log.
    redef enum Log::ID += { LOG };

    # Esquema de una fila del log de payload.
    type Info: record {
        uid:         string &log;
        ts:          time   &log;
        orig_h:      addr   &log;
        orig_p:      count  &log;
        resp_h:      addr   &log;
        resp_p:      count  &log;
        service:     string &log;
        dir:         string &log;
        len:         count  &log;
        payload_hex: string &log;
    };
}

event zeek_init()
{
    # Crea el stream y lo asocia al fichero payload.log en el directorio actual.
    Log::create_stream(PayloadExtract::LOG, [$columns=Info, $path="payload"]);
}

# Serializa el conjunto c$service ("ssh", "http", "ssl"...) a una cadena. Zeek lo
# rellena conforme sus analizadores reconocen el protocolo por el contenido, asi
# que puede estar vacio en los primeros segmentos de la conexion.
function service_str(c: connection): string
{
    local out = "";
    if ( c?$service )
        for ( s in c$service )
            out = (out == "" ? s : cat(out, ",", s));
    return (out == "" ? "-" : out);
}

event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
{
    # Solo nos interesan los segmentos que llevan datos de aplicacion; los
    # paquetes de control (SYN, ACK puros, FIN...) no aportan payload.
    if ( len == 0 )
        return;

    Log::write(PayloadExtract::LOG, [
        $uid         = c$uid,
        $ts          = network_time(),
        $orig_h      = c$id$orig_h,
        $orig_p      = port_to_count(c$id$orig_p),
        $resp_h      = c$id$resp_h,
        $resp_p      = port_to_count(c$id$resp_p),
        $service     = service_str(c),
        $dir         = (is_orig ? "orig" : "resp"),
        $len         = len,
        $payload_hex = bytestring_to_hexstr(payload)
    ]);
}

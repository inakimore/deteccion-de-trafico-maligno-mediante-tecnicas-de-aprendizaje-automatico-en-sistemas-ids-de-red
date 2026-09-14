#!/usr/bin/env python
"""Numeros de todos los experimentos del TFG, con su procedencia.

FUENTE UNICA DE VERDAD para las figuras y las tablas de la memoria. Cada
bloque cita el fichero de `models/` que lo genero, de modo que cualquier
cifra de la memoria es trazable hasta el script que la produjo.

REGLA: aqui no se calcula nada. Si un numero cambia, se re-ejecuta el
script correspondiente de `scripts/zeek/`, se copia el valor nuevo aqui y
se regeneran las figuras con `generar_todo.py`.

--------------------------------------------------------------------------
AVISO SOBRE RESULTADOS OBSOLETOS
--------------------------------------------------------------------------
El 11 de agosto se corrigio un error de limite de ventana en el dia del DoS
(16-02) que contaminaba el benigno con el 65.1% de flujos del propio
atacante. Los resultados del dia DoS medidos ANTES de esa correccion
(15-jul Eje A y Eje C, 7-ago rigor) quedan invalidados. Se conservan aqui
marcados con el sufijo `_OBSOLETO` porque la comparacion antes/despues es
en si misma una figura de la memoria (la leccion metodologica), pero NO
deben usarse como resultado del sistema.

Lo mismo ocurrio antes con el SSH (17-jun): ambos casos comparten causa.
"""

from __future__ import annotations

# ==========================================================================
# 0. IDENTIDAD DE LOS DIAS Y REGIMENES
# ==========================================================================
# Fuente: SUMMARY.md seccion 4, models/phase3_service_id_*.md

DIAS = {
    "Wednesday-14-02-2018": {
        "corto": "14-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "SSH-Bruteforce",
        "regimen": "cifrado",
        "servicio": "ssh",
        "puerto": 22,
        "flujos_total": 2_202_231,
        "flujos_ataque": 94_207,
        "benigno_servicio_por_puerto": 433,   # puerto == 22
        "benigno_servicio_por_dpi": 358,      # servicio == ssh (contenido)
        "atacante": "13.58.98.64",
        "victima": "172.31.69.25:22",
        "ventana_local": "14:01-15:33",
        "firma": "conducta / rafaga de conexiones",
    },
    "Thursday-22-02-2018": {
        "corto": "22-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "Web (BF / XSS / SQLi)",
        "regimen": "en claro",
        "servicio": "http",
        "puerto": 80,
        "flujos_total": 2_777_898,
        "flujos_ataque": 203,
        "benigno_servicio_por_puerto": 459_654,
        "benigno_servicio_por_dpi": 459_743,
        "atacante": "18.218.115.60",
        "victima": "172.31.69.28:80",
        "ventana_local": "10:13 / 13:50 / 16:10",
        "firma": "contenido en los bytes",
    },
    "Friday-16-02-2018": {
        "corto": "16-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "DoS-Hulk / SlowHTTPTest",
        "regimen": "volumetrico",
        "servicio": "http",
        "puerto": 80,
        "flujos_total": 4_041_078,
        "flujos_ataque": 1_803_160,        # tras el re-etiquetado del 11-ago
        "flujos_ataque_antes": 1_062_339,  # etiquetado erroneo previo
        "benigno_servicio_por_puerto": 1_137_872,
        "benigno_servicio_por_dpi": 396_977,   # benigno GENUINO tras corregir
        "atacante": "18.219.193.20",
        "victima": "172.31.69.25:80",
        "ventana_local": "13:45-13:59",
        "firma": "volumen agregado por origen",
    },
    "Thursday-15-02-2018": {
        "corto": "15-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "DoS-GoldenEye / Slowloris",
        "regimen": "volumetrico",
        "servicio": "http",
        "puerto": 80,
        "flujos_total": 1_997_325,
        "flujos_ataque": 31_876,           # 26.861 GoldenEye + 5.015 Slowloris
        "flujos_ataque_goldeneye": 26_861,
        "flujos_ataque_slowloris": 5_015,
        "atacante": "18.219.211.138 (GoldenEye) / 18.217.165.70 (Slowloris)",
        "victima": "172.31.69.25:80",
        "ventana_local": "09:27-10:12 / 11:00-11:42",
        "firma": "volumen agregado por origen (GoldenEye a oleadas, Slowloris goteo plano)",
        # El conn.log veia 29.696 y 7.248 conexiones: al dataset solo llegan las
        # que tienen payload -> GoldenEye conserva el 90%, Slowloris solo el 69%.
        "conex_conn_log": {"GoldenEye": 29_696, "Slowloris": 7_248},
    },
    "Tuesday-20-02-2018": {
        "corto": "20-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "DDoS-LOIC-HTTP",
        "regimen": "volumetrico distribuido",
        "servicio": "http",
        "puerto": 80,
        "flujos_total": 2_837_519,
        "flujos_ataque": 289_328,
        "atacante": "10 IPs (18.219.9.1, 18.218.229.235, 52.14.136.135, ...)",
        "n_atacantes": 10,
        "victima": "172.31.69.25:80",
        "ventana_local": "10:13-13:16",
        "firma": "volumen, pero REPARTIDO en 10 origenes -> la rafaga se diluye",
    },
    "Friday-02-03-2018": {
        "corto": "02-03",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "Bot (Ares)",
        "regimen": "periodicidad",
        "servicio": "http",
        "puerto": 8080,
        "flujos_total": 3_347_221,
        "flujos_ataque": 142_925,
        "atacante": "18.219.211.138 (C2)",
        "n_bots": 10,
        "victima": "10 bots en 172.31.69.x:8080",
        "ventana_local": "10:13-15:54",
        "firma": "PERIODICIDAD (beaconing): ninguna vista actual la mide",
    },
    "Wednesday-28-02-2018": {
        "corto": "28-02",
        "dataset": "CSE-CIC-IDS2018",
        "ataque": "Infiltration",
        "regimen": "reconocimiento (sin payload)",
        "servicio": "disperso (53, 135, 443, 22, 445, 3389...)",
        "puerto": None,
        "flujos_total": None,              # NO se construyo dataset: HALLAZGO 16
        "flujos_ataque": None,
        "atacante": "13.58.225.34 (C2 en :31337)",
        "victima": "172.31.69.24",
        "ventana_local": "10:38-17:42",
        "firma": "abanico (1 origen -> 612 destinos) + conn_state (82% S0)",
        "nota": "analizado y NO vectorizado a proposito: el 94.4% del ataque no "
                "tiene payload (HALLAZGO 16). Fuente: conn.log, no .npz.",
    },
    "Tuesday-04-07-2017": {
        "corto": "04-07 (2017)", "dataset": "CIC-IDS2017",
        "ataque": "SSH-Patator", "regimen": "cifrado", "servicio": "ssh",
        "puerto": 22, "flujos_total": 100_871, "flujos_ataque": 2_979,
        "atacante": "172.16.0.1 (NAT)", "victima": "192.168.10.50:22",
    },
    "Wednesday-05-07-2017": {
        "corto": "05-07 (2017)", "dataset": "CIC-IDS2017",
        "ataque": "DoS-Hulk", "regimen": "volumetrico", "servicio": "http",
        "puerto": 80, "flujos_total": 263_226, "flujos_ataque": 168_817,
        "atacante": "172.16.0.1 (NAT)", "victima": "192.168.10.50:80",
    },
    "Thursday-06-07-2017": {
        "corto": "06-07 (2017)", "dataset": "CIC-IDS2017",
        "ataque": "Web (BF / XSS / SQLi)", "regimen": "en claro",
        "servicio": "http", "puerto": 80, "flujos_total": 83_886,
        "flujos_ataque": 174,
        "atacante": "172.16.0.1 (NAT)", "victima": "192.168.10.50:80",
    },
}

# Recuento agregado de los dias con dataset construido. El 28-02 queda fuera
# porque no tiene .npz: el 94,4% de su ataque no lleva payload analizable.
# Se guarda aqui porque el resumen lo cita y toda cifra citada debe tener fuente.
FLUJOS_TOTALES_2018 = 17_203_272
DIAS_CON_DATASET = 6
DIAS_CON_DATASET_2017 = 3          # 04-07, 05-07 y 06-07, validacion cruzada
GIGABYTES_CAPTURA = "~150 GB"      # capturas en bruto saneadas y procesadas

# Los CUATRO regimenes: marco DESCRIPTIVO del capitulo 4.
# (eran tres hasta el 21-ago; el dia Bot anadio el de periodicidad)
#
# OJO (24-ago, HALLAZGO 19): este marco describe DONDE VIVE LA FIRMA de cada
# ataque -- un hecho sobre el ataque, comprobable inspeccionando el trafico --
# y NO cual es la vista ganadora. Habia una columna "vista ganadora" que se ha
# retirado porque la medicion uniforme la desmiente en tres de las cuatro filas:
# afirmaba "meta + rafaga" en el volumetrico (mide payload 1.0000 vs conducta
# 0.9999) y "ninguna vista lo mide" en el dia del Bot (miden las tres 0.998).
# Ver SATURACION_INTRADIA justo debajo.
REGIMENES = [
    # (regimen, dia, ataque, donde vive la firma, la mide el pipeline?)
    ("Cifrado", "14-02", "SSH-Bruteforce",
     "conducta: rafaga de conexiones", True),
    ("En claro", "22-02", "Web BF / XSS / SQLi",
     "contenido: tokens en los bytes", True),
    ("Volumetrico", "16-02", "DoS-Hulk",
     "volumen agregado por origen", True),
    ("Periodicidad", "02-03", "Bot (Ares)",
     "intervalo entre conexiones (beaconing)", False),
]

# ==========================================================================
# HALLAZGO 19: LA EVALUACION INTRA-DIA ESTA SATURADA
# ==========================================================================
# Fuente: models/phase2_ic_caso_dificil_<dia>.md (scripts/zeek/ic_caso_dificil.py)
#
# Las MISMAS tres vistas, la MISMA metrica (macro-F1 out-of-fold, 5-Fold), el
# MISMO protocolo (benigno genuino de terceros, balanceo 1:1 con tope de 5.000
# por clase, media sobre 10 submuestreos, IC 95% agrupando 2.000 remuestreos de
# bootstrap) en los seis dias procesados del CSE-CIC-IDS2018.
#
# Resultado: TODO satura. El payload no baja de 0.973 en ningun dia y es el mejor
# o empata en cuatro de los seis; la conducta no baja de 0.982. La unica vista
# que falla de forma apreciable son los metadatos de flujo basicos.
#
# CAUSA: cada dia tiene UN SOLO host atacante (salvo el DDoS del 20-02, con 10).
# Cualquier vista puede memorizar lo idiosincrasico de ese host -- el banner
# `paramiko`, los User-Agents de Hulk, las cabeceras de Ares -- y eso basta para
# separar. Es el atajo que documenta Engelen (WTMC 2021). Por tanto la evaluacion
# intra-dia NO DISCRIMINA entre vistas, y un 0.99 aqui no significa que el
# problema este resuelto: significa que la pregunta esta mal planteada.
#
# Donde SI se discrimina: evasion (EJE_E_EVASION), transferencia entre dias y
# datasets (CROSS_*), calibracion (CALIBRACION_CRUZADA) y ceguera del payload
# (FTP del 14-02 e INFILTRACION_CEGUERA). Es decir, el capitulo 5.

# dia -> (regimen, n_ataque, n_benigno_genuino, n_por_clase_y_repeticion)
SATURACION_CONTEXTO = {
    "14-02": ("cifrado",             94_207,   358,   358),
    "22-02": ("en claro",               203, 459_743,  203),
    "16-02": ("volumetrico",      1_803_160, 396_977, 5_000),
    "15-02": ("volumetrico",         31_875, 423_299, 5_000),
    "20-02": ("volumetrico diluido", 289_328, 475_962, 5_000),
    "02-03": ("periodicidad",       142_921, 417_009, 5_000),
}

# dia -> vista -> (macro_f1, ic_lo, ic_hi, sd_entre_repeticiones)
SATURACION_INTRADIA = {
    "14-02": {
        "payload":   (0.9842, 0.9720, 0.9958, 0.0040),
        "metadatos": (0.9906, 0.9790, 0.9986, 0.0038),
        "conducta":  (0.9985, 0.9944, 1.0000, 0.0004),
    },
    "22-02": {
        "payload":   (0.9734, 0.9507, 0.9926, 0.0075),
        "metadatos": (0.9186, 0.8793, 0.9507, 0.0120),
        "conducta":  (0.9823, 0.9652, 0.9975, 0.0065),
    },
    "16-02": {
        "payload":   (1.0000, 0.9997, 1.0000, 0.0001),
        "metadatos": (0.9715, 0.9678, 0.9756, 0.0011),
        "conducta":  (0.9999, 0.9995, 1.0000, 0.0001),
    },
    "15-02": {
        "payload":   (0.9998, 0.9992, 1.0000, 0.0001),
        "metadatos": (0.9621, 0.9566, 0.9673, 0.0020),
        "conducta":  (0.9967, 0.9952, 0.9980, 0.0005),
    },
    "20-02": {
        "payload":   (1.0000, 1.0000, 1.0000, 0.0000),
        "metadatos": (0.9987, 0.9972, 0.9996, 0.0005),
        "conducta":  (0.9984, 0.9974, 0.9993, 0.0003),
    },
    "02-03": {
        "payload":   (0.9990, 0.9980, 0.9997, 0.0003),
        "metadatos": (0.9981, 0.9966, 0.9993, 0.0006),
        "conducta":  (0.9983, 0.9970, 0.9993, 0.0004),
    },
}

# dia -> vista -> (recall_ataque, ic_lo, ic_hi)
SATURACION_RECALL = {
    "14-02": {"payload": (0.9997, 0.9947, 1.0000),
              "metadatos": (0.9997, 0.9947, 1.0000),
              "conducta": (0.9997, 0.9947, 1.0000)},
    "22-02": {"payload": (0.9867, 0.9360, 1.0000),
              "metadatos": (0.9887, 0.9633, 1.0000),
              "conducta": (0.9714, 0.9368, 1.0000)},
    "16-02": {"payload": (1.0000, 0.9996, 1.0000),
              "metadatos": (0.9981, 0.9960, 1.0000),
              "conducta": (0.9998, 0.9990, 1.0000)},
    "15-02": {"payload": (0.9997, 0.9988, 1.0000),
              "metadatos": (0.9876, 0.9746, 0.9943),
              "conducta": (0.9963, 0.9936, 0.9984)},
    "20-02": {"payload": (1.0000, 1.0000, 1.0000),
              "metadatos": (1.0000, 0.9996, 1.0000),
              "conducta": (0.9984, 0.9970, 0.9996)},
    "02-03": {"payload": (0.9987, 0.9965, 0.9998),
              "metadatos": (0.9974, 0.9950, 0.9992),
              "conducta": (0.9988, 0.9974, 0.9998)},
}

# ==========================================================================
# HALLAZGO 20: EL ATAJO NO ES LA IDENTIDAD DEL HOST
# ==========================================================================
# Fuente: models/phase3_loao_Tuesday-20-02-2018.md (scripts/zeek/loao_eval.py)
#
# El HALLAZGO 19 proponia un mecanismo para la saturacion: un solo host atacante
# por dia => cualquier vista memoriza ese host. Es contrastable en el UNICO dia
# con varios atacantes, el DDoS del 20-02, que tiene diez con ~29.000 flujos
# cada uno. Se aparta un host atacante entero (y un grupo disjunto de hosts
# benignos) y se entrena con el resto.
#
# RESULTADO: el mecanismo propuesto NO se sostiene. Apartar un atacante entero
# no degrada ninguna de las tres vistas; la diferencia frente al control
# aleatorio del mismo tamano es +0,0000 / +0,0001 / +0,0004.
#
# El test es sensible: el CONTROL POSITIVO (los cuatro octetos de la IP de
# origen, un identificador de host puro) cae de 0,9999 a 0,9332 de media, pero
# con una desviacion enorme (0,2000) porque el efecto se concentra en un solo
# pliegue. Ver LOAO_CONTROL_IP: nueve de los diez atacantes estan en 18.2xx.x.x
# y el benigno en 172.31.x.x, asi que apartar uno deja otros nueve del mismo
# rango y el primer octeto sigue separando. Es la fuga del HALLAZGO 18 medida a
# nivel de SUBRED, no de host.
#
# El pliegue decisivo es 52.14.136.135, la unica atacante fuera de ese rango:
# ahi el control se hunde a 0,3333 (predice una sola clase) y las tres vistas
# reales siguen dando 1,0000 / 0,9987 / 0,9990. En el unico pliegue donde se
# demuestra que un atajo por identidad de host FALLA, las vistas reales aguantan.
#
# CONSECUENCIA: la saturacion no se explica por la identidad del host sino por
# la HERRAMIENTA y la captura. Lo confirma la evasion sobre este mismo dia:
# camuflar los primeros bytes hunde el payload de 1,0000 a 0,0108. LOAO dice
# "no es el host"; la evasion dice "es la herramienta".
#
# EFECTO SECUNDARIO: rehabilita la vista conductual. La rafaga cuenta conexiones
# por origen y se temia que funcionase como identificador de host; medida contra
# un atacante nunca visto, generaliza igual (0,9990 vs 0,9986 del control).
#
# LIMITE DEL TEST: los diez atacantes ejecutan la MISMA herramienta (LOIC), asi
# que distingue "memoriza el host" de "aprende la herramienta o la conducta",
# pero no "aprende la herramienta" de "aprende el ataque".

# vista -> (macro_f1 control, sd, macro_f1 LOAO, sd, diferencia)
LOAO_20_02 = {
    "payload (histograma + entropia)":     (1.0000, 0.0000, 1.0000, 0.0000, +0.0000),
    "metadatos de flujo":                  (0.9991, 0.0005, 0.9992, 0.0006, +0.0001),
    "conducta (metadatos + rafaga)":       (0.9986, 0.0006, 0.9990, 0.0007, +0.0004),
    "[control] octetos de la IP de origen": (0.9999, 0.0001, 0.9332, 0.2000, -0.0667),
}
LOAO_CONTEXTO = {"hosts_atacantes": 10, "hosts_benignos": 469,
                 "n_train_por_clase": 5000, "n_test_por_clase": 2000,
                 "flujos_por_atacante": "~29.000"}
# El pliegue decisivo: la unica IP atacante fuera del rango 18.2xx.x.x.
LOAO_PLIEGUE_DECISIVO = {
    "host_apartado": "52.14.136.135",
    "payload": 1.0000, "metadatos": 0.9987, "conducta": 0.9990,
    "control_ip": 0.3333,
}

VISTAS_ORDEN = ["payload", "metadatos", "conducta"]
VISTAS_ETIQUETA = {
    "payload": "Payload\n(histograma + entropia)",
    "metadatos": "Metadatos\nde flujo",
    "conducta": "Conducta\n(metadatos + rafaga)",
}

# Un quinto caso que NO es un regimen mas, sino el limite del enfoque: el
# reconocimiento de la Infiltration no tiene payload que analizar (HALLAZGO 16).
FUERA_DE_ALCANCE = (
    "Reconocimiento", "28-02", "Infiltration",
    "abanico de destinos + conn_state", "ninguna: 94.4% sin payload", False,
)

# ==========================================================================
# 1. FASE 1 - BASELINE CON METADATOS DE FLUJO (CSV de CICFlowMeter)
# ==========================================================================
# Fuente: README.md, entrada del 27 de abril; notebooks/02_multiclass_benchmark.ipynb

FASE1_BENCHMARK = {          # 5-Fold CV, sin balancear, con firmas mecanicas
    "Decision Tree": (0.99986, 0.00002),
    "Random Forest": (0.99992, 0.00001),
    "XGBoost":       (0.99993, 0.00002),
}

# Prueba de robustez: undersampling + eliminadas las firmas mecanicas del
# script (Init_Win_bytes, Fwd Seg Size Min...). El ataque sigiloso se cae.
FASE1_ROBUSTEZ = {
    "Benigno":            {"precision": 1.00, "f1": 1.00},
    "Fuerza bruta":       {"precision": 1.00, "f1": 1.00},
    "DoS-Slowloris":      {"precision": 0.80, "f1": 0.89},
}

# ==========================================================================
# 2. EL ESPEJISMO DEL 99,96 %  (HALLAZGO 3)
# ==========================================================================
# Fuente: models/phase2_results.md + scripts/zeek/honest_check.py
# Accuracy global sobre benigno diverso vs. auditoria sobre SSH benigno real.

ESPEJISMO = {
    "histograma+entropia": {"cv": 0.99952, "test": 0.9996, "fp_ssh_benigno": 0.960},
    "secuencial":          {"cv": 0.99959, "test": 0.9996, "fp_ssh_benigno": 0.795},
}

# ==========================================================================
# 3. TRES VISTAS BAJO BALANCEO GLOBAL POR CLASE  (16-jun, paso 1)
# ==========================================================================
# Fuente: models/phase2_hybrid_compare.md
# Las tres vistas son ESTADISTICAMENTE EQUIVALENTES: el espejismo es del
# protocolo de balanceo, no de la vista.

BALANCEO_GLOBAL = {
    #             CV acc,  test acc, FP sobre SSH benigno, recall ataque
    "payload":   (0.99959, 0.99965, 1596 / 2022, 1.000),
    "metadatos": (0.99951, 0.99946, 1579 / 2022, 1.000),
    "hibrido":   (0.99958, 0.99965, 1594 / 2022, 1.000),
}

# ==========================================================================
# 4. EL CASO DIFICIL: BENIGNO CONTAMINADO vs GENUINO  (HALLAZGO clave)
# ==========================================================================
# Fuente: models/phase2_by_service.md y models/phase2_by_service_rich.md
# El 78,6 % del "SSH benigno" era el propio atacante fuera de la ventana
# etiquetada. El techo de 0.61 era contaminacion, no un limite de la vista.

CASO_DIFICIL_SSH = {
    "contaminado": {"payload": 0.5732, "meta-basica": 0.6093, "meta-rica": 0.7841},
    "limpio":      {"payload": 0.9908, "meta-basica": 0.9793, "meta-rica": 1.0000},
}
CASO_DIFICIL_SSH_F1 = {   # F1 de la clase ataque en el test held-out
    "contaminado": {"payload": 0.6225, "meta-basica": 0.6659, "meta-rica": 0.7826},
    "limpio":      {"payload": 1.0000, "meta-basica": 1.0000, "meta-rica": 1.0000},
}

# OJO: los dos diccionarios de arriba NO son macro-F1.
#   - CASO_DIFICIL_SSH    -> exactitud en validacion cruzada (scoring="accuracy").
#   - CASO_DIFICIL_SSH_F1 -> F1 de la clase ataque sobre un unico test held-out,
#     donde las tres vistas saturan a 1.0000 y el ranking desaparece.
# Ademas, la fila "contaminado" YA NO ES REPRODUCIBLE: la correccion del limite
# de ventana reetiqueto como ataque los 1.589 flujos del atacante que estaban
# marcados Benign, de modo que hoy el .npz no contiene contaminacion que medir.
# Esas cifras son historicas (etiquetado anterior) y no deben mezclarse en una
# misma tabla con las de abajo.
# La memoria declara macro-F1 + recall de ataque, asi que usa el diccionario
# siguiente, que es out-of-fold y trae intervalo de confianza.

# Macro-F1 y recall de ataque OUT-OF-FOLD con IC 95% (bootstrap, 2000 remuestreos)
# sobre el caso dificil del SSH-Bruteforce con benigno GENUINO.
# Seleccion del servicio por CONTENIDO (DPI ssh) -> 358 benignos de terceros
# (por puerto :22 serian 433); balanceo 1:1 -> 716 flujos evaluados.
# Fuente: models/phase2_ic_caso_dificil_Wednesday-14-02-2018.md
CASO_DIFICIL_SSH_IC = {
    "n_ataque": 358, "n_benigno": 358, "n_total": 716, "n_boot": 2000,
    "vistas": {
        # vista: (macro_f1, f1_lo, f1_hi, recall_atk, rec_lo, rec_hi)
        "payload (histograma + entropia)": (0.9818, 0.9707, 0.9916, 1.0, 1.0, 1.0),
        "metadatos de flujo":              (0.9902, 0.9818, 0.9972, 1.0, 1.0, 1.0),
        "conducta (metadatos + rafaga)":   (0.9986, 0.9958, 1.0000, 1.0, 1.0, 1.0),
    },
}

# Composicion del "SSH benigno" del paso 2 (n=2022 flujos del puerto 22)
CONTAMINACION_SSH = {
    "del atacante (fuera de ventana)": 1589,   # 78,6 %
    "de terceros (genuino)": 433,
    "total": 2022,                             # los dos anteriores
}

# Ceguera del FTP-BruteForce del 14-02 (HALLAZGO 1). El servicio FTP de la
# victima estaba caido durante la captura, asi que rechazo los intentos. No es
# una propiedad del protocolo: es una circunstancia de ESTA captura.
FTP_SIN_PAYLOAD = {
    "atacante": "18.221.219.4",
    "victima": "172.31.69.25:21",
    "conexiones_totales": 162_801,
    "en_rej_con_cero_bytes": 134_945,
    "flujos_con_payload": 0,
}
# Composicion del "HTTP benigno" del dia DoS antes de la correccion
CONTAMINACION_DOS = {
    "del atacante (fuera de ventana)": 740_821,
    "de terceros (genuino)": 396_977,
    "fraccion_contaminada": 0.651,
}

# Error de limite de ventana: actividad real del atacante vs ventana etiquetada
# Fuente: README 17-jun (SSH) y 11-ago (DoS). Horas UTC.
VENTANAS = {
    "SSH-Bruteforce (14-02)": {
        "atacante_inicio": "18:01:50", "atacante_fin": "19:32:30",
        "ventana_fin_original": "19:31:00", "ventana_fin_corregida": "19:33:00",
        "flujos_reetiquetados": 1_589,
        "gap_max_s": 1.0,
    },
    "DoS-Hulk (16-02)": {
        "atacante_inicio": "17:45:27", "atacante_fin": "17:58:22",
        "ventana_fin_original": "17:52:59", "ventana_fin_corregida": "17:59:00",
        "flujos_reetiquetados": 740_821,
        "gap_max_s": 0.2,
    },
}

# ==========================================================================
# 5. EL DIA WEB: LA INVERSION  (HALLAZGO 4)
# ==========================================================================
# Fuente: models/phase2_by_service_web.md  (CV accuracy, 1:1, 203 vs 203)

WEB_POR_SERVICIO = {"payload": 0.9877, "metadatos": 0.9286, "hibrido": 0.9926}

# Multi-tipo web: solo la SECUENCIA identifica el tipo de ataque.
# Fuente: models/phase2_multitype_web.md (macro-F1 out-of-fold, 5-Fold)
MULTITIPO_WEB = {"payload-hist": 0.7462, "payload-seq": 0.9505, "metadatos": 0.7695}
# Recall de la clase minoritaria (SQL Injection, n=19): donde se ve la diferencia
MULTITIPO_WEB_RECALL_SQLI = {"payload-hist": 0.2632, "payload-seq": 0.8421,
                             "metadatos": 0.2632}
MULTITIPO_WEB_CLASES = {"Brute Force -Web": 142, "Brute Force -XSS": 42,
                        "SQL Injection": 19}

# ==========================================================================
# 6. FASE 3 EJE A - DEEP LEARNING SOBRE BYTES
# ==========================================================================
# Fuente: models/phase2_dl_<dia>_<tarea>.md  (macro-F1 out-of-fold, 5-Fold)

DL_EJE_A = {
    "14-02 SSH (binario)": {
        "byte-CNN": 0.9988, "byte-LSTM": 0.9988, "mlp-seq": 0.9988,
        "mlp-hist": 0.9896, "metadatos": 0.9931,
    },
    "22-02 Web (binario)": {
        "byte-CNN": 1.0000, "byte-LSTM": 0.9951, "mlp-seq": 0.9754,
        "mlp-hist": 0.9901, "metadatos": 0.9184,
    },
    "22-02 Web (multitipo)": {
        "byte-CNN": 0.9679, "byte-LSTM": 0.4859, "mlp-seq": 0.9505,
        "mlp-hist": 0.7462, "metadatos": 0.7695,
    },
    # Dias anadidos el 19-22 de agosto (todos con --service http, cap 4000).
    # Fuente: models/phase2_dl_{Tuesday-20-02-2018,Friday-02-03-2018,
    #                           Thursday-15-02-2018}_binary.md
    "15-02 DoS GoldenEye+Slowloris (binario)": {
        "byte-CNN": 1.0000, "byte-LSTM": 0.9999, "mlp-seq": 0.9935,
        "mlp-hist": 0.9998, "metadatos": 0.9589,
    },
    "20-02 DDoS-LOIC (binario)": {
        "byte-CNN": 1.0000, "byte-LSTM": 1.0000, "mlp-seq": 1.0000,
        "mlp-hist": 1.0000, "metadatos": 0.9985,
    },
    "02-03 Bot (binario)": {
        "byte-CNN": 1.0000, "byte-LSTM": 0.9999, "mlp-seq": 1.0000,
        "mlp-hist": 0.9992, "metadatos": 0.9986,
    },
}
# OBSOLETO: medido con el benigno contaminado del dia DoS (ver aviso de cabecera)
DL_EJE_A_DOS_OBSOLETO = {
    "byte-CNN": 0.6072, "byte-LSTM": 0.6299, "mlp-seq": 0.6303,
    "mlp-hist": 0.7375, "metadatos": 0.6186,
}

# ==========================================================================
# 7. FASE 3 EJE B - HIBRIDO DE DOS RAMAS (FUSION TARDIA)
# ==========================================================================
# Fuente: models/phase2_dlhybrid_*.md  (macro-F1 out-of-fold)
# La fusion BIEN HECHA es robusta en ambos regimenes; la INGENUA (concatenar
# features crudas) pierde en los dos.

HIBRIDO = {
    "14-02 SSH (binario)": {
        "solo-payload (byte-CNN)": 0.9988, "solo-metadatos (MLP)": 0.9931,
        "fusion ingenua (concat)": 0.9988, "hibrido 2 ramas": 1.0000,
    },
    "22-02 Web (binario)": {
        "solo-payload (byte-CNN)": 1.0000, "solo-metadatos (MLP)": 0.9184,
        "fusion ingenua (concat)": 0.9803, "hibrido 2 ramas": 0.9975,
    },
    "22-02 Web (multitipo)": {
        "solo-payload (byte-CNN)": 0.9679, "solo-metadatos (MLP)": 0.7695,
        "fusion ingenua (concat)": 0.9009, "hibrido 2 ramas": 0.9628,
    },
}

# ==========================================================================
# 8. FASE 3 EJE C - LA FIRMA DEL DoS  (HALLAZGO 8, REVISADO EL 11-AGO)
# ==========================================================================
# Fuente: models/phase2_dos_burst_Friday-16-02-2018.md
# Antes: benigno contaminado (65,1 % era el propio flood) -> todo parecia debil.
# Despues: benigno genuino -> el payload per-flujo tambien separa, pero es
# un fingerprint de herramienta (evadible); la rafaga sigue siendo la robusta.

DOS_BURST = {
    "contaminado (15-jul)": {"payload-hist": 0.7375, "meta-basica": 0.6186,
                             "meta+rafaga": 0.8057},
    "genuino (11-ago)":     {"payload-hist": 1.0000, "meta-basica": 0.9714,
                             "meta+rafaga": 1.0000},
}

# --------------------------------------------------------------------------
# REFINAMIENTO DEL HALLAZGO 8 (22-ago): la rafaga se DILUYE conforme el
# ataque se reparte entre origenes. Solo se ve con los TRES dias volumetricos.
# Fuente: models/phase2_dos_burst_{Friday-16-02,Thursday-15-02,Tuesday-20-02}*.md
# --------------------------------------------------------------------------
RAFAGA_DILUIDA = {
    # dia: (n_origenes, meta-basica, meta+rafaga, ganancia)
    "16-02 DoS-Hulk":            (1,  0.9714, 1.0000, +0.0286),
    "15-02 GoldenEye+Slowloris": (2,  0.9589, 0.9964, +0.0375),
    "20-02 DDoS-LOIC":           (10, 0.9985, 0.9982, -0.0003),
}
RAFAGA_DILUIDA_LECTURA = (
    "El agregado por origen no es una solucion al regimen volumetrico, sino al "
    "regimen volumetrico CONCENTRADO: con 1 origen es la vista dominante; "
    "repartido entre 10, deja de aportar."
)

# Payload-hist de los mismos tres dias, para la figura comparativa.
BURST_PAYLOAD_HIST = {"16-02": 1.0000, "15-02": 0.9998, "20-02": 1.0000}

# --------------------------------------------------------------------------
# La MEDIANA de rafaga (conexiones/5 s por origen) mide el mismo fenomeno de
# forma directa, y en TODOS los dias. Calculado el 22-ago desde
# figuras/cache/rafaga_*.npz (que produce scripts/figuras/extraer_datos.py).
# Es la explicacion cuantitativa de por que meta+rafaga ayuda o no en cada dia.
# --------------------------------------------------------------------------
RAFAGA_MEDIANA = {
    # dia: (mediana ataque, mediana benigno, contraste x)
    "16-02 DoS-Hulk (1 origen)":        (11626, 3, 3875),
    "14-02 SSH-Bruteforce":             (   86, 1,   86),
    "15-02 GoldenEye+Slowloris (1+1)":  (  104, 3,   35),
    "20-02 DDoS-LOIC (10 origenes)":    (   39, 3,   13),
    "02-03 Bot (beaconing)":            (   10, 2,    5),
    "22-02 Web (BF/XSS/SQLi)":          (    1, 3,    0),
}
RAFAGA_MEDIANA_LECTURA = (
    "El contraste de rafaga se desploma TRES ORDENES DE MAGNITUD segun se "
    "distribuye el ataque: 3875x (Hulk, un origen) -> 35x (GoldenEye) -> 13x "
    "(LOIC, diez origenes) -> 5x (beaconing del Bot). Y el dia web lo cierra "
    "por el otro lado: contraste 0x, el ataque tiene MENOS rafaga que el "
    "benigno, y por eso alli gana el payload."
)

# ==========================================================================
# 9. FASE 3 EJE D - INTERPRETABILIDAD (SALIENCY)
# ==========================================================================
# Fuente: models/phase2_saliency_ssh.md

SALIENCY = {
    "fraccion_importancia_primeros_48B": 0.311,
    "banner_ataque": "SSH-2.0-paramiko_2.0.0",
    "n_banners_ataque": 2,
    "n_banners_benignos": 81,
    "banners_benignos_ejemplo": [
        "SSH-2.0-libssh2_1.7.0", "SSH-2.0-OpenSSH_7.2p2 Ubuntu",
        "SSH-2.0-PUTTY",
    ],
    "entropia_ataque": 7.4, "entropia_benigno": 7.4,   # indistinguibles
}

# ==========================================================================
# 10. PUNTO 3 - ROBUSTEZ ANTE EVASION  (HALLAZGO 11)
# ==========================================================================
# Fuente: models/phase2_evasion_*.md
# Se camuflan los primeros bytes del ataque con los de un cliente benigno.
# El payload se hunde; la conducta es INVARIANTE (no mira el contenido).

EVASION = {
    "SSH cifrado (14-02, 48 B)": {
        "payload (byte-CNN)":     {"original": 1.0000, "evadido": 0.3538},
        "conducta (meta+rafaga)": {"original": 1.0000, "evadido": 1.0000},
    },
    "DoS volumetrico (16-02, 200 B)": {
        "payload (byte-CNN)":     {"original": 0.7242, "evadido": 0.4258},
        "conducta (meta+rafaga)": {"original": 0.9992, "evadido": 0.9992},
    },
}

# ==========================================================================
# 11. PUNTO 4 - DETECCION NO SUPERVISADA (ZERO-DAY)  (HALLAZGO 12)
# ==========================================================================
# Fuente: models/phase2_anomaly_*.md  (ROC-AUC; entrenado SOLO con benigno)

ANOMALIA = {
    "Cifrado (14-02, SSH)":      {"payload-IF": 0.6946, "payload-AE": 0.5683,
                                  "meta+rafaga-IF": 1.0000},
    "En claro (22-02, Web)":     {"payload-IF": 0.7580, "payload-AE": 0.7920,
                                  "meta+rafaga-IF": 0.9121},
    "Volumetrico (16-02, DoS)":  {"payload-IF": 0.3411, "payload-AE": 0.4791,
                                  "meta+rafaga-IF": 0.5402},
}
ANOMALIA_DET_5FPR = {   # fraccion de ataques capturados aceptando 5 % de FP
    "Cifrado (14-02, SSH)":     {"payload-IF": 0.0000, "payload-AE": 0.0000,
                                 "meta+rafaga-IF": 1.0000},
    "En claro (22-02, Web)":    {"payload-IF": 0.2808, "payload-AE": 0.0739,
                                 "meta+rafaga-IF": 0.5714},
    "Volumetrico (16-02, DoS)": {"payload-IF": 0.0000, "payload-AE": 0.0000,
                                 "meta+rafaga-IF": 0.0170},
}

# ==========================================================================
# 12. PUNTO 6 - RIGOR ESTADISTICO: ROC-AUC CON IC 95 % (BOOTSTRAP)
# ==========================================================================
# Fuente: models/phase2_rigor_*.md  (2000 remuestreos)
# (valor, low, high)

RIGOR = {
    "Cifrado (14-02, SSH)": {
        "payload byte-CNN":     (1.0000, 1.0000, 1.0000),
        "payload histograma":   (0.9958, 0.9902, 1.0000),
        "conducta meta+rafaga": (1.0000, 1.0000, 1.0000),
    },
    "En claro (22-02, Web)": {
        "payload byte-CNN":     (1.0000, 1.0000, 1.0000),
        "payload histograma":   (0.9949, 0.9843, 1.0000),
        "conducta meta+rafaga": (0.9998, 0.9994, 1.0000),
    },
}
# OBSOLETO: el dia DoS se midio el 7-ago, antes del re-etiquetado del 11-ago.
RIGOR_DOS_OBSOLETO = {
    "payload byte-CNN":     (0.6775, 0.6650, 0.6898),
    "payload histograma":   (0.8422, 0.8342, 0.8505),
    "conducta meta+rafaga": (0.8427, 0.8346, 0.8511),
}

# ==========================================================================
# 13. GENERALIZACION CRUZADA ENTRE DATASETS  (HALLAZGOS 9 y 10)
# ==========================================================================
# Fuente: models/phase2_crossdataset_*.md  (accuracy; 0.5 = azar)
# Entrenar en un dataset y testear en OTRO con el ataque analogo.
# Por indicacion del tutor (11-ago) pasa a presentarse como validacion
# complementaria / trabajo futuro, no como eje central.

CRUZADO = {
    # (origen -> destino): {vista: accuracy}
    "2018 -> 2017 (Web)":  {"payload-hist": 0.8391, "metadatos": 0.5287, "byte-CNN": 0.9914},
    "2018 -> 2017 (SSH)":  {"payload-hist": 0.7921, "metadatos": 0.5139, "byte-CNN": 0.9990},
    "2018 -> 2017 (DoS)":  {"payload-hist": 0.4955, "metadatos": 0.4291, "byte-CNN": 0.9656},
    "2017 -> 2018 (Web)":  {"payload-hist": None,   "metadatos": None,   "byte-CNN": 0.5000},
    "2017 -> 2018 (SSH)":  {"payload-hist": 0.5855, "metadatos": 0.5219, "byte-CNN": 0.6051},
    "2017 -> 2018 (DoS)":  {"payload-hist": 0.6012, "metadatos": 0.4994, "byte-CNN": 0.6710},
}
# --------------------------------------------------------------------------
# HALLAZGO 14 (19-ago, CORREGIDO el 22-ago): generalizacion cruzada ENTRE DIAS
# del MISMO regimen (los tres dias volumetricos del 2018), no entre datasets.
# Fuente: models/phase2_crossdataset_*_p80.md  (6 pares dirigidos)
#
# OJO METODOLOGICO: el hallazgo se enuncio con SOLO 2 dias ("el modelo mas
# expresivo generaliza peor") y con el tercero resulto FALSO como
# generalizacion. Se conserva la correccion a la vista: no inducir leyes de n=2.
# --------------------------------------------------------------------------
CRUZADO_DIAS = {
    # (entreno -> test): {vista: (accuracy, recall_ataque)}
    "15-02 -> 16-02": {"payload-hist": (1.0000, 1.0000), "metadatos": (0.8393, 0.6970),
                       "byte-CNN": (1.0000, 1.0000)},
    "16-02 -> 15-02": {"payload-hist": (0.7904, 0.5807), "metadatos": (0.7510, 0.5573),
                       "byte-CNN": (0.9597, 0.9195)},
    "15-02 -> 20-02": {"payload-hist": (1.0000, 1.0000), "metadatos": (0.9854, 1.0000),
                       "byte-CNN": (0.4996, 0.0000)},
    "20-02 -> 15-02": {"payload-hist": (0.7218, 0.4435), "metadatos": (0.6025, 0.2092),
                       "byte-CNN": (0.5000, 0.0000)},
    "16-02 -> 20-02": {"payload-hist": (1.0000, 1.0000), "metadatos": (0.4700, 0.0000),
                       "byte-CNN": (0.5000, 0.0000)},
    "20-02 -> 16-02": {"payload-hist": (0.9928, 0.9855), "metadatos": (0.5011, 0.0063),
                       "byte-CNN": (0.5000, 0.0000)},
}
CRUZADO_DIAS_LECTURA = {
    "byte-CNN": "FALLA DE FORMA BINARIA: o ~1.0 (1.0000, 0.9597) o exactamente "
                "0.5 con recall de ataque 0.0000. Nunca un valor intermedio. "
                "Colapsa siempre que el 20-02 (LOIC) esta en un lado.",
    "payload-hist": "SE DEGRADA CON SUAVIDAD: 1.0000, 1.0000, 1.0000, 0.9928, "
                    "0.7904, 0.7218. Nunca colapsa.",
    "hipotesis": "Hulk y GoldenEye son floods HTTP de la misma familia (Python, "
                 "cabeceras aleatorizadas) y LOIC construye la peticion de otra "
                 "forma: el CNN memorizaria la firma de FAMILIA DE HERRAMIENTA. "
                 "NO demostrado.",
    "asimetria": "La direccion '-> 15-02' es dificil para TODAS las vistas, "
                 "probablemente porque su clase de ataque mezcla GoldenEye con "
                 "Slowloris (lento): 'volumetrico' no es homogeneo.",
    "para_la_memoria": "La eleccion CNN vs histograma es una eleccion entre "
                       "RIESGO y ROBUSTEZ: el CNN da 1.0000 si acierta la familia "
                       "y un IDS que no detecta NADA si no; el histograma nunca es "
                       "el mejor pero nunca baja de 0.72.",
}

# --------------------------------------------------------------------------
# RECALIBRACION REAL (23-ago): del oraculo a un metodo desplegable.
# Fuente: scripts/zeek/cross_recalibration.py -> models/phase3_recalibracion_*.json
#
# El "umbral oraculo" de CALIBRACION_CRUZADA es una cota superior, no un metodo:
# se elige conociendo las etiquetas del dia de test. Aqui se sustituye por Platt
# scaling -sigmoide(A*logit(p)+B)- ajustado sobre una muestra PEQUENA del dia
# nuevo y evaluado sobre el RESTO, que el calibrador no ha visto.
# Es la correccion que aplica el trabajo independiente "Cross-Dataset
# Transformer-IDS with Calibration and AUC Optimization" (2026), que documenta
# el MISMO fenomeno en otros datasets (NSL-KDD -> UNSW-NB15) y baja su ECE de
# 0.25 a 0.06. Aqui el punto de partida es peor (ECE ~0.499) y la mejora mayor.
# --------------------------------------------------------------------------
RECALIBRACION = {
    # (par): {"sin": (f1, recall, ece), "n25": (f1, recall, ece), "n1000": (...)}
    "16-02 -> 20-02": {"sin": (0.3333, 0.0000, 0.4973), "n25": (0.9750, 1.0000, 0.0216), "n1000": (0.9814, 1.0000, 0.0330)},
    "20-02 -> 16-02": {"sin": (0.3333, 0.0000, 0.4991), "n25": (0.9912, 1.0000, 0.0087), "n1000": (0.9907, 1.0000, 0.0125)},
    "15-02 -> 20-02": {"sin": (0.3332, 0.0000, 0.4967), "n25": (0.9828, 1.0000, 0.0170), "n1000": (0.9820, 1.0000, 0.0023)},
    "20-02 -> 15-02": {"sin": (0.3333, 0.0000, 0.4993), "n25": (0.9698, 0.9571, 0.0216), "n1000": (0.9890, 0.9997, 0.0180)},
    "15-02 -> 16-02": {"sin": (1.0000, 1.0000, 0.0002), "n25": (1.0000, 1.0000, 0.0000), "n1000": (1.0000, 1.0000, 0.0000)},
    "16-02 -> 15-02": {"sin": (0.9597, 0.9195, 0.0611), "n25": (0.9999, 1.0000, 0.0002), "n1000": (0.9999, 1.0000, 0.0002)},
}
RECALIBRACION_LECTURA = {
    "coste": "VEINTICINCO flujos etiquetados del dia nuevo bastan en los cuatro "
             "pares colapsados (F1 >= 0.9698). Mas etiquetas apenas mejoran, "
             "salvo en el par mas dificil (20-02 -> 15-02: recall 0.9571 con 25 "
             "y 0.9997 con 1000). En despliegue eso es que un analista etiquete "
             "25 conexiones.",
    "ece_diagnostico": "El ECE separa perfectamente los pares rotos (0.4967-0.4993, "
                       "practicamente el maximo posible) de los sanos "
                       "(0.0002-0.0611). Es la metrica que delata el problema, y "
                       "el trabajo no la reportaba.",
    "no_perjudica": "Recalibrar nunca empeora: el par que ya funcionaba pasa de "
                    "0.9597 a 0.9999.",
    "para_la_memoria": "Convierte el HALLAZGO 14 de diagnostico en receta: el "
                       "byte-CNN no hay que descartarlo, hay que RECALIBRARLO al "
                       "desplegarlo en un dominio nuevo, y el coste es trivial.",
}

# --------------------------------------------------------------------------
# CALIBRACION CRUZADA (22-ago): la vuelta de tuerca del HALLAZGO 14.
# Fuente: scripts/zeek/cross_calibration.py -> models/phase3_calibracion_*.json
#
# La accuracy con umbral fijo NO distingue "no transfiere la representacion" de
# "transfiere pero descalibrado". El AUC si, porque mide el ORDEN. Resultado:
# el byte-CNN tiene AUC-ROC >= 0.9724 en LOS SEIS PARES, y sus cuatro colapsos a
# recall 0 se recuperan enteros con el umbral adecuado (F1 >= 0.9849).
# El histograma es el que falla DE VERDAD en la direccion "-> 15-02": AUC 0.67 y
# 0.80, y ni con umbral oraculo pasa de 0.73 y 0.85.
# --------------------------------------------------------------------------
CALIBRACION_CRUZADA = {
    # (entreno -> test): {vista: (auc_roc, f1_umbral_0.5, f1_umbral_oraculo)}
    "16-02 -> 20-02": {"byte-CNN": (0.9724, 0.0000, 0.9849),
                       "payload-hist": (1.0000, 1.0000, 1.0000)},
    "20-02 -> 16-02": {"byte-CNN": (0.9886, 0.0000, 0.9918),
                       "payload-hist": (1.0000, 0.9927, 0.9997)},
    "15-02 -> 20-02": {"byte-CNN": (0.9758, 0.0000, 0.9872),
                       "payload-hist": (1.0000, 1.0000, 1.0000)},
    "20-02 -> 15-02": {"byte-CNN": (0.9854, 0.0000, 0.9899),
                       "payload-hist": (0.6749, 0.6145, 0.7346)},
    "15-02 -> 16-02": {"byte-CNN": (1.0000, 1.0000, 1.0000),
                       "payload-hist": (1.0000, 1.0000, 1.0000)},
    "16-02 -> 15-02": {"byte-CNN": (1.0000, 0.9581, 0.9999),
                       "payload-hist": (0.8023, 0.7348, 0.8538)},
}
CALIBRACION_LECTURA = {
    "byte-CNN": "Su REPRESENTACION transfiere en los seis pares (AUC 0.97-1.00). "
                "Lo que no transfiere es la CALIBRACION: en el dia nuevo sus "
                "puntuaciones caen dos ordenes de magnitud (media 0.0051 en "
                "ataque, 0.0006 en benigno), asi que un umbral fijo de 0.5 lo "
                "manda todo a Benigno.",
    "payload-hist": "Bien calibrado, pero con TECHO de representacion: en la "
                    "direccion '-> 15-02' su AUC baja a 0.67/0.80 y ni con "
                    "umbral oraculo supera 0.73/0.85. Ahi el limite es real.",
    "para_la_memoria": "Nunca juzgar la transferencia entre dominios con un "
                       "umbral fijo. La accuracy a 0.5 decia 'CNN 0.5, "
                       "histograma 1.0'; el AUC dice lo contrario sobre la "
                       "calidad de la representacion. Y en despliegue: un IDS "
                       "con umbral fijo falla EN SILENCIO ante una herramienta "
                       "no vista, aunque el modelo siga sabiendo ordenar.",
}

# ==========================================================================
# ARQUITECTURAS: ¿aporta la ATENCION algo sobre lo nuestro? (24-ago)
# ==========================================================================
# Fuente: scripts/zeek/arquitecturas_eval.py -> models/phase3_arquitecturas_*.json
# Se comparan a igualdad de datos, particion y PRESUPUESTO DE PARAMETROS: si el
# modelo del estado del arte ganara solo por ser mas grande no probaria nada
# sobre la arquitectura.
# --------------------------------------------------------------------------
ARQUITECTURAS_SECUENCIA = {
    # dia: {modelo: (macro_f1, auc, parametros, segundos)}
    "22-02 Web (203/clase)": {
        "byte-CNN (este TFG)":     (0.9975, 1.0000, 29_762, 4),
        "byte-LSTM (este TFG)":    (0.8296, 0.9551, 52_482, 14),
        "byte-Transformer (SOTA)": (0.9778, 0.9969, 41_922, 144),
    },
    "02-03 Bot (4000/clase)": {
        "byte-CNN (este TFG)":     (1.0000, 1.0000, 29_762, 65),
        "byte-LSTM (este TFG)":    (0.9999, 1.0000, 52_482, 313),
        "byte-Transformer (SOTA)": (1.0000, 1.0000, 41_922, 3191),
    },
}
ARQUITECTURAS_FUSION = {
    "22-02 Web": {
        "fusion tardia (este TFG)": (0.9828, 0.9994, 31_042, 4),
        "atencion cruzada (SOTA)":  (0.9828, 0.9992, 72_066, 6),
    },
    "02-03 Bot": {
        "fusion tardia (este TFG)": (1.0000, 1.0000, 31_042, 64),
        "atencion cruzada (SOTA)":  (0.9999, 1.0000, 72_066, 137),
    },
}
ARQUITECTURAS_LECTURA = {
    "transformer": "NUNCA gana. Con pocos datos (dia web, 203/clase) es PEOR que "
                   "el byte-CNN: 0.9778 frente a 0.9975. Con datos suficientes "
                   "(dia Bot, 4000/clase) EMPATA: 1.0000 los dos. Y siempre cuesta "
                   "entre 36 y 49 veces mas tiempo (3.191 s frente a 65 s en el dia "
                   "grande). El coste cuadratico de la autoatencion que el documento "
                   "senala como su penalizacion queda MEDIDO, no solo citado.",
    "atencion_cruzada": "EMPATA con nuestra fusion tardia en los dos dias "
                        "(0.9828/0.9828 y 1.0000/0.9999) usando 2.3 veces mas "
                        "parametros y el doble de tiempo. La sofisticacion de la "
                        "fusion no compra nada en estos datos.",
    "matiz": "Ambos resultados son a igualdad de presupuesto y sin preentrenar. "
             "Un Transformer preentrenado sobre millones de trazas (ET-BERT) es "
             "otra cosa y NO se ha probado: aqui se contrasta la arquitectura, "
             "no el preentrenamiento.",
}

# ==========================================================================
# ABLACION (24-ago): ¿que caracteristica lleva la senal?
# ==========================================================================
# Fuente: scripts/zeek/ablation_features.py -> models/phase3_ablacion_*.json
# CORRIGE una afirmacion del trabajo: se habia escrito que `cv_local` era "LA
# feature del beaconing". La ablacion dice que no.
# --------------------------------------------------------------------------
ABLACION_GRUPOS = {           # dia Bot 02-03, macro-F1 CV out-of-fold
    "metadatos": 0.9985,
    "metadatos + rafaga": 0.9991,
    "metadatos + inter-arribo": 0.9989,
    "metadatos + rafaga + inter": 0.9989,
    "inter-arribo SOLO (6)": 0.9914,
    "rafaga SOLA (3)": 0.9909,
}
ABLACION_INTERARRIBO = {
    # caracteristica: (F1 sin ella, caida, F1 ella sola).  Las 6 juntas: 0.9914
    "dt_prev":            (0.9896, +0.0018, 0.9669),
    "dt_next":            (0.9900, +0.0014, 0.9641),
    "media_local":        (0.9789, +0.0125, 0.9638),
    "cv_local":           (0.9835, +0.0079, 0.9355),
    "regularidad":        (0.9949, -0.0035, 0.9062),
    "frac_cerca_mediana": (0.9887, +0.0026, 0.9336),
}
ABLACION_LECTURA = {
    "correccion": "Se habia escrito que `cv_local` era LA caracteristica del "
                  "beaconing. FALSO por partida doble: en leave-one-out la mas "
                  "importante es `media_local` (caida 0.0125 frente a 0.0079), y "
                  "por si sola la mejor es `dt_prev` (0.9669).",
    "regularidad_estorba": "Quitar `regularidad` MEJORA el resultado (-0.0035) y "
                           "por si sola es la peor (0.9062): es redundante con "
                           "`cv_local` y anade ruido. Deberia eliminarse.",
    "senal_cruda": "Un solo intervalo crudo (`dt_prev`) ya da 0.9669: la senal "
                   "esta en los intervalos mismos, y los estadisticos de "
                   "regularidad solo anaden 0.025 encima.",
    "grupos": "Sobre metadatos, rafaga e inter-arribo aportan casi lo mismo "
              "(+0.0006 y +0.0004) y NO son aditivos: juntos dan 0.9989, menos "
              "que la rafaga sola sobre metadatos. Miden lo mismo por dos vias.",
}

# ==========================================================================
# BUSQUEDA DE HIPERPARAMETROS (24-ago)
# ==========================================================================
# Fuente: scripts/zeek/hyperparam_search.py -> models/phase3_hiperparametros_*.json
# Hasta esta fecha TODOS los modelos usaban valores fijos elegidos a mano. La
# busqueda (RandomizedSearchCV, 30 combinaciones) se hace SOLO con CV dentro del
# dia de entrenamiento: el dia de test nunca participa en la eleccion.
# --------------------------------------------------------------------------
HIPERPARAMETROS = {
    "22-02 Web, metadatos": {
        "MLP":     {"por_defecto": 0.9107, "mejor": 0.9383, "ganancia": +0.0275, "segundos": 37},
        "XGBoost": {"por_defecto": 0.9556, "mejor": 0.9679, "ganancia": +0.0122, "segundos": 46},
    },
    "15-02 DoS, metadatos": {
        "MLP":     {"por_defecto": 0.9556, "mejor": 0.9619, "ganancia": +0.0063, "segundos": 2624},
        "XGBoost": {"por_defecto": 0.9814, "mejor": 0.9819, "ganancia": +0.0005, "segundos": 38},
    },
}
HIPERPARAMETROS_LECTURA = {
    "carencia_real": "Los dos modelos dejaban rendimiento sin recoger (+0.0275 el "
                     "MLP, +0.0122 XGBoost), asi que la falta de busqueda era una "
                     "carencia real del trabajo, no un detalle.",
    "no_explica_la_diferencia": "Pero NO explica la ventaja del ensemble dentro "
                                "del dia, y en NINGUNO de los dos dias: en el "
                                "22-02 la brecha baja de 0.0449 a 0.0296 y en el "
                                "15-02 de 0.0258 a 0.0200. Persiste siempre: era "
                                "una diferencia entre modelos, no entre ajustes.",
    "depende_del_dia": "La ganancia varia mucho: +0.0275 en el 22-02 y solo "
                       "+0.0063 en el 15-02, donde la mejor configuracion del MLP "
                       "resulto ser (256,128), EXACTAMENTE el valor por defecto "
                       "del trabajo -solo mejoraba la tasa de aprendizaje-.",
    "coste_de_ajustar": "Asimetria practica que conviene citar: ajustar el MLP "
                        "costo 2.624 s frente a los 38 s de XGBoost en el mismo "
                        "dia, 69 veces mas. En un despliegue real donde hay que "
                        "reajustar por dominio, eso pesa tanto como la exactitud.",
}

# ==========================================================================
# ESTADO DEL ARTE (22-ago) - contraste contra nuestro pipeline
# ==========================================================================
# Fuente documental: "Machine Learning en NIDS.pdf" (revision 2020-2026).
# Fuente experimental: scripts/zeek/sota_baselines.py -> models/phase3_sota_*.json
#
# El documento hace DOS afirmaciones comprobables sobre nuestros datos:
#   (A) "La supremacia del Ensemble Learning": RF/XGBoost/LightGBM dominan sobre
#       caracteristicas de flujo (~99,9% intra-dataset; XGBoost 0.9367 cruzado).
#   (B) El "shortcut learning" de Engelen et al. (WTMC2021): sin eliminar IPs y
#       puertos efimeros el modelo memoriza la topologia del laboratorio, da
#       99,99% en el lab y "fracasa por completo al generalizar en redes externas".
# --------------------------------------------------------------------------

SOTA_TAXONOMIA = [
    # (familia, ejemplos, que aporta, que cuesta)
    ("Ensembles sobre flujo", "Random Forest, XGBoost, LightGBM",
     "imbatibles en volumetrico, coste inferencial minimo", "miopia contextual"),
    ("Tabular profundo", "TabNet",
     "potencia de DNN con seleccion interpretable", "97% en 2017, 95% en 2018"),
    ("Grafos", "GNN, E-GraphSAGE",
     "movimiento lateral y anomalia topologica", "gestion de estado compleja"),
    ("Payload como imagen", "CNN 2D sobre bytes rasterizados",
     "patrones espaciales del codigo malicioso", "destruye la causalidad temporal"),
    ("Transformers", "ET-BERT, DeBERTav2",
     "semantica del paquete, malware ofuscado", "autoatencion O(N^2)"),
    ("Espacios de estados", "MambaNetBurst (Mamba-2)",
     "byte-level sin tokenizacion ni preentreno", "escala lineal en la secuencia"),
    ("Hibridos multimodales", "AE-GMM, CNN-RNN/LSTM, CPS-IDS (cross-attention)",
     "fusion de flujo y payload: el horizonte del campo", "complejidad de diseno"),
]

# Contraste (A), DENTRO del dia: macro-F1 con CV 5-Fold. Aqui los ensembles SI
# ganan modestamente en la vista tabular (metadatos), que es justo lo que afirma
# la literatura; el margen mayor es de +4,7 puntos (22-02). Ojo a la ultima fila:
# la vista con FUGA da 1.0000 exacto con LOS TRES modelos en LOS CINCO dias.
SOTA_INTRADIA = {
    # dia: {vista: {modelo: macro_f1}}
    "02-03 Bot": {
        "payload-hist": {"MLP": 0.9992, "RandomForest": 0.9992, "XGBoost": 0.9990},
        "metadatos":    {"MLP": 0.9985, "RandomForest": 0.9998, "XGBoost": 0.9994},
        "meta+rafaga":  {"MLP": 0.9991, "RandomForest": 0.9998, "XGBoost": 0.9996},
        "meta+FUGA":    {"MLP": 0.9996, "RandomForest": 1.0000, "XGBoost": 0.9996},
    },
    "15-02 GoldenEye+Slowloris": {
        "payload-hist": {"MLP": 0.9999, "RandomForest": 1.0000, "XGBoost": 0.9996},
        "metadatos":    {"MLP": 0.9556, "RandomForest": 0.9810, "XGBoost": 0.9814},
        "meta+rafaga":  {"MLP": 0.9954, "RandomForest": 0.9979, "XGBoost": 0.9981},
        "meta+FUGA":    {"MLP": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
    },
    "16-02 DoS-Hulk": {
        "payload-hist": {"MLP": 1.0000, "RandomForest": 0.9999, "XGBoost": 0.9995},
        "metadatos":    {"MLP": 0.9699, "RandomForest": 0.9751, "XGBoost": 0.9731},
        "meta+rafaga":  {"MLP": 0.9999, "RandomForest": 0.9999, "XGBoost": 0.9998},
        "meta+FUGA":    {"MLP": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
    },
    "20-02 DDoS-LOIC": {
        "payload-hist": {"MLP": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
        "metadatos":    {"MLP": 0.9990, "RandomForest": 1.0000, "XGBoost": 0.9994},
        "meta+rafaga":  {"MLP": 0.9981, "RandomForest": 0.9997, "XGBoost": 0.9991},
        "meta+FUGA":    {"MLP": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
    },
    "22-02 Web": {
        "payload-hist": {"MLP": 0.9951, "RandomForest": 0.9951, "XGBoost": 0.9852},
        "metadatos":    {"MLP": 0.9109, "RandomForest": 0.9581, "XGBoost": 0.9557},
        "meta+rafaga":  {"MLP": 0.9852, "RandomForest": 0.9975, "XGBoost": 0.9901},
        "meta+FUGA":    {"MLP": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
    },
}

# Contraste (A) ENTRE DIAS: es donde la afirmacion se decide, porque la pregunta
# util es la transferencia ENTRE DIAS. macro-F1 / AUC-ROC sobre el dia de test.
SOTA_CRUZADO = {
    # (par): {vista: {modelo: (macro_f1, auc_roc)}}
    "16-02 -> 20-02": {
        "payload-hist": {"MLP (nuestro)": (1.0000, 1.0000), "RandomForest": (1.0000, 1.0000), "XGBoost": (1.0000, 1.0000)},
        "metadatos":    {"MLP (nuestro)": (0.3180, 0.9270), "RandomForest": (0.3286, 0.4577), "XGBoost": (0.3276, 0.9269)},
        "meta+rafaga":  {"MLP (nuestro)": (0.3333, 0.9829), "RandomForest": (0.3336, 0.9937), "XGBoost": (0.3336, 0.9847)},
    },
    "20-02 -> 16-02": {
        "payload-hist": {"MLP (nuestro)": (0.9952, 1.0000), "RandomForest": (0.3333, 0.9994), "XGBoost": (0.3333, 0.5000)},
        "metadatos":    {"MLP (nuestro)": (0.3329, 0.9394), "RandomForest": (0.3333, 0.5009), "XGBoost": (0.3333, 0.9374)},
        "meta+rafaga":  {"MLP (nuestro)": (0.4960, 0.9871), "RandomForest": (0.3333, 0.9995), "XGBoost": (0.3333, 0.9992)},
    },
    "15-02 -> 20-02": {
        "payload-hist": {"MLP (nuestro)": (1.0000, 1.0000), "RandomForest": (1.0000, 1.0000), "XGBoost": (0.9999, 1.0000)},
        "metadatos":    {"MLP (nuestro)": (0.9583, 1.0000), "RandomForest": (0.9895, 0.9949), "XGBoost": (0.9876, 0.9895)},
        "meta+rafaga":  {"MLP (nuestro)": (0.9935, 0.9973), "RandomForest": (0.9957, 0.9997), "XGBoost": (0.9921, 0.9997)},
    },
    "20-02 -> 15-02": {
        "payload-hist": {"MLP (nuestro)": (0.7446, 0.7244), "RandomForest": (0.3333, 0.9368), "XGBoost": (0.3333, 0.5000)},
        "metadatos":    {"MLP (nuestro)": (0.4956, 0.8048), "RandomForest": (0.3525, 0.5725), "XGBoost": (0.3347, 0.7864)},
        "meta+rafaga":  {"MLP (nuestro)": (0.5996, 0.8977), "RandomForest": (0.4818, 0.9200), "XGBoost": (0.4480, 0.8877)},
    },
    "15-02 -> 16-02": {
        "payload-hist": {"MLP (nuestro)": (0.9996, 1.0000), "RandomForest": (1.0000, 1.0000), "XGBoost": (0.9997, 1.0000)},
        "metadatos":    {"MLP (nuestro)": (0.9532, 0.9803), "RandomForest": (0.9662, 0.9955), "XGBoost": (0.9670, 0.9957)},
        "meta+rafaga":  {"MLP (nuestro)": (0.9969, 1.0000), "RandomForest": (0.9992, 1.0000), "XGBoost": (0.9984, 1.0000)},
    },
    "16-02 -> 15-02": {
        "payload-hist": {"MLP (nuestro)": (0.8599, 0.7905), "RandomForest": (0.7760, 0.9901), "XGBoost": (0.7762, 0.9988)},
        "metadatos":    {"MLP (nuestro)": (0.8444, 0.8833), "RandomForest": (0.5744, 0.8185), "XGBoost": (0.6096, 0.8469)},
        "meta+rafaga":  {"MLP (nuestro)": (0.6697, 0.9296), "RandomForest": (0.7456, 0.9198), "XGBoost": (0.6602, 0.9227)},
    },
}

# Contraste (B): la FUGA de IPs y puertos, medida en nuestros datos.
# macro-F1 de la vista meta+FUGA (metadatos + puerto de origen + octetos de ambas IPs)
SOTA_FUGA = {
    "16-02 -> 20-02": {"MLP (nuestro)": 0.7756, "RandomForest": 1.0000, "XGBoost": 1.0000},
    "20-02 -> 16-02": {"MLP (nuestro)": 1.0000, "RandomForest": 1.0000, "XGBoost": 1.0000},
    "15-02 -> 20-02": {"MLP (nuestro)": 0.8759, "RandomForest": 1.0000, "XGBoost": 1.0000},
    "20-02 -> 15-02": {"MLP (nuestro)": 0.9886, "RandomForest": 1.0000, "XGBoost": 1.0000},
    "15-02 -> 16-02": {"MLP (nuestro)": 1.0000, "RandomForest": 1.0000, "XGBoost": 0.9999},
    "16-02 -> 15-02": {"MLP (nuestro)": 0.9960, "RandomForest": 1.0000, "XGBoost": 1.0000},
}
SOTA_FUGA_MECANISMO = {
    "ips_atacantes_2018": 18,
    "empiezan_por_18": 15,          # de 18 IPs atacantes en 6 dias
    "rango_victimas": "172.31.69.x  (las 12 victimas)",
    "lectura": "Un modelo que aprenda 'origen 18.x -> ataque' transfiere PERFECTO "
               "entre cualquier par de dias del dataset. Por eso la vista con fuga "
               "da F1 = 1.0000 cruzado con RF y XGBoost en cinco de los seis pares.",
}

SOTA_LECTURA = {
    "afirmacion_A": "SE CONFIRMA DENTRO DEL DIA y se INVIERTE entre dias. Dentro "
                    "del dia los ensembles ganan de forma modesta en la vista "
                    "tabular, tal y como afirma la literatura: hasta +4.7 puntos "
                    "en metadatos (22-02: 0.9581 RF frente a 0.9109 del MLP). "
                    "Entre dias se da la vuelta y nuestro MLP GANA en las "
                    "direcciones dificiles (0.9952 vs 0.3333 en payload "
                    "20-02->16-02; 0.8444 vs 0.5744/0.6096 en metadatos "
                    "16-02->15-02). O sea: los ensembles son mejores en su dia y "
                    "peores fuera de el, que es lo contrario de lo que un NIDS "
                    "necesita.",
    "matiz_calibracion": "Buena parte de esa ventaja NO es representacional: los "
                         "AUC de RF/XGBoost suelen ser altos donde su F1 se hunde "
                         "(RF 20-02->16-02: F1 0.3333 con AUC 0.9994). Es el mismo "
                         "problema de CALIBRACION del HALLAZGO 14, y afecta a TODAS "
                         "las familias de modelo, no solo al byte-CNN. Nuestro MLP "
                         "resulta estar mejor calibrado entre dominios.",
    "afirmacion_B": "SE CONFIRMA, y peor de lo que advierte Engelen: la fuga no "
                    "solo infla el laboratorio, SOBREVIVE A LA VALIDACION CRUZADA "
                    "ENTRE DIAS, porque el laboratorio reutiliza los rangos de "
                    "direcciones todos los dias. Un investigador que valide entre "
                    "dias veria 1.0000 y concluiria que su modelo generaliza.",
}

# --------------------------------------------------------------------------
# HALLAZGO 15 (21-ago): la firma del Bot es la PERIODICIDAD (beaconing).
# Fuente: conn.log del dia 02-03 (analisis en el diario del 19-22 de agosto).
# --------------------------------------------------------------------------
BOT_BEACONING = {
    "c2": "18.219.211.138:8080",
    "n_bots": 10,
    "paquetes_al_c2": 438_825,
    "ventana_local": "10:13:28-15:53:46",
    "hueco_maximo_s": 32.6,          # continua: la doc dice 2 franjas y es 1
    "meseta_paq_por_10min": 8_035,   # de 11:40 a 15:20, constante a 3 cifras
    "pico_rampa": 38_318,            # 11:10-11:30
    "picos_ordenes": {"14:20": 22_873, "15:30": 34_065, "15:40": 34_927},
    "lectura": "Cuarto regimen. No vive en el payload ni en el volumen sino en "
               "el INTERVALO entre conexiones. Ninguna vista actual lo mide: "
               "meta+rafaga incluso RESTA (0.9964 vs 0.9986 de metadata sola).",
}

# El BEACONING, medido (22-ago). El perfil agregado NO bastaba: el DDoS-LOIC
# tambien es plano. La medida que si separa es el INTERVALO entre conexiones
# consecutivas de un mismo origen, y se calcula desde los .npz (ts + orig_h),
# sin necesidad del conn.log. Fuente: figuras/cache/interarribo_02-03.npz.
BOT_INTERARRIBO = {
    "modas": {"0.50-0.55 s": 0.418, "2.00-2.05 s": 0.493},
    "fraccion_en_las_dos_modas": 0.911,
    "mediana_ataque_s": 0.531,
    "mediana_benigno_s": 0.372,
    "banda_050_055": {"ataque": 0.418, "benigno": 0.013, "contraste": 32.0},
    "concentracion_pm20pct": {"Bot": 0.471, "benigno_mismo_dia": 0.053,
                              "DDoS-LOIC": 0.033, "DoS-Hulk": 0.130},
    "lectura": "El Bot late con DOS intervalos discretos (~0.5 s y ~2.0 s) que "
               "concentran el 91.1% de sus intervalos en dos bandas de 50 ms, "
               "mientras el benigno del mismo dia es una curva suave decreciente. "
               "Una sola caracteristica -el inter-arribo- separaria el ataque de "
               "forma trivial, y NINGUNA vista del trabajo la calcula: es el "
               "argumento definitivo del Eje E.",
}

# --------------------------------------------------------------------------
# EJE E EJECUTADO (22-ago): el inter-arribo COMO VISTA, y la evasion bien hecha.
# Fuente: scripts/zeek/interarrival_eval.py -> models/phase3_interarribo_*.md
#
# Seis caracteristicas de inter-arribo por flujo (dt_prev, dt_next, media_local,
# cv_local, regularidad, frac_cerca_mediana), calculadas desde el .npz con `ts` y
# `orig_h`, SIN conn.log. Prueba de evasion: el atacante sobrescribe los primeros
# bytes de cada flujo de ataque con los de un cliente benigno.
# --------------------------------------------------------------------------
EJE_E_EVASION = {
    # dia: {vista: (recall original, recall evadido)}
    "02-03 Bot": {"payload (byte-CNN)": (1.0000, 0.0025),
                  "meta+rafaga": (0.9983, 0.9983),
                  "inter-arribo solo": (0.9900, 0.9900),
                  "meta+inter-arribo": (0.9933, 0.9933)},
    "16-02 DoS-Hulk": {"payload (byte-CNN)": (1.0000, 0.0417),
                       "meta+rafaga": (1.0000, 1.0000),
                       "inter-arribo solo": (0.9950, 0.9950),
                       "meta+inter-arribo": (0.9942, 0.9942)},
    "20-02 DDoS-LOIC": {"payload (byte-CNN)": (1.0000, 0.0108),
                        "meta+rafaga": (0.9992, 0.9992),
                        "inter-arribo solo": (0.9467, 0.9467),
                        "meta+inter-arribo": (1.0000, 1.0000)},
    "22-02 Web": {"payload (byte-CNN)": (0.9672, 0.0164),   # prefijo 160: ver aviso
                  "meta+rafaga": (1.0000, 1.0000),
                  "inter-arribo solo": (0.8525, 0.8525),
                  "meta+inter-arribo": (0.9508, 0.9508)},
}
# EL AVISO METODOLOGICO (22-ago), y es importante para la memoria:
# en el dia WEB, sobrescribir 160 bytes no evade la deteccion, DESTRUYE EL ATAQUE
# (el `union select` vive en esos bytes). Repetido con un prefijo de 24 bytes, que
# NO llega a la inyeccion, el payload aguanta: 0.9672 -> 0.8852 (caida 0.0820).
EVASION_PREFIJO_WEB = {"prefijo_160": (0.9672, 0.0164), "prefijo_24": (0.9672, 0.8852)}
EJE_E_LECTURA = {
    "payload": "Se desploma donde los primeros bytes son la HUELLA DE LA "
               "HERRAMIENTA y no el ataque: Bot 0.0025, Hulk 0.0417, LOIC 0.0108. "
               "Sobrescribirlos es gratis para el atacante y el ataque sigue "
               "funcionando.",
    "web_excepcion": "El dia web es la excepcion que confirma la regla: con 24 "
                     "bytes (sin tocar la inyeccion) el payload aguanta en 0.8852. "
                     "Su firma es CONTENIDO genuino, no fingerprint. El HALLAZGO 4 "
                     "sobrevive al test de evasion cuando el test se hace bien.",
    "interarribo": "Seis features temporales, sin mirar un solo byte, dan recall "
                   "0.9900 en el Bot y 0.9950 en el Hulk, y son inmunes a la "
                   "evasion por construccion. Caen a 0.8525 en el dia web, que es "
                   "justo donde la firma NO es temporal: no son buenas 'porque si'.",
    "limitacion_honesta": "El inter-arribo NO mejora a la rafaga: meta+rafaga iguala "
                          "o supera a meta+inter-arribo en 3 de los 4 dias. Su valor "
                          "es ser una vista COMPACTA (6 features) e inmune a la "
                          "evasion, y demostrar que el beaconing del HALLAZGO 15 es "
                          "USABLE y no solo medible. No es una vista superior.",
}

# --------------------------------------------------------------------------
# HALLAZGO 16 (21-ago): el pipeline de payload es CIEGO al 94,4% de la
# Infiltration, POR CONSTRUCCION. Resultado negativo.
# Fuente: models/phase3_infiltration_Wednesday-28-02-2018.md (desde conn.log)
# --------------------------------------------------------------------------
INFILTRACION_CEGUERA = {
    "conexiones_salientes_victima": 193_097,
    "con_payload": 10_774,           # 5,6%
    "sin_payload": 182_323,
    "fraccion_sin_payload": 0.944,
    "sin_servicio_zeek": 183_907,    # service = "-"
    "conn_state": {"S0": 158_474, "REJ": 21_069, "SF": 8_505,
                   "RSTR": 2_255, "S1": 1_140, "SH": 988},
    "c2": {"ip": "13.58.225.34", "puerto": 31_337, "conexiones": 5,
           "bytes_app": 195_816, "con_payload_pct": 100.0},
    "destinos_escaneados": 612,
    "lectura": "No es que el payload funcione PEOR: es que NO PUEDE VER el "
               "ataque. Una fase entera de la intrusion (el reconocimiento) es "
               "estructuralmente invisible. Contraste en el mismo dia: las 5 "
               "conexiones del C2 (0.003% del ataque) llevan payload al 100%.",
}

# Reutilizacion de infraestructura del laboratorio (aviso metodologico):
# la MISMA IP hace de atacante en dias y roles distintos. No contamina nuestras
# vistas (la IP no es una feature), pero invalidaria cualquier experimento que
# incluyera identificadores de red.
REUTILIZACION_IPS = {
    "18.219.211.138": ["DoS-GoldenEye (15-02)", "C2 de la botnet (02-03)"],
    "18.218.115.60":  ["Web Attacks (22-02)", "uno de los 10 del DDoS (20-02)"],
}

# Por que transfiere el payload en cada caso (matiz del HALLAZGO 10):
CRUZADO_MOTIVO = {
    "Web": ("contenido intrinseco", "union select, <script>", "robusto"),
    "SSH": ("fingerprint de herramienta", "banner paramiko compartido", "evadible"),
    "DoS": ("fingerprint de herramienta", "User-Agents de Hulk/GoldenEye", "evadible"),
}

# ==========================================================================
# 14. CORRECCION DEL TUTOR 1 - EL SERVICIO SUSTITUYE AL PUERTO
# ==========================================================================
# Fuente: models/phase3_service_id_*.md
# El contenido (DPI, firmas de los analizadores de Zeek) confirma el puerto
# casi siempre en un laboratorio: ningun resultado previo cambia. El valor
# es metodologico (context independence), y se ve en los flujos que la
# convencion de puertos dejaba fuera.

SERVICIO_VS_PUERTO = {
    # dia: (comparables, confirman, contradicen)
    "14-02 (SSH)":        (2_200_888, 2_200_419, 469),
    "22-02 (Web)":        (2_769_964, 2_769_217, 747),
    "16-02 (DoS)":        (4_038_401, 4_037_957, 444),
    "04-07 2017 (SSH)":   (98_154, 98_033, 121),
    "05-07 2017 (DoS)":   (260_796, 259_410, 1_386),
    "06-07 2017 (Web)":   (81_352, 81_330, 22),
}
# Lo que cambia al seleccionar por contenido en vez de por puerto
SELECCION_SERVICIO = {
    "14-02 (SSH)": {"puerto_sin_contenido": 75, "contenido_fuera_de_puerto": 0,
                    "efecto": "el SSH benigno pasa de 433 a 358 flujos"},
    "22-02 (Web)": {"puerto_sin_contenido": 111, "contenido_fuera_de_puerto": 200,
                    "efecto": "200 flujos HTTP que la seleccion por puerto ignoraba"},
    "16-02 (DoS)": {"puerto_sin_contenido": 135, "contenido_fuera_de_puerto": 61,
                    "efecto": "61 flujos HTTP fuera del puerto 80"},
}
# Distribucion de servicios identificados por contenido (% de flujos del dia)
SERVICIOS_POR_DIA = {
    "14-02": {"rdp": 34.77, "ssl": 32.59, "http": 19.16, "smb": 9.11,
              "ssh": 4.29, "other": 0.07},
    "22-02": {"rdp": 47.27, "ssl": 26.52, "http": 16.56, "smb": 9.32,
              "other": 0.29, "ssh": 0.04},
    "16-02": {"http": 54.44, "rdp": 24.21, "ssl": 16.35, "smb": 4.92,
              "other": 0.07, "ssh": 0.01},
}

# ==========================================================================
# 15. CORRECCION DEL TUTOR 2 - ATRIBUTOS DEL PAYLOAD (LITERATURA) + ZEEK
# ==========================================================================
# Fuente: models/phase3_payload_attrs_*.md  (CV accuracy)
# HALLAZGO 13: 19 descriptores interpretables valen lo que 257 dimensiones
# de histograma, y ademas NO diluyen la fusion con los metadatos de Zeek.

ATRIBUTOS_PAYLOAD = {
    #                    attrs(19) hist(257) zeek(7)  zeek+attrs(26) zeek+hist(264)
    "Cifrado (14-02)":  (0.9833, 0.9847, 0.9986, 0.9958, 0.9819),
    "En claro (22-02)": (0.9606, 0.9753, 0.9926, 0.9877, 0.9877),
    "Volumetrico (16-02)": (1.0000, 1.0000, 1.0000, 1.0000, 1.0000),
}
ATRIBUTOS_VISTAS = ["payload-attrs (19)", "payload-hist (257)", "zeek-meta (7)",
                    "zeek+attrs (26)", "zeek+hist (264)"]
ATRIBUTOS_NDIM = [19, 257, 7, 26, 264]

# Los 19 descriptores y su origen bibliografico (para la tabla de la memoria)
DESCRIPTORES = [
    ("entropy_norm", "Entropia de Shannon normalizada", "Lyda & Hamrock 2007"),
    ("distinct_ratio", "Riqueza: bytes distintos / total", "PAYL, Wang & Stolfo 2004"),
    ("max_freq", "Frecuencia del byte dominante", "PAYL, Wang & Stolfo 2004"),
    ("top4_mass", "Masa de los 4 bytes dominantes", "PAYL, Wang & Stolfo 2004"),
    ("mean_byte", "Media del valor de byte", "PAYL, Wang & Stolfo 2004"),
    ("std_byte", "Desviacion del valor de byte", "PAYL, Wang & Stolfo 2004"),
    ("l1_uniform", "Distancia L1 a la distribucion uniforme", "PAYL, Wang & Stolfo 2004"),
    ("chi2_uniform", "Chi-cuadrado frente a la uniforme", "Dorfinger et al. 2011"),
    ("coincidence_idx", "Indice de coincidencia", "Lyda & Hamrock 2007"),
    ("compress_ratio", "Ratio de compresion (zlib)", "aprox. complejidad de Kolmogorov"),
    ("bigram_entropy_norm", "Entropia de 2-gramas", "Anagram, Wang et al. 2006"),
    ("bigram_distinct", "Diversidad de 2-gramas", "Anagram, Wang et al. 2006"),
    ("printable_ratio", "Fraccion de bytes imprimibles", "deteccion de inyecciones"),
    ("alnum_ratio", "Fraccion de alfanumericos", "deteccion de inyecciones"),
    ("ctrl_ratio", "Fraccion de caracteres de control", "deteccion de shellcode"),
    ("high_ratio", "Fraccion de bytes no-ASCII (>127)", "deteccion de shellcode"),
    ("null_ratio", "Fraccion de bytes nulos", "deteccion de shellcode"),
    ("longest_print_run", "Racha imprimible mas larga", "deteccion de inyecciones"),
    ("transition_rate", "Tasa de transicion imprimible/no", "deteccion de inyecciones"),
]

# Medias por clase de los 19 descriptores (para el grafico de separacion).
# Fuente: models/phase3_payload_attrs_<dia>_<servicio>.md, seccion "media por clase".
ATRIBUTOS_MEDIAS = {
    "Cifrado (14-02, SSH)": {
        # atributo: (ataque, benigno)
        "entropy_norm": (0.9223, 0.8282), "distinct_ratio": (1.0000, 0.9149),
        "max_freq": (0.0376, 0.0544), "top4_mass": (0.1309, 0.1911),
        "mean_byte": (0.4239, 0.3848), "std_byte": (0.5264, 0.4593),
        "l1_uniform": (0.3235, 0.5072), "chi2_uniform": (0.5476, 0.6214),
        "coincidence_idx": (0.0066, 0.0172), "compress_ratio": (0.3580, 0.3728),
        "bigram_entropy_norm": (0.4321, 0.4337), "bigram_distinct": (0.5768, 0.5986),
        "printable_ratio": (0.5757, 0.6945), "alnum_ratio": (0.4282, 0.5430),
        "ctrl_ratio": (0.1142, 0.1043), "high_ratio": (0.3074, 0.1997),
        "null_ratio": (0.0376, 0.0501), "longest_print_run": (0.5513, 0.5691),
        "transition_rate": (0.0536, 0.0550),
    },
    "En claro (22-02, Web)": {
        "entropy_norm": (0.8266, 0.7528), "distinct_ratio": (0.7479, 0.5118),
        "max_freq": (0.0514, 0.0636), "top4_mass": (0.1551, 0.1988),
        "mean_byte": (0.3632, 0.3172), "std_byte": (0.3814, 0.3426),
        "l1_uniform": (0.5330, 0.6453), "chi2_uniform": (0.5888, 0.6338),
        "coincidence_idx": (0.0133, 0.0206), "compress_ratio": (0.4177, 0.4113),
        "bigram_entropy_norm": (0.4599, 0.4537), "bigram_distinct": (0.7243, 0.7011),
        "printable_ratio": (0.8275, 0.8824), "alnum_ratio": (0.6171, 0.6316),
        "ctrl_ratio": (0.0344, 0.0433), "high_ratio": (0.1371, 0.0739),
        "null_ratio": (0.0034, 0.0051), "longest_print_run": (1.0000, 1.0000),
        "transition_rate": (0.0000, 0.0000),
    },
}

# Importancia por permutacion sobre la vista `zeek+attrs` (dia web).
# Demuestra que la union usa DE VERDAD las dos familias, no una sola.
IMPORTANCIA_PERMUTACION_WEB = [
    ("bytes_per_pkt", 0.0659, 0.0098, "zeek"),
    ("bigram_entropy_norm", 0.0537, 0.0124, "payload"),
    ("n_pkts", 0.0390, 0.0091, "zeek"),
    ("std_byte", 0.0341, 0.0142, "payload"),
    ("burst_1s", 0.0293, 0.0124, "zeek"),
    ("ctrl_ratio", 0.0244, 0.0204, "payload"),
    ("burst_30s", 0.0146, 0.0091, "zeek"),
    ("burst_5s", 0.0146, 0.0091, "zeek"),
    ("bigram_distinct", 0.0049, 0.0060, "payload"),
    ("alnum_ratio", 0.0049, 0.0098, "payload"),
    ("chi2_uniform", 0.0024, 0.0119, "payload"),
    ("null_ratio", 0.0024, 0.0049, "payload"),
]

# ==========================================================================
# 16. HALLAZGOS CLAVE (para la tabla-resumen y la presentacion)
# ==========================================================================

HALLAZGOS = [
    (1, "Ataques sin payload",
     "FTP-BruteForce (REJ) y DoS-SlowHTTPTest dejan 0 bytes analizables: "
     "invisibles al payload, solo detectables por flujo."),
    (2, "Perdida silenciosa de datos",
     "Zeek se detenia en un record intermedio corrupto; sanear el PCAP antes "
     "es obligatorio (se perdia la tarde entera del ataque SSH)."),
    (3, "El 99.96 % es un espejismo",
     "Con benigno diverso el modelo separa el PROTOCOLO, no el ataque: sobre "
     "SSH benigno real marca el 96 % de los usuarios legitimos como ataque."),
    (4, "En payload en claro el payload gana",
     "El dia web invierte el resultado del SSH (payload 0.99 vs metadatos 0.93): "
     "cada vista gana en su regimen."),
    (5, "El byte-CNN es el modelo mas fuerte",
     "La convolucion aprende n-gramas de bytes; gana en deteccion y en "
     "identificar el TIPO de ataque."),
    (6, "La fusion bien hecha es robusta",
     "El hibrido de dos ramas con fusion tardia es ~1.0 en ambos regimenes y "
     "corrige la dilucion de concatenar vistas a ciegas."),
    (7, "El exito del payload sobre el cifrado es un fingerprint",
     "La saliency prueba que el CNN lee el banner `paramiko` en claro, no el "
     "contenido cifrado: senal real pero evadible."),
    (8, "La firma del DoS es volumetrica (revisado)",
     "Con benigno genuino el payload tambien separa, pero es un fingerprint de "
     "herramienta; la rafaga agregada es la unica robusta ante evasion."),
    (9, "La firma del payload en claro generaliza entre datasets",
     "El byte-CNN entrenado en 2018 detecta el web de 2017 con 0.9914; los "
     "metadatos caen al azar (0.53), son especificos del laboratorio."),
    (10, "No basta con que generalice: hay que ver por que",
     "Solo el web transfiere por contenido intrinseco; SSH y DoS transfieren "
     "por fingerprints de herramienta compartidos, evadibles."),
    (11, "Prueba activa de evasion",
     "Camuflando los primeros bytes, el recall del payload cae (SSH 1.0->0.35, "
     "DoS 0.72->0.43) mientras la conducta permanece invariante (~1.0)."),
    (12, "Sin etiquetas la tesis se replica",
     "Entrenando solo con benigno, cada regimen esconde su anomalia en una "
     "vista distinta; el zero-day volumetrico es intrinsecamente dificil."),
    (13, "19 atributos interpretables valen lo que 257 dimensiones",
     "Y ademas no diluyen la fusion: la dilucion del 16-jun era un problema de "
     "REPRESENTACION, no de la fusion."),
    (14, "Lo que no transfiere entre dias es el UMBRAL, no la representacion",
     "Con umbral fijo el byte-CNN parece colapsar entre dias; el AUC muestra "
     "que el orden se conserva. Se arregla recalibrando con 25 etiquetas."),
    (15, "La firma de la botnet es la PERIODICIDAD",
     "Dos modas discretas (~0.5 s y ~2.0 s) concentran el 91.1% de sus "
     "intervalos; ninguna de las tres vistas del protocolo la calcula."),
    (16, "El payload es CIEGO al 94.4% de la Infiltration",
     "182.323 de 193.097 conexiones del reconocimiento no llevan un byte de "
     "aplicacion. No es que funcione peor: no puede ver. Limite del enfoque."),
    (17, "La evasion distingue la huella de herramienta del contenido real",
     "Camuflar los primeros bytes hunde el payload salvo en el dia web, donde "
     "la firma es contenido genuino. Es la prueba que si discrimina."),
    (18, "La fuga de IPs sobrevive a la validacion cruzada entre dias",
     "Incluir IPs y puertos como atributos infla el resultado incluso al "
     "evaluar en otro dia: el atajo viaja con el conjunto de datos."),
    (19, "La evaluacion intra-dia esta SATURADA y no discrimina",
     "Las mismas tres vistas, misma metrica y mismo protocolo en seis dias: "
     "el payload no baja de 0.973 y la conducta de 0.982. Con un solo host "
     "atacante por dia cualquier vista dispone de un atajo suficiente, asi "
     "que un 0.99 aqui no mide deteccion. La discriminacion esta en la "
     "robustez, no en el macro-F1."),
]

# Errores de limite de ventana: la leccion metodologica que se repitio dos veces
LECCION_VENTANAS = (
    "Dos veces (SSH 17-jun, DoS 11-ago) un limite de ventana mal fijado "
    "contamino el benigno con el propio atacante y produjo una conclusion "
    "erronea. Procedimiento fijado: verificar que la ventana cubre toda la "
    "actividad continua del atacante sobre el dataset COMPLETO, no sobre una "
    "sola captura."
)

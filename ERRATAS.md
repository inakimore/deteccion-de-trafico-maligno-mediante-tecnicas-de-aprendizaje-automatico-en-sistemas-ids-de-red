# Erratas de la memoria entregada

`DIF_Dissertation_2026/main.pdf` es **la versión entregada al ADDI el 8 de
septiembre de 2026**, sin modificar: es el mismo fichero, byte a byte
(`md5 e934d5d06bedb8d769b74ecf69d00dc2`). Después de la entrega se revisó el texto
contra el código, afirmación por afirmación —arquitecturas, tamaños de
experimento, métodos, recuentos y parámetros—, y aparecieron cinco erratas.
Se documentan aquí en lugar de corregirlas en el PDF, porque el PDF entregado es
el que tiene el tribunal y cambiarlo a posteriori haría que dejasen de coincidir.

**Ninguna de las cinco afecta a un resultado.** El auditor de coherencia
(`scripts/figuras/verificar_memoria.py`) contrasta las 432 cifras del texto y
las tablas contra `scripts/figuras/resultados.py` y sale en verde. Dos están en
figuras —una con cifras de escala desfasadas, otra con un rótulo cortado— y las
otras tres fallan al *describir* algo que el código hace de otra manera.

**El código de este repositorio sí está corregido** en los dos casos que lo
requerían (las erratas 1 y 2). Por eso, si se regeneran las figuras 3.2 y 5.2,
salen distintas de las que imprime `main.pdf`. Esa divergencia es deliberada y
es la que explica este fichero.

---

## 1. La figura 3.2 se quedó congelada en un estado antiguo del trabajo

**Dónde:** figura 3.2, «volumen procesado», capítulo 3.

| Dice la figura | Es |
|---|---|
| 6 días procesados, «**3** de CSE-CIC-IDS2018 + 3 de CIC-IDS2017» | **6** días del CSE-CIC-IDS2018 con conjunto construido + 3 del CIC-IDS2017 |
| **9.4 M** flujos TCP vectorizados | **17.203.272** conexiones TCP |
| **3** regímenes de firma: cifrado, en claro y volumétrico | **4**: cifrado, en claro, volumétrico y **periodicidad** |

El cuarto régimen entró el 21 de agosto, al incorporar el día de la botnet
(`02-03-2018`, Ares). Las cuatro fichas de esa figura estaban escritas a mano y
no se actualizaron con él.

**Es la más visible de las cinco** porque se contradice con la propia memoria a
tres páginas de distancia: el resumen, en la página I, dice «17.203.272
conexiones TCP repartidas en **seis** días del conjunto CSE-CIC-IDS2018».

**Por qué el auditor no la detectó.** `verificar_memoria.py` contrasta el texto
y las tablas de los capítulos, no las cadenas de texto que van dibujadas
*dentro* de una figura: ahí el número es un literal de Python sobre un lienzo,
no una cifra del documento. Las otras 41 figuras se derivan de datos y se mueven
solas al recalcularlas; esta era la excepción.

**Qué se ha corregido.** Las cuatro fichas se derivan ahora de `resultados.py`
(`DIAS_CON_DATASET`, `DIAS_CON_DATASET_2017`, `GIGABYTES_CAPTURA`,
`FLUJOS_TOTALES_2018`, `len(REGIMENES)`), de modo que no pueden volver a
desfasarse. Ningún resultado del capítulo 4, 5 o 6 cita esta figura como fuente:
es una ficha de escala, dice cuánto material se procesó, no qué salió.

---

## 2. A la figura 5.2 se le sale del recorte la última palabra de un rótulo

**Dónde:** figura 5.2, «La evasión separa la huella de la herramienta del
contenido real», capítulo 5. Panel derecho.

El rótulo bajo ese panel se imprime como «día web: con 160 bytes se borra el» y
ahí se acaba. El texto completo es «**día web: con 160 bytes se borra el
ataque**»: el rótulo mide 38 px más que el panel —que es el estrecho de los
dos— y la última palabra queda fuera del recorte.

Ese panel no es decorativo: es el aviso metodológico del capítulo. Dice que, en
el día web, sobrescribir los primeros 160 bytes no evadía la detección sino que
*destruía el ataque*, porque la inyección SQL vive en esos bytes; repetida la
prueba con un prefijo de 24 bytes, que no la toca, el recall aguanta en 0.8852.
La regla que sale de ahí —un test de evasión solo vale si el ataque sigue siendo
el ataque después de la modificación— está enunciada entera en el texto de la
sección, así que no se pierde información: el defecto es de composición.

**Qué se ha corregido.** El rótulo va ahora en dos líneas y entra completo. De
paso, las etiquetas del eje del panel izquierdo: a 7,4 pt «DoS-Hulk» y
«DDoS-LOIC» se tocaban y se leían como una sola palabra; bajadas a 6,6 pt, ya
no. Como en la errata 1, `main.pdf` no se recompila.

---

## 3. El cuarto escalar de la vista de metadatos no es la duración

**Dónde:** §3.2, §3.3 y §4.2.

> «Cuatro escalares de la conexión: número de paquetes, bytes totales, longitud
> de la carga útil y **duración**.»

Los cuatro escalares implementados son `n_pkts`, `tot_bytes`, `seq_len` y
`tot_bytes / n_pkts`. El cuarto es **bytes por paquete**. La duración no se
calcula en ningún punto del *pipeline* y el fichero `.npz` no tiene esa columna.

Ninguna cifra cambia: los modelos siempre entrenaron con los cuatro escalares
que están en el código. El argumento tampoco, porque la propiedad que se le pide
a esa vista —ser invariante al camuflaje de bytes, ya que cuenta los bytes sin
leerlos— vale igual para «bytes por paquete» que para «duración».

---

## 4. La atención cruzada no sustituye a la concatenación: la incluye

**Dónde:** §5.1, descripción de `CrossAttentionNet`.

> «Fusión por atención cruzada bidireccional entre la rama de bytes y la de
> metadatos, **en lugar de concatenación**.»

La capa de decisión recibe `[pf, mf, a_m2p, a_p2m]`: los dos *embeddings*
originales de cada rama **concatenados**, más los dos vectores de atención
cruzada. La atención se añade a la concatenación, no la sustituye.

Esto refuerza la conclusión en lugar de debilitarla: significa que la
`CrossAttentionNet` **contiene a la fusión tardía como subconjunto** —tiene todo
lo que la fusión tardía usa, más dos vectores atendidos y 41.024 parámetros de
más— y aun así no la supera (0.9828 frente a 0.9828 en el día web; 0.9999 frente
a 1.0000 en el de la botnet). Un modelo que incluye a otro y no lo mejora dice
que lo añadido no aporta.

---

## 5. §2.4 remite a una explicación que §6.5 no da

**Dónde:** §2.4, cierre del apartado de conjuntos de datos.

> «Ninguno de los dos se ha usado aquí; **la sección 6.5 explica por qué el
> segundo sería el complemento más valioso**.»

§6.5, «Trabajo futuro», tiene cinco párrafos y ninguno menciona
Malware-Traffic-Analysis.net. La afirmación es defendible; lo que falta es el
desarrollo que se promete. Es un defecto de lectura, no de resultados.

La explicación que debería estar allí: Malware-Traffic-Analysis contiene
infecciones *reales*, no tráfico sintetizado en un laboratorio, y eso ataca
directamente el hallazgo central de este trabajo. Si dentro de un día todo
satura porque los ataques los genera un único programa con una única
configuración, el conjunto que rompería esa saturación es justamente el que no
tiene un generador detrás. El precio es que no viene etiquetado de forma
sistemática, que es lo que lo dejó fuera del alcance.

---

## Erratas ortográficas en las figuras

Dieciocho palabras sin tilde en el texto **dibujado dentro** de las figuras:
«tráfico legitimo» (5.1), «meta+rafaga» y «Volumetrico» (4.x y 5.x), «hibrido»,
«fusion», «caida», «caracteristicas», «origenes», «dialogo», «senal», «ningun».

Casi todas tienen la misma causa: la etiqueta se tomaba directamente de una
clave de `resultados.py`, y esas claves van en ASCII a propósito, porque se
indexan y se comparan —acentuar una rompe el acceso, y ya pasó tres veces con
`precision`, `entropia` y `rafaga`—. La solución no es acentuar la clave sino
`estilo.rotulo()`, que traduce clave a rótulo **solo en el momento de dibujar**.

Se encontraron con un script que recorre las 42 figuras, extrae todo el texto
realmente dibujado y contrasta cada palabra sin tilde contra la prosa de los
capítulos, que hace de autoridad ortográfica. El mismo script mide el recorte de
cada rótulo, y así apareció la errata 2. Estado actual del código: **0 tildes
pendientes, 0 rótulos cortados, 0 comas decimales** en las 42.

No se listan como erratas numeradas porque ninguna cambia lo que la figura dice.

---

## Tres imprecisiones menores

Ninguna es falsa en sentido estricto.

- **«número de paquetes»** cuenta solo los paquetes *que llevaban datos*: el
  *script* de Zeek emite una fila por segmento con `len > 0`, así que los ACK
  vacíos no entran.
- **«las intrínsecas se derivan de la cabecera»** es cierto en la taxonomía
  clásica, pero en esta implementación los cuatro escalares salen de contar la
  carga útil, no de leer campos de cabecera.
- **«sobre la secuencia cruda de bytes»**: el byte-CNN y el byte-LSTM tienen
  delante una capa de *embedding* de 24 dimensiones que §5.1 no menciona. La
  figura del anexo sí la dibuja.

---

## Lo que ya se corrigió antes de entregar

Estos **no** están en la memoria entregada; se listan para evitar confusiones al
leer el historial: tres referencias cruzadas rotas en el capítulo 6, el recuento
de modelos («ocho» cuando la lista tenía diez, y sin declarar el perceptrón
multicapa que produce todo el capítulo 4), el pie de la figura 5.4, una
afirmación sin fuente sobre la cobertura de las firmas estáticas, la atribución
del dato de TabNet y las comas decimales que babel-español reintroducía en modo
matemático.

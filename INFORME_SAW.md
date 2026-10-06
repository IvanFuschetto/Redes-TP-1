# Trabajo Práctico 1: File Transfer

**Materia:** Redes (TA048)  
**Institución:** Universidad de Buenos Aires (UBA) - Facultad de Ingeniería (FIUBA)  

---

## 1. Introducción

El presente trabajo práctico aborda el diseño, la especificación y la implementación de una aplicación de red bajo el paradigma cliente-servidor para la transferencia confiable de archivos (*Reliable Data Transfer*, RDT) a través del protocolo de transporte UDP (*User Datagram Protocol*).

UDP es un protocolo de la capa de transporte no confiable sin garantías de entrega ni orden de las entregas, se pretende construir mecanismos de confiabilidad a nivel de capa de aplicación.

Para garantizar la confiabilidad de la transmisión, se implementó un protocolo RDT de capa de aplicación CON MECANISMOS *Stop-and-Wait (SAW)* y *Selective Acknowledgment (SACK)* que admite las operaciones:
- **UPLOAD**: Transferencia unidireccional de un archivo local desde el proceso cliente hacia el almacenamiento del servidor.
- **DOWNLOAD:** Solicitud y transferencia unidireccional de un archivo existente en el servidor hacia el cliente.

---

## 2. Hipótesis

Para el desarrollo del protocolo y de la aplicación se establecieron las siguientes hipótesis operativas y de diseño:

1. **Canal de red no confiable con pérdidas y retardos:**
   - La red subyacente puede perder datagramas UDP tanto en el trayecto de ida (datos o sincronización) como en el de vuelta (confirmaciones o *ACKs*).
   - El canal puede presentar retardos apreciables y variables (*jitter*).
   - Se asume que cualquier datagrama que llegue con corrupción de bits es descartado silenciosamente por el mecanismo de suma de verificación (*checksum*) de UDP, manifestándose a nivel de aplicación como una pérdida de paquete.
   - Los datagramas pueden duplicarse o sufrir desordenamiento en tránsito; el protocolo debe ser capaz de detectar y descartar duplicados sin corromper el flujo de bytes.

2. **Límite de tamaño de paquete y prevención de fragmentación IP:**
   - La Unidad Máxima de Transferencia (*Maximum Transmission Unit*, MTU) estándar en redes Ethernet es de 1500 bytes.
   - El encabezado IPv4 ocupa 20 bytes y el encabezado UDP ocupa 8 bytes.
   - Por ende, la carga útil máxima disponible para UDP antes de causar fragmentación a nivel IP es $1500 - 20 - 8 = 1472$ bytes.
   - Nuestro diseño define un encabezado de aplicación de 3 bytes y un tamaño máximo de payload de datos de 1447 bytes, totalizando un tamaño máximo de datagrama de aplicación de 1450 bytes. Con los encabezados de red y transporte suma $1450 + 28 = 1478 \le 1500$ bytes, garantizando que **ningún paquete sea fragmentado por el kernel o la red**, minimizando la penalización de pérdida.

3. **Restricciones del sistema de archivos y tamaño máximo:**
   - Se establece por requisito un límite máximo de tamaño de archivo de 15 MiB ($15 \times 1024 \times 1024 = 15.728.640$ bytes). Por lo que bastan 3 bytes para indicar el tamaño del mismo, permitiendo representar hasta $2^{24} - 1 \approx 16.77$ MiB).
   - Los nombres de archivo se codifican en UTF-8 y su longitud está acotada a 255 bytes (1 byte de longitud en el mensaje SYN).
   - Si un archivo a subir ya existe en el servidor, o un archivo a descargar no existe, la operación debe ser rechazada inmediatamente en la fase de negociación inicial sin transferir datos.

4. **Modelo de concurrencia y puertos:**
   - El servidor escucha pasivamente en un puerto UDP indicado al momento de su iniciar su ejecución y debe atender a múltiples clientes concurrentemente.
   - El servidor debe implementar su propia capa de desmultiplexación interna basada en la tupla `(IP_cliente, puerto_cliente)`.

5. **Garantía de integridad transaccional:**
   - Ante una falla irrecuperable (por ejemplo, exceso de *timeouts* consecutivos o desconexión del par), los archivos transferidos parcialmente deben eliminarse del disco para evitar archivos corruptos.

---

## 3. Implementación

### 3.1. Arquitectura del Sistema

La solución está construida en Python 3 sobre la biblioteca estándar `socket`, utilizando sockets de datagramas (`socket.AF_INET`, `socket.SOCK_DGRAM`).

#### Desmultiplexación y Concurrencia en el Servidor

Todos los datagramas destinados al servidor se reciben siempre y en todo momento a través de un único puerto.

Para permitir que múltiples clientes suban o descarguen archivos en paralelo sin interferirse mutuamente, el servidor implementa una arquitectura basada en **hilos de trabajo y colas thread-safe**:
1. El hilo principal del servidor realiza el `bind` del socket a la dirección IP y puerto indicados por argumento `(args.host, args.port)` y establece un timeout periódico (`sock.settimeout(5)`) para permitir el manejo limpio de señales de interrupción (`KeyboardInterrupt` / Ctrl+C) y recolección de hilos terminados.
2. Mantiene una tabla de conexiones activas en memoria.
3. Al recibir un datagrama mediante :
   - Si la dirección `address` no existe en la tabla y el paquete tiene el flag `SYN` activo, se identifica una nueva sesión de transferencia. Se crea una cola de mensajes y se lanza un nuevo hilo dedicado a la función que maneja la operación (upload o download).
   - Si la dirección ya se encuentra registrada, el hilo principal simplemente deposita el paquete en la cola correspondiente.
   - Si un paquete llega sin la bandera `SYN` y no pertenece a una conexión registrada, es descartado.

Esta separación desacopla la recepción masiva de red de la lógica de negocio y estado de cada cliente individual.

---

### 3.2. Especificación Detallada de los Paquetes del Protocolo de Red

El protocolo se diseñó con un encabezado compacto y eficiente de **3 bytes**, maximizando el espacio para los datos útiles y permitiendo un análisis veloz de banderas y códigos de control.

#### Estructura del Encabezado

```
 0                   1                   2       
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sequence No  |    Ack No     |     Flags     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Payload (0 - 1447 B)          |
|                         ...                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


1. **Byte 0 - Sequence Number (SN):** Entero sin signo de 8 bits (rango 0 a 255). Identifica de manera unívoca la posición relativa **del paquete** en la secuencia. En Stop and Wait, avanza mediante aritmética modular: $SN_{siguiente} = (SN + 1) \pmod{256}$. En SACK sólo se numeran los paquetes de datos y el `FIN` del Emisor (empezando en 1 y con la misma aritmética modular); los paquetes de control (`SYN`, `SYN-ACK`, `ACK` y `FIN-ACK`) llevan `SN=0`, ya que el Emisor identifica las confirmaciones únicamente por el campo `ACKN`.
2. **Byte 1 - Acknowledgment Number (ACKN):** Entero sin signo de 8 bits (rango 0 a 255). En Stop and Wait confirma el número de secuencia exacto **del paquete recibido** que se está reconociendo. En SACK es un **ACK acumulativo**: indica el número de secuencia del último paquete recibido **en orden**, es decir, que todos los paquetes hasta ese número ya fueron recibidos.
3. **Byte 2 - Flags y Código de Error:** Compuesto por 5 bits de banderas de control y 3 bits para señalización de errores:
   - **Bit 7 (`TY`):** Tipo de protocolo RDT. `0` = Stop and Wait (SAW), `1` = SACK.
   - **Bit 6 (`OP`):** Operación. `1` = UPLOAD, `0` = DOWNLOAD.
   - **Bit 5 (`ACK`):** Indicador de confirmación. `1` si el paquete transporta un reconocimiento válido en el campo `Ack No`.
   - **Bit 4 (`SYN`):** Indicador de sincronización. `1` en la fase de establecimiento de conexión para negociar la transferencia y metadatos.
   - **Bit 3 (`FIN`):** Indicador de finalización. `1` para señalar el fin de los datos transmitidos y ordenar el cierre.
   - **Bits 2, 1, 0 (`ERR`):** 3 bits para codificar hasta 8 estados de error. Los errores contemplados (expresados en decimal) son:
     - `0`: Operación normal, sin error.
     - `1`: Nombre de archivo inválido.
     - `2`: El archivo ya existe en el servidor (durante UPLOAD).
     - `3`: El archivo excede el tamaño máximo permitido (> 15 MiB).
     - `4`: El archivo solicitado no existe en el servidor (durante DOWNLOAD).
     - `7`: Error de entrada/salida local al intentar leer o escribir en disco.

#### Mensajes de Control y Carga Útil en Handshake

Durante la fase de sincronización (`SYN = 1`), el payload no contiene fragmentos del archivo, sino estructuras de metadatos específicas:

- **`MessageSynUpload` (Fase SYN de UPLOAD):**
  - Bytes 0 a 2 (3 bytes): Tamaño del archivo en bytes (entero *big-endian* sin signo, hasta 16.777.215 bytes).
  - Byte 3 (1 byte): Longitud del nombre del archivo en bytes.
  - Bytes 4 en adelante: Nombre del archivo codificado en UTF-8.
- **`MessageSynDownload` (Fase SYN de DOWNLOAD):**
  - Byte 0 (1 byte): Longitud del nombre del archivo solicitado.
  - Bytes 1 en adelante: Nombre del archivo codificado en UTF-8.
- **`MessageSynAckDownload` (Respuesta SYN-ACK de DOWNLOAD, sólo SACK):**
  - Bytes 0 a 2 (3 bytes): Tamaño del archivo a descargar en bytes (entero *big-endian* sin signo). Le permite al Cliente (Receptor) verificar que recibió el archivo completo antes de aceptar el `FIN`.

#### Información SACK

En SACK, los paquetes de confirmación (`ACK=1`, sin `SYN` ni `FIN`) transportan en su payload la lista de bloques de paquetes que el Receptor recibió **fuera de orden**, es decir, posteriores a `ACKN` pero separados de él por al menos un paquete faltante (un *hueco*):

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  N (bloques)  |   Inicio 1    |     Fin 1     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Inicio 2    |     Fin 2     |      ...      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Byte 0:** Cantidad `N` de bloques.
- **Bytes siguientes:** `N` pares `(Inicio, Fin)` de 1 byte cada uno. Cada par representa un rango contiguo de números de secuencia recibidos, con ambos extremos inclusive.

Los bloques se arman agrupando los números de secuencia contiguos del buffer de fuera de orden, ordenados según su distancia circular a partir del próximo número esperado. Por ejemplo, si el Receptor tiene en orden hasta el paquete 10 y además recibió los paquetes 12, 13 y 15, envía `ACKN=10` con el payload `[2, 12, 13, 15, 15]`.

Como la ventana es de 16 paquetes, puede haber a lo sumo 15 paquetes fuera de orden y, por lo tanto, como máximo 8 bloques: el payload SACK nunca supera los 17 bytes.

### 3.3. Flujo y Máquina de Estados de las Operaciones

#### 3.3.1. Operación UPLOAD con SAW

La operación de subida consta de tres fases bien diferenciadas:

```
CLIENTE (Emisor)                                  SERVIDOR (Receptor)
================                                  ===================
    |                                                      |
    | --- SYN [SN=1, ACKN=0, SYN=1, MessageSynUpload] ---> | (Valida tamaño
    |                                                      |  y existencia)
    | <-- SYN-ACK [SN=1, ACKN=1, SYN=1, ACK=1, ERR=0] ---- |
    |                                                      |
 [Inicia envío]                                     [Crea archivo]
    |                                                      |
    | ------- DATA [SN=2, ACKN=0, Payload Chunk 1] ------> | (Escribe)
    | <------ ACK [SN=2, ACKN=2, ACK=1] ------------------ |
    |                                                      |
    | ------- DATA [SN=3, ACKN=0, Payload Chunk 2] ------> | (Escribe)
    | <------ ACK [SN=3, ACKN=3, ACK=1] ------------------ |
    |                        ...                           |
    |                                                      |
    | ------- FIN [SN=k, ACKN=0, FIN=1] -----------------> |
    | <------ FIN-ACK [SN=k, ACKN=k, FIN=1, ACK=1] ------- | (Cierra archivo)
    |                                                      |
 [Cierra socket]                               [Entra en TIME_WAIT (10s)]
                                               (Reenvía FIN-ACK si llega
                                                  un FIN retransmitido)
```

1. **Fase de Negociación:**
   - El cliente envía un paquete con bandera `SYN=1`, conteniendo en el payload el `MessageSynUpload` con el tamaño y nombre del archivo destino.
   - El servidor recibe el paquete, extrae los parámetros y ejecuta las validaciones. Si el tamaño es mayor a 15 MiB o si el archivo ya existe en su directorio de almacenamiento, responde con `SYN=1, ACK=1` indicando el código de error (`ERR`) correspondiente y no inicia la transferencia.
   - Si no hay error, el servidor responde con `SYN=1, ACK=1, ERR=0`.
2. **Fase de Transferencia (Stop & Wait):**
   - El cliente lee secuencialmente el archivo en bloques de hasta 1447 bytes.
   - Para cada bloque, genera un paquete con su número de secuencia correspondiente, lo envía y se queda a la espera de recibir el ACK correspondiente.
   - El receptor valida que el número de secuencia recibido coincida exactamente con el número de secuencia que **espera recibir** . Si coincide, escribe los datos en disco y despacha un paquete de confirmación con `ACK=1` y `ACKN = SN_recibido`.
   - Si el número de secuencia recibido **no es el esperado**, el receptor lo descarta y reenvía su último ACK generado para desbloquear al emisor.
3. **Fase de Cierre:**
   - Una vez enviado y confirmada la recepción de todo el contenido del archivo, el cliente envía un paquete con bandera `FIN=1`.
   - El servidor recibe el `FIN`, confirma con `FIN=1, ACK=1` y cierra el archivo en disco.
   - El servidor ingresa en un estado de guardia `TIME_WAIT` durante 10 segundos. Si en ese lapso recibe una retransmisión del paquete `FIN` (lo cual ocurriría si su `FIN-ACK` se perdió en la red), vuelve a transmitir el `FIN-ACK` de inmediato para permitir que el cliente cierre correctamente. Si en ese lapso no recibe nada, asume que el cliente recibió correctamente el `FIN-ACK` y finaliza la ejecución de ese hilo.

##### Error en la Fase de Negociación y FIN implícito

Si durante la fase de negociación el Cliente recibe un paquete con `ERR > 0` ocurre un *FIN implícito* ya que no será posible realizar ninguna transferencia. Por otra parte, el Servidor, luego de enviar ese paquete de *FIN implícito* (`SYN=1, ACK=1, ERR>0`) entra en estado `TIME_WAIT`. En caso de recibirse cualquier paquete por parte de ese Cliente, reenvía el paquete de *FIN implícito* (`SYN=1, ACK=1, ERR>0`). Si en el lapso del `TIME_WAIT` no recibe nada, asume que el cliente recibió e interpretó correctamente el *FIN implícito* y finaliza la ejecución de ese hilo.

#### 3.3.2. Operación DOWNLOAD con SAW

En la descarga, los roles de emisor y receptor de datos se invierten durante la comunicación. El Cliente es el Emisor durante la Fase de Negociación, solicitando el archivo, y durante la Fase de Transferencia es Receptor, recibiendo los datos.

```
CLIENTE (Emisor)                                  SERVIDOR (Receptor)
================                                  ===================
    |                                                      |
    | -- SYN [SN=1, ACKN=0, SYN=1, MessageSynDownload] --> | (Valida 
    |                                                      |  existencia)
    | <-- SYN-ACK [SN=1, ACKN=1, SYN=1, ACK=1, ERR=0] ---- |
    |                                                      |
    | ----- READY ACK [SN=2, ACKN=1, ACK=1] -------------> | (Confirmación)
    |                                                      |
 [Crea archivo]                                      [Inicia envío]
   (Receptor)                                          (Emisor)
    |                                                      |
    | <------ DATA [SN=2, ACKN=0, Payload Chunk 1] ------- | 
    | ------- ACK [SN=3, ACKN=2, ACK=1] -----------------> |
    |                                                      |
    | <------ DATA [SN=3, ACKN=0, Payload Chunk 2] ------- | 
    | ------- ACK [SN=4, ACKN=3, ACK=1] -----------------> |
    |                        ...                           |
    |                                                      |
    | <------ FIN [SN=k, ACKN=0, FIN=1] ------------------ |
    | ------- FIN-ACK [SN=k+1, ACKN=k, FIN=1, ACK=1] ----> |
    |                                                      |
 [Entra en TIME_WAIT (10s)]                          [Cierra hilo]
 (Reenvía FIN-ACK si llega
 un FIN retransmitido)
```

1. **Fase de Negociación y Handshake de 3 Vías:**
   - El cliente envía `SYN=1` con `MessageSynDownload` indicando el nombre del archivo requerido.
   - El servidor valida la existencia del archivo. Si el archivo no existe, responde con `SYN=1, ACK=1, ERR=4` y finaliza.
   - Si existe, el servidor envía `SYN=1, ACK=1, ERR=0`.
   - Dado que el servidor comenzaría a transmitir inmediatamente después, para evitar que sus paquetes de datos lleguen antes de que el cliente esté preparado para recibirlos (mientras está esperando `SYN-ACK`), el cliente despacha un **READY ACK** (Un paquete con `ACK=1` y `ACKN` igual al `SN` del paquete `SYN-ACK` que le envió el servidor). El servidor aguarda este READY ACK antes de comenzar a enviar los datos.
2. **Fase de Transferencia:**
   - La transferencia es idéntica a la descrita en *3.3.1. Operación UPLOAD con SAW*, con la única salvedad que, quien envía los datos es el Servidor y quien los recibe es el Cliente.
3. **Fase de Cierre:**
   - El servidor envía el paquete `FIN`.
   - El cliente responde con `FIN-ACK`, cierra su archivo local y entra en el estado `TIME_WAIT` por 10 segundos para cubrir la eventual pérdida del `FIN-ACK`.

##### Error en la Fase de Negociación y FIN implícito

Si durante la fase de negociación el Cliente recibe un paquete con `ERR > 0` ocurre un *FIN implícito* ya que no será posible realizar ninguna transferencia. A diferencia del caso descrito en *3.3.1. Operación UPLOAD con SAW*, el Cliente deberá responder con un `ACK`. El Servidor queda esperando recibir ese paquete READY ACK para finalizar la ejecución de ese hilo. Si recibiese cualquier otro paquete, reenviará el paquete `SYN-ACK` que informa el error. En caso de no recibirse ningún paquete durante un tiempo, se da por finalizada la comunicación.

#### 3.3.3. Operación UPLOAD con SACK

Las fases son las mismas que en SAW (negociación, transferencia y cierre). La diferencia está en la fase de transferencia: el Emisor puede tener hasta **16 paquetes en vuelo** sin esperar confirmación, y el Receptor acepta y guarda los paquetes que llegan fuera de orden en lugar de descartarlos.

En el siguiente diagrama se pierde el paquete 2; los tres ACK duplicados que generan los paquetes 3, 4 y 5 disparan su retransmisión antes de que expire el temporizador (*fast retransmit*):

```
CLIENTE (Emisor)                                  SERVIDOR (Receptor)
================                                  ===================
    |                                                      |
    | --- SYN [SN=0, ACKN=0, SYN=1, MessageSynUpload] ---> | (Valida tamaño
    |                                                      |  y existencia)
    | <-- SYN-ACK [SN=0, ACKN=0, SYN=1, ACK=1, ERR=0] ---- |
    |                                                      |
 [Inicia envío]                                     [Crea archivo]
 (ventana de 16)                                           |
    | ------- DATA [SN=1, ACKN=0, Chunk 1] --------------> | (Escribe 1)
    | ------- DATA [SN=2, ACKN=0, Chunk 2] ---X (perdido)  |
    | ------- DATA [SN=3, ACKN=0, Chunk 3] --------------> | (Guarda 3)
    | ------- DATA [SN=4, ACKN=0, Chunk 4] --------------> | (Guarda 4)
    | ------- DATA [SN=5, ACKN=0, Chunk 5] --------------> | (Guarda 5)
    |                                                      |
    | <------ ACK [SN=0, ACKN=1, SACK=[]] ---------------- |
    | <------ ACK [SN=0, ACKN=1, SACK=[3-3]] ------------- | (duplicado 1)
    | <------ ACK [SN=0, ACKN=1, SACK=[3-4]] ------------- | (duplicado 2)
    | <------ ACK [SN=0, ACKN=1, SACK=[3-5]] ------------- | (duplicado 3)
    |                                                      |
 [Fast retransmit]                                         |
    | ------- DATA [SN=2, ACKN=0, Chunk 2] --------------> | (Escribe 2 a 5)
    | <------ ACK [SN=0, ACKN=5, SACK=[]] ---------------- |
    |                        ...                           |
    |                                                      |
    | ------- FIN [SN=k, ACKN=0, FIN=1] -----------------> | (Verifica que
    | <------ FIN-ACK [SN=0, ACKN=k, FIN=1, ACK=1] ------- |  esté completo)
    |                                                      |
 [Cierra socket]                               [Entra en TIME_WAIT (10s)]
                                               (Reenvía FIN-ACK si llega
                                                  un FIN retransmitido)
```

1. **Fase de Negociación:**
   - El cliente envía `SYN=1` con el `MessageSynUpload`. El servidor realiza las mismas validaciones que en SAW y responde `SYN=1, ACK=1` con el código de error correspondiente (`ERR=0` si no hay error).
   - El `SYN` se retransmite con *backoff* exponencial (1, 2, 4, 8 y 16 segundos) hasta un máximo de 5 intentos. Si el `SYN-ACK` se pierde y el cliente repite el `SYN`, el servidor reenvía el mismo `SYN-ACK`.
   - Los paquetes de datos se numeran a partir de $SN_{SYN} + 1$, por lo que el primer paquete de datos tiene `SN=1`.
2. **Fase de Transferencia (SACK):** se describe en detalle en *3.4. Mecanismos de Confiabilidad*.
   - El Emisor envía paquetes mientras haya lugar en la ventana, sin esperar confirmación de cada uno.
   - Por cada paquete recibido (en orden, fuera de orden o duplicado), el Receptor responde con un ACK acumulativo que incluye los bloques SACK de lo que tiene guardado fuera de orden.
   - Con cada ACK nuevo, la ventana del Emisor se desliza hacia adelante y se pueden enviar paquetes nuevos.
3. **Fase de Cierre:**
   - Una vez confirmados todos los paquetes de datos, el cliente envía `FIN=1` con el número de secuencia siguiente al último paquete de datos.
   - El servidor sólo acepta el `FIN` si su número de secuencia es el próximo que espera recibir y si ya escribió en disco exactamente la cantidad de bytes anunciada en el `MessageSynUpload`, sin paquetes pendientes en el buffer. Si falta algo, responde con su ACK/SACK actual para que el cliente retransmita lo que falta.
   - Si el archivo está completo, responde `FIN=1, ACK=1`, cierra el archivo y entra en `TIME_WAIT` durante 10 segundos, igual que en SAW.

##### Error en la Fase de Negociación

Si el servidor detecta un error, envía el `SYN-ACK` con `ERR > 0` y finaliza el hilo de esa conexión sin crear el archivo. Al recibirlo, el cliente informa el error y finaliza (*FIN implícito*).

#### 3.3.4. Operación DOWNLOAD con SACK

Igual que en SAW, los roles se invierten: durante la transferencia el Servidor es el Emisor de datos (con la ventana de 16 paquetes) y el Cliente es el Receptor (con el buffer de fuera de orden).

```
CLIENTE (Emisor)                                  SERVIDOR (Receptor)
================                                  ===================
    |                                                      |
    | -- SYN [SN=0, ACKN=0, SYN=1, MessageSynDownload] --> | (Valida
    |                                                      |  existencia)
    | <-- SYN-ACK [SN=0, ACKN=0, SYN=1, ACK=1, ERR=0, ---- |
    |              MessageSynAckDownload]                  |
    |                                                      |
 [Crea archivo]                                            |
    |                                                      |
    | ----- READY ACK [SN=0, ACKN=0, ACK=1, SACK=[]] ----> | (Confirmación)
    |                                                      |
   (Receptor)                                       [Inicia envío]
    |                                               (ventana de 16)
    | <------ DATA [SN=1, ACKN=0, Chunk 1] --------------- |
    | <------ DATA [SN=2, ACKN=0, Chunk 2] --------------- |
    | ------- ACK [SN=0, ACKN=1, SACK=[]] ---------------> |
    | ------- ACK [SN=0, ACKN=2, SACK=[]] ---------------> |
    |                        ...                           |
    |                                                      |
    | <------ FIN [SN=k, ACKN=0, FIN=1] ------------------ |
    | ------- FIN-ACK [SN=0, ACKN=k, FIN=1, ACK=1] ------> |
    |                                                      |
 [Entra en TIME_WAIT (3s)]                           [Cierra hilo]
 (Reenvía FIN-ACK si llega
 un FIN retransmitido)
```

1. **Fase de Negociación y Handshake de 3 Vías:**
   - El cliente envía `SYN=1` con el `MessageSynDownload`. El servidor valida la existencia del archivo y responde `SYN=1, ACK=1`. A diferencia de SAW, el `SYN-ACK` incluye el `MessageSynAckDownload` con el tamaño del archivo, que el cliente usa para saber cuándo recibió el archivo completo.
   - Igual que en SAW, el servidor no envía datos hasta recibir el **READY ACK**. En SACK, el READY ACK es el primer ACK acumulativo del Receptor: como todavía no recibió ningún dato, su `ACKN` es el número anterior al primero que espera, es decir, el `SN` del `SYN-ACK` (0), con la lista SACK vacía.
   - El servidor retransmite el `SYN-ACK` con *backoff* exponencial mientras no llegue el READY ACK. Si el READY ACK se pierde, el cliente recibe un `SYN-ACK` repetido y vuelve a enviar su ACK actual.
2. **Fase de Transferencia:** idéntica a la de *3.3.3. Operación UPLOAD con SACK*, con el Servidor como Emisor y el Cliente como Receptor.
3. **Fase de Cierre:**
   - Una vez confirmados todos los datos, el servidor envía `FIN=1` y lo retransmite hasta recibir el `FIN-ACK`.
   - El cliente acepta el `FIN` sólo si recibió exactamente la cantidad de bytes anunciada en el `MessageSynAckDownload`. Responde `FIN-ACK`, cierra el archivo y entra en `TIME_WAIT` durante 3 segundos.

##### Error en la Fase de Negociación

Si el archivo no existe, el servidor responde el `SYN-ACK` con `ERR=4` y finaliza el hilo. A diferencia de SAW, el cliente no envía un `ACK` de respuesta: informa el error y finaliza sin crear el archivo local.

---

### 3.4. Mecanismos de Confiabilidad

#### Control de Secuencialidad en SAW

El protocolo asigna números de secuencia enteros de 8 bits. Cada paquete enviado incrementa su número de secuencia en 1 módulo 256 (`(sn + 1) % 256`). Por lo tanto, el Receptor es capaz de inferir el número de secuencia del próximo paquete. Todo paquete cuyo número de secuencia difiera del esperado es clasificado como fuera de orden o duplicado; en tal caso, el Receptor ignora los datos recibidos y reenvía inmediatamente el último paquete de confirmación transmitido.

#### Límite de Reintentos y Limpieza de Basura

Los envíos de paquetes que requieren confirmación se limita a **5 intentos consecutivos** de retransmisiones. Si se alcanza el quinto timeout sin respuesta, se asume la caída definitiva del enlace. En ese escenario, tanto el cliente como el servidor eliminan del disco el archivo parcialmente escrito, protegiendo la integridad del sistema de archivos.

#### Ventana Deslizante en SACK

El Emisor mantiene una ventana de **16 paquetes** (`SACK_WINDOW_SIZE`) que comienza en `base`, el paquete más antiguo sin confirmar. Mientras el siguiente número de secuencia a enviar caiga dentro de `[base, base + 15]`, envía un paquete nuevo y lo guarda en un buffer de paquetes no confirmados, por si hay que retransmitirlo.

El tamaño de la ventana cumple la condición de *Selective Repeat*: debe ser como mucho la mitad del espacio de números de secuencia ($16 \le 256 / 2$). De lo contrario, después de que la numeración vuelve a 0, el Receptor no podría distinguir un paquete nuevo de la retransmisión de uno viejo con el mismo número.

Todas las comparaciones de números de secuencia usan aritmética circular: la distancia de `a` a `b` es $(a - b) \bmod 256$, y un número `s` pertenece a la ventana que empieza en `base` si $(s - base) \bmod 256 < 16$.

#### Receptor SACK: Buffer de Paquetes Fuera de Orden

El Receptor mantiene `rcv_nxt`, el próximo número de secuencia que espera, y un buffer de paquetes recibidos fuera de orden. Ante cada paquete de datos:

1. **Es el esperado (`SN = rcv_nxt`):** escribe los datos en disco y avanza `rcv_nxt`. Luego escribe en orden los paquetes del buffer que quedaron contiguos, avanzando `rcv_nxt` por cada uno.
2. **Está dentro de la ventana pero no es el esperado:** hay un hueco antes de él. Lo guarda en el buffer (si no lo tenía) sin escribirlo.
3. **Es anterior a `rcv_nxt` (duplicado) o está fuera de la ventana:** lo descarta.

En los tres casos responde con un ACK: `ACKN = rcv_nxt - 1` (el último recibido en orden) y la lista de bloques SACK del buffer. Así el archivo se escribe siempre en orden y cada byte una sola vez, aunque los paquetes lleguen desordenados o duplicados.

#### Emisor SACK: Procesamiento de ACKs

Ante cada ACK recibido, el Emisor:

1. Marca como confirmados por SACK los paquetes de su ventana incluidos en los bloques. Esos paquetes no se retransmiten, pero siguen en el buffer hasta que el ACK acumulativo los alcance.
2. **Si `ACKN` es nuevo** (pertenece a la ventana): libera todos los paquetes desde `base` hasta `ACKN`, mueve `base` a $ACKN + 1$ y reinicia el temporizador.
3. **Si `ACKN` es igual al anterior** (ACK duplicado): el Receptor recibió algo posterior a un hueco. Se cuentan los ACK duplicados para la recuperación rápida.
4. **Si `ACKN` está fuera de la ventana:** es un ACK viejo y se ignora.

#### Recuperación Rápida (*Fast Retransmit* y *Fast Recovery*)

Para no esperar a que expire el temporizador ante cada pérdida, se usan los ACK duplicados como indicio de pérdida:

1. **Fast Retransmit:** al recibir el tercer ACK duplicado, el Emisor retransmite `base`, que es el paquete que bloquea el avance de la ventana. Registra como *punto de recuperación* el último paquete enviado y entra en **Fast Recovery**. Mientras `base` no avance, retransmite `base` de nuevo cada 3 ACK duplicados adicionales.
2. **Fast Recovery:** cada vez que llega un ACK nuevo durante la recuperación, se buscan los huecos que quedan en la ventana y se retransmiten. Un paquete se considera **hueco** si no fue confirmado (ni por ACK acumulativo ni por SACK). Cada hueco se retransmite como máximo una vez por recuperación.
3. La recuperación termina cuando `base` supera el punto de recuperación, es decir, cuando se confirmó todo lo que estaba en vuelo al detectarse la pérdida.

#### Timeout y Límite de Reintentos en SACK

Si expira el temporizador sin recibir un ACK nuevo, el Emisor sale de la recuperación rápida, descarta la cuenta de ACK duplicados, retransmite `base` y duplica el timeout. La transferencia se aborta después de **20 timeouts consecutivos** sin ningún ACK nuevo; cualquier ACK nuevo reinicia la cuenta.

Las fases de negociación y cierre (`SYN` y `FIN`) usan, como en SAW, un máximo de **5 intentos** con *backoff* exponencial a partir de 1 segundo.

Por su parte, el Receptor da la conexión por perdida si no recibe ningún paquete durante **10 segundos** (timeout de inactividad). En todos los casos de falla, el Receptor elimina el archivo parcial.

### 3.5. Temporización Adaptativa

#### Estimación Dinámica del RTT
En lugar de utilizar un temporizador estático que resultaría ineficiente ante redes rápidas o generaría retransmisiones prematuras (espurias) ante enlaces con retardo, se implementó el algoritmo de estimación adaptativa de RTT (basado en *Computer Networking : A Top-Down Approach, James Kurose and Keith Ross*):

$$\text{RTT}_{\text{sample}} = t_{\text{llegada ACK}} - t_{\text{envío paquete}}$$

$$\text{EstimatedRTT} = (1 - \alpha) \cdot \text{EstimatedRTT} + \alpha \cdot \text{RTT}_{\text{sample}} \quad (\text{con } \alpha = 0.125)$$

$$\text{DevRTT} = (1 - \beta) \cdot \text{DevRTT} + \beta \cdot |\text{RTT}_{\text{sample}} - \text{EstimatedRTT}| \quad (\text{con } \beta = 0.25)$$

$$\text{Timeout (RTO)} = \text{EstimatedRTT} + 4 \cdot \text{DevRTT}$$

Este cálculo actualiza continuamente el timeout en cada recepción exitosa de ACK no ambiguo, adaptándose a la fluctuación natural de la red.

#### Backoff Exponencial ante Pérdidas
Cuando expira el temporizador antes de recibir el ACK esperado, se duplica el valor del timeout actual hasta un techo seguro de 10 segundos:

$$\text{Timeout}_{\text{nuevo}} = \min(10.0, \, \text{Timeout}_{\text{actual}} \times 2)$$

Este mecanismo evita saturar un enlace que podría estar atravesando un episodio momentáneo de congestión severa.

#### Temporización en SACK

SACK usa las mismas fórmulas de `EstimatedRTT`, `DevRTT` y RTO, con dos diferencias:

- **Un único temporizador para toda la ventana:** no hay un temporizador por paquete. Se reinicia con cada ACK nuevo (o al vencer), y al expirar se retransmite sólo `base`.
- **Techo del RTO de 1 segundo:** tanto el cálculo como el *backoff* se limitan a 1 segundo ($\text{RTO} = \min(\text{EstimatedRTT} + 4 \cdot \text{DevRTT}, \, 1)$ y $\text{RTO}_{\text{nuevo}} = \min(2 \cdot \text{RTO}, \, 1)$). El techo es bastante menor que el timeout de inactividad del otro extremo (10 segundos), así que las retransmisiones siguen llegando aunque haya varias pérdidas seguidas.

El RTO inicial de la transferencia es el timeout con el que se completó el `SYN` (1 segundo si el `SYN` se confirmó en el primer intento).

La muestra de RTT se toma como el tiempo transcurrido desde el último reinicio del temporizador hasta la llegada del ACK nuevo. Siguiendo el algoritmo de Karn, se descarta la muestra si hubo una retransmisión en ese intervalo, porque no se puede saber a qué envío corresponde el ACK.
---

## 4. Pruebas

## 5. Preguntas 

#### 1- Describa la arquitectura Cliente-Servidor
La arquitectura Cliente-Servidor es un modelo de diseño de software distribuido donde las tareas y la carga de trabajo se dividen entre los proveedores de un recurso o servicio, llamados servidores, y los demandantes de dicho servicio, llamados clientes.

    Cliente: Es el proceso (generalmente iniciado por un usuario final) que solicita recursos o la ejecución de una tarea. No comparte sus recursos con otros nodos y requiere iniciar  la comunicación conectándose al servidor.

    Servidor: Es un proceso centralizado pasivo que se ejecuta continuamente (en modo escucha ), esperando solicitudes de los clientes. Procesa las peticiones entrantes, ejecuta la lógica de negocio o acceso a datos y devuelve una respuesta.

Características principales:

    Centralización: La gestión de recursos, datos y seguridad suele centralizarse en el servidor.

    Desacoplamiento e Independencia: Clientes y servidores son procesos independientes que interactúan únicamente mediante una interfaz definida (protocolo), permitiendo cambiar la implementación de uno sin afectar al otro.

    Asimetría de la comunicación: La interacción es iniciada por el cliente; el servidor no inicia conexiones hacia el cliente de forma espontánea.

#### 2- ¿Cuál es la función de un protocolo de capa de aplicación?
El protocolo de la capa de aplicación define las reglas, estructuras de mensajes y secuencias de interacción que utilizan dos aplicaciones de software para comunicarse e intercambiar información a través de una red.

Sus funciones principales son:

    Sintaxis de los mensajes: Define la estructura externa y el formato de los datos transferidos (por ejemplo, cómo se separan los encabezados del cuerpo, campos de texto o binarios).

    Semántica de los mensajes: Define el significado exacto de cada campo, comando o código de estado enviado (ej. códigos de error, tipo de operación como UPLOAD o DOWNLOAD).

    Reglas de sincronización/interacción: Establece la secuencia de pasos o máquina de estados requerida para realizar una tarea (cuándo un extremo debe enviar un mensaje y cómo debe responder el otro).

    Representación de datos: Asegura que la información enviada por un sistema sea comprensible para el otro, independientemente de la arquitectura subyacente 

#### 3- Detalle el protocolo de aplicación desarrollado en este trabajo.
El protocolo de aplicación desarrollado permite transferir archivos de forma confiable sobre UDP, con dos operaciones: UPLOAD (cargar archivos al servidor) y DOWNLOAD (descargar archivos del servidor). Siguiendo la definición de protocolo de capa de aplicación de la pregunta 2, se detallan sus tipos de mensajes, su sintaxis, su semántica y sus reglas de interacción.

**a) Tipos de mensajes**

- **Pedido de UPLOAD:** el cliente solicita subir un archivo al servidor.
- **Pedido de DOWNLOAD:** el cliente solicita descargar un archivo del servidor.
- **Respuesta al pedido:** el servidor acepta el pedido o lo rechaza indicando el motivo.
- **Datos:** fragmentos del contenido del archivo.
- **Fin de transferencia:** indica que se envió el archivo completo, y su confirmación.

**b) Sintaxis**

Todos los mensajes comparten un encabezado de 3 bytes (número de secuencia, número de ACK y un byte de flags), seguido de un payload cuyo formato depende del tipo de mensaje (ver *3.2*):

- **Pedido de UPLOAD** (`MessageSynUpload`): tamaño del archivo (3 bytes), longitud del nombre (1 byte) y nombre del archivo en UTF-8.
- **Pedido de DOWNLOAD** (`MessageSynDownload`): longitud del nombre (1 byte) y nombre del archivo en UTF-8.
- **Respuesta a un pedido de DOWNLOAD con SACK** (`MessageSynAckDownload`): tamaño del archivo (3 bytes).
- **Datos:** un fragmento del archivo de hasta 1447 bytes.
- **Resto de las respuestas a pedidos, fin de transferencia y su confirmación:** sin payload.

**c) Semántica**

- **Bit `OP`:** operación solicitada (`1` = UPLOAD, `0` = DOWNLOAD).
- **Bit `TY`:** mecanismo de transferencia confiable elegido por el cliente (`0` = Stop and Wait, `1` = SACK).
- **Bit `SYN`:** identifica el pedido y su respuesta.
- **Bit `FIN`:** indica el fin del archivo.
- **Bits de error:** resultado del pedido o de la transferencia: `0` sin error, `1` nombre de archivo inválido, `2` el archivo ya existe, `3` el archivo supera los 15 MiB, `4` el archivo no existe y `7` error de lectura o escritura en disco.

Los números de secuencia y de ACK y el bit `ACK` no tienen significado para la aplicación: los usa el mecanismo de transferencia confiable para garantizar la entrega de los mensajes (ver *3.4* y *3.5*).

**d) Reglas de interacción**

1. El cliente siempre inicia la comunicación enviando un pedido de UPLOAD o de DOWNLOAD. El servidor nunca inicia una comunicación.
2. El servidor valida el pedido: en UPLOAD, que el archivo no exista y no supere el tamaño máximo; en DOWNLOAD, que el archivo exista. Si el pedido no es válido, responde con el código de error correspondiente y la operación finaliza sin transferir datos.
3. Si el pedido es válido, quien tiene el archivo (el cliente en UPLOAD, el servidor en DOWNLOAD) envía su contenido en fragmentos, que el receptor escribe en disco en orden.
4. Una vez enviado todo el contenido, el emisor envía el fin de transferencia. El receptor sólo lo acepta si recibió el archivo completo y, en ese caso, lo confirma.
5. Si la transferencia no puede completarse, el receptor elimina el archivo parcial, de modo que nunca queda en disco un archivo incompleto.

El detalle de cada intercambio para cada operación y mecanismo se describe en *3.3*.

####  4- Lacapadetransporte del stack TCP/IP ofrece dos protocolos: TCP y UDP. ¿Qué servicios proveen dichos protocolos? ¿Cuáles son sus características? ¿Cuándo es apropiado utilizar cada uno?
La capa de transporte del stack TCP/IP abstrae la red física ofreciendo comunicación proceso a proceso mediante el uso de puertos. Los dos protocolos principales presentan características contrastantes:
TCP (Transmission Control Protocol)

    Servicios que provee:

        Orientado a conexión: Requiere un establecimiento formal de enlace (three-way handshake ) antes del intercambio de datos y un cierre ordenado.

        Entrega confiable: Garantiza que todos los bytes lleguen a destino sin errores, sin duplicados y en el orden exacto en que fueron enviados.

        Control de flujo: Evita que el emisor sature al receptor ajustando la velocidad de envío según el buffer disponible (Ventana deslizante).

        Control de congestión: Modula la tasa de transferencia en función de la capacidad de la red global para prevenir el colapso por congestión.

    Características:

        Basado en flujo de bytes (byte-stream), no preserva límites de mensajes.

        Mayor sobrecarga (overhead) debido a encabezados de mayor tamaño (20 bytes o más) y mantenimiento de estado de conexión.

    Cuándo utilizarlo:

        Cuando la integridad y exactitud de los datos es crítica y no se puede tolerar ninguna pérdida de información.

        Ejemplos: Web (HTTP/HTTPS), transferencia de archivos (FTP), correo electrónico (SMTP), terminales remotas (SSH).

UDP (User Datagram Protocol)

    Servicios que provee:

        Servicio básico sin conexión: No realiza handshake ni mantiene estado de conexión en los extremos.

        Multiplexación/Desmultiplexación por puertos: Asigna mensajes a aplicaciones específicas basándose en sockets/puertos.

        Detección básica de errores: Verificación opcional mediante la suma de comprobación (checksum).

    Características:

        Orientado a datagramas: Preserva los límites explícitos de los mensajes enviándolos como unidades independientes.
        No confiable: No garantiza la entrega, el orden de llegada ni previene la duplicación de paquetes.

        Mínima sobrecarga: Encabezados pequeños (8 bytes) y nula latencia en el establecimiento de conexión.

        Otorga control total a la capa de aplicación sobre el envío de paquetes.

    Cuándo utilizarlo:

        En aplicaciones en tiempo real donde prima la baja latencia por sobre la retransmisión de datos perdidos.

        Cuando se prefiere implementar un protocolo a medida con mecanismos propios de confiabilidad y control de flujo en la capa de aplicación .

        Para mensajes breves tipo consulta-respuesta que caben en un único paquete.

        Ejemplos: Streaming de video/audio en vivo, videojuegos multijugador, consultas DNS, VoIP.

#### 5- Justifique si el protocolo desarrollado cuenta con mecanismos de control de congestión, en caso de tenerlos, descríbalos.
El protocolo desarrollado no cuenta con un algoritmo de control de congestión ni de control de flujo. Sí se provee un mecanismo de ventana deslizante, pero que es propio de SACK y no es una estrategia de control de flujo ni de congestión. La ventana tiene un tamaño fijo de 16 paquetes, que no se ajusta según el estado de la red (no se reduce ante pérdidas) o según la capacidad del receptor.

#### 6- ¿Cuál de los dos protocolos desarrollados envía archivos en la menor cantidad de tiempo? ¿Es siempre el mismo?
En todas las pruebas realizadas, SACK envió los archivos en menos tiempo que Stop and Wait. Esto se debe a que SAW tiene un único paquete en vuelo, por lo que envía como máximo un paquete por RTT, mientras que SACK puede tener hasta 16 paquetes en vuelo y, ante una pérdida, sigue enviando el resto de la ventana.
Sin embargo para archivos muy pequeños,que entran en uno o pocos paquetes, ambos protocolos tardan prácticamente lo mismo.

---        

## 6. Dificultades Encontradas

A lo largo del diseño, implementación y prueba del sistema se sortearon diversas dificultades técnicas relevantes:

1. **Ausencia de abstracción de conexiones en la API de Sockets UDP:**
   - La interfaz de sockets del sistema operativo no provee una función `accept()` para UDP que devuelva un socket conectado independiente por cliente. Todos los datagramas entran por el mismo puerto asignado con `bind()`.
   - **Solución implementada:** Se diseñó una capa de desmultiplexación en el servidor que inspecciona la tupla `(IP, puerto)` de cada datagrama recibido y despacha el paquete a una cola privada asociada al hilo de trabajo del cliente, logrando concurrencia limpia y aislada.
2. **Pérdida del último paquete de confirmación (`FIN-ACK`):**
   - En el cierre de la conexión, si el receptor envía el `FIN-ACK` final y cierra inmediatamente su socket, la pérdida de ese último datagrama en la red dejaría al emisor retransmitiendo su paquete `FIN` sin obtener respuesta alguna, finalizando la ejecución con un falso error de conexión por timeout a pesar de que el archivo se transfirió íntegro.
   - **Solución implementada:** Se incorporó el estado de espera `TIME_WAIT` (con un temporizador de 10 segundos) en el receptor. Durante este periodo, el receptor mantiene la escucha: si recibe nuevamente un paquete `FIN`, reenvía el `FIN-ACK` y resetea la espera, asegurando un cierre ordenado para ambos extremos.
3. **Manejo de paquetes desordenados y duplicados en Stop and Wait:**
   - Si un ACK sufre un retardo transitorio superior al timeout, el emisor retransmite el paquete de datos original. Cuando el receptor recibe este duplicado, debe evitar escribir dos veces el mismo bloque en el archivo.
   - **Solución implementada:** El receptor mantiene un control estricto de secuencia. Al detectar un paquete duplicado o fuera de orden, descarta el payload y reenvía inmediatamente el último ACK generado, lo que permite que el emisor destrabe su ciclo sin alterar los datos persistidos.
4. **Sintonización de Temporizadores bajo Enlaces con Retardo y Pérdida:**
   - Fijar un timeout estático provocaba o bien transferencias extremadamente lentas ante pérdidas (si era muy alto) o bien retransmisiones espurias masivas que congestionaban el canal (si era menor que el RTT).
   - **Solución implementada:** Se implementó un algoritmo de cálculo adaptativo de RTT sobre las mediciones en tiempo real, acoplado a un backoff exponencial que amortigua las pérdidas sucesivas.
5. **Abstracciones y Simetría:**
   - Las operaciones UPLOAD y DOWNLOAD son operaciones simétricas. En UPLOAD el Cliente es *Emisor* de datos y el Servidor es *Receptor* de datos, y en DOWNLOAD el Cliente es *Receptor* de datos y el Servidor es *Emisor* de datos. Se deseaba que esa simetría se respete en la implementación.
   - **Solución implementada:** Se desarrolló la abstracción `Channel`, que es capaz de enviar y recibir paquetes, además de gestionar los números de secuencias recibidos y enviados, sus incrementos mediante aritmética modular y ser capaz de reeenviar el último mensaje enviado. Se implementaron dos clases concretas `ServerChannel` (un canal hacia el servidor, donde todos los paquetes se envían y reciben a través de un mismo socket) y `ClientChannel` (un canal hacia el cliente, donde los paquetes se envían a través de un socket y se reciben mediante una cola)
   - En SACK la misma idea se llevó a las clases `SackSender` (Emisor) y `SackReceiver` (Receptor), que operan sobre un `Channel` sin saber si son cliente o servidor. En UPLOAD el cliente usa `SackSender` y el servidor `SackReceiver`; en DOWNLOAD se intercambian. De esta forma, la lógica de ventana, SACK y recuperación es la misma en ambas operaciones.

---

## 7. Conclusión

El desarrollo de este trabajo práctico permitió afianzar y aplicar de manera tangible los principios esenciales de las comunicaciones en redes de datos y la programación de sistemas distribuidos:

- Se comprendió a fondo el modelo de servicio que ofrece la capa de transporte: la ausencia de garantías en UDP obligó a diseñar y construir artesanalmente en la capa de aplicación todos los mecanismos que hacen a la confiabilidad (encabezados, sincronización, detección de pérdidas por temporizadores, confirmaciones positivas, numeración de secuencia y control de duplicados).
- La experiencia práctica con la interfaz de sockets demandó la implementación de patrones de concurrencia y desmultiplexación para brindar servicio multicliente.
**COMPLETAR!!! A CHEQUEAR - ESCRITO POR IA**
- Las pruebas empíricas en el entorno virtualizado de Mininet demostraron con claridad los límites teóricos del protocolo **Stop and Wait**: al estar acotado a un único paquete en tránsito a la vez, su rendimiento está directamente limitado por el RTT de la red, resultando en un factor de utilización del canal sumamente bajo que empeora sensiblemente ante pérdidas de paquetes.
- Esta limitación comprueba experimentalmente la necesidad y justificación de los protocolos con ventana deslizante (como SACK o TCP), que logran maximizar la eficiencia de la red transmitiendo ráfagas continuas de datos.
**COMPLETAR!!! A CHEQUEAR - ESCRITO POR IA**


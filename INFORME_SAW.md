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


1. **Byte 0 - Sequence Number (SN):** Entero sin signo de 8 bits (rango 0 a 255). Identifica de manera unívoca la posición relativa **del paquete** en la secuencia. En Stop and Wait, avanza mediante aritmética modular: $SN_{siguiente} = (SN + 1) \pmod{256}$.
2. **Byte 1 - Acknowledgment Number (ACKN):** Entero sin signo de 8 bits (rango 0 a 255). Confirma el número de secuencia exacto **del paquete recibido** que se está reconociendo.
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

#### Información SACK

**COMPLETAR!!!**

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

---

### 3.4. Mecanismos de Confiabilidad

#### Control de Secuencialidad en SAW

El protocolo asigna números de secuencia enteros de 8 bits. Cada paquete enviado incrementa su número de secuencia en 1 módulo 256 (`(sn + 1) % 256`). Por lo tanto, el Receptor es capaz de inferir el número de secuencia del próximo paquete. Todo paquete cuyo número de secuencia difiera del esperado es clasificado como fuera de orden o duplicado; en tal caso, el Receptor ignora los datos recibidos y reenvía inmediatamente el último paquete de confirmación transmitido.

#### Límite de Reintentos y Limpieza de Basura

Los envíos de paquetes que requieren confirmación se limita a **5 intentos consecutivos** de retransmisiones. Si se alcanza el quinto timeout sin respuesta, se asume la caída definitiva del enlace. En ese escenario, tanto el cliente como el servidor eliminan del disco el archivo parcialmente escrito, protegiendo la integridad del sistema de archivos.

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

---

## 5. Preguntas 

1- La arquitectura Cliente-Servidor es un modelo de diseño de software distribuido donde las tareas y la carga de trabajo se dividen entre los proveedores de un recurso o servicio, llamados servidores, y los demandantes de dicho servicio, llamados clientes.

    Cliente: Es el proceso (generalmente iniciado por un usuario final) que solicita recursos o la ejecución de una tarea. No comparte sus recursos con otros nodos y requiere iniciar  la comunicación conectándose al servidor.

    Servidor: Es un proceso centralizado pasivo que se ejecuta continuamente (en modo escucha ), esperando solicitudes de los clientes. Procesa las peticiones entrantes, ejecuta la lógica de negocio o acceso a datos y devuelve una respuesta.

Características principales:

    Centralización: La gestión de recursos, datos y seguridad suele centralizarse en el servidor.

    Desacoplamiento e Independencia: Clientes y servidores son procesos independientes que interactúan únicamente mediante una interfaz definida (protocolo), permitiendo cambiar la implementación de uno sin afectar al otro.

    Asimetría de la comunicación: La interacción es iniciada por el cliente; el servidor no inicia conexiones hacia el cliente de forma espontánea.

2- El protocolo de la capa de aplicación define las reglas, estructuras de mensajes y secuencias de interacción que utilizan dos aplicaciones de software para comunicarse e intercambiar información a través de una red.

Sus funciones principales son:

    Sintaxis de los mensajes: Define la estructura externa y el formato de los datos transferidos (por ejemplo, cómo se separan los encabezados del cuerpo, campos de texto o binarios).

    Semántica de los mensajes: Define el significado exacto de cada campo, comando o código de estado enviado (ej. códigos de error, tipo de operación como UPLOAD o DOWNLOAD).

    Reglas de sincronización/interacción: Establece la secuencia de pasos o máquina de estados requerida para realizar una tarea (cuándo un extremo debe enviar un mensaje y cómo debe responder el otro).

    Representación de datos: Asegura que la información enviada por un sistema sea comprensible para el otro, independientemente de la arquitectura subyacente 
    
4- La capa de transporte del stack TCP/IP abstrae la red física ofreciendo comunicación proceso a proceso mediante el uso de puertos. Los dos protocolos principales presentan características contrastantes:
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

---

## 7. Conclusión

El desarrollo de este trabajo práctico permitió afianzar y aplicar de manera tangible los principios esenciales de las comunicaciones en redes de datos y la programación de sistemas distribuidos:

- Se comprendió a fondo el modelo de servicio que ofrece la capa de transporte: la ausencia de garantías en UDP obligó a diseñar y construir artesanalmente en la capa de aplicación todos los mecanismos que hacen a la confiabilidad (encabezados, sincronización, detección de pérdidas por temporizadores, confirmaciones positivas, numeración de secuencia y control de duplicados).
- La experiencia práctica con la interfaz de sockets demandó la implementación de patrones de concurrencia y desmultiplexación para brindar servicio multicliente.
**COMPLETAR!!! A CHEQUEAR - ESCRITO POR IA**
- Las pruebas empíricas en el entorno virtualizado de Mininet demostraron con claridad los límites teóricos del protocolo **Stop and Wait**: al estar acotado a un único paquete en tránsito a la vez, su rendimiento está directamente limitado por el RTT de la red, resultando en un factor de utilización del canal sumamente bajo que empeora sensiblemente ante pérdidas de paquetes.
- Esta limitación comprueba experimentalmente la necesidad y justificación de los protocolos con ventana deslizante (como SACK o TCP), que logran maximizar la eficiencia de la red transmitiendo ráfagas continuas de datos.
**COMPLETAR!!! A CHEQUEAR - ESCRITO POR IA**


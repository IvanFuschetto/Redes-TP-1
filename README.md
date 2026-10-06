# Redes (TA048) - TP N° 1. File Transfer

Implementación de una aplicación de red de arquitectura cliente-servidor para carga y descarga de archivos binarios, con una implementación de un protocolo RDT sobre UDP

Grupo 2:
 - Ivan Fuschetto - 110632
 - Alexis Torres - 111449
 - Rodrigo Velez - 98256
 - Lautaro Laffont - 108346
 - Matias Etchegoyen - 110923

## Requisitos

1. **Python 3.x** instalado.
2. Librería estándar de sockets de Python.
3. Herramienta **Mininet** para simular condiciones de red.

### Instalación de Dependencias

```bash
pip install flake8
```

## Levanatar Topología

```bash
sudo python3 topologia.py [-hosts HOSTS] [--delay DELAY] [--loss LOSS]
```

Parámetros:

| Parametros  | Descripción                                         |
|-------------|-----------------------------------------------------|
| `--hosts`   | Cantidad de hosts clientes (por defecto: 4).        |
| `--delay`   | Delay de los enlaces (por defecto: 75ms).           |
| `--loss`    | Porcentaje de pérdida de paquetes (por defecto: 5). |

#### Ejemplo de uso
```bash
python3 topologia.py --delay 40ms --loss 5
```

## Ejecucion Servidor

```bash
python3 start-server [-h] [-H ADDR] [-p PORT] [-s DIRPATH] [-v|-q] 
```
Opciones:

| Opción              | Descripción                                   |
|---------------------|-----------------------------------------------|
| `-h`, `--help`      | Muestra el mensaje de ayuda y sale.           |
| `-v`, `--verbose`   | Incrementa la verbosidad de la salida.        |
| `-q`, `--quiet`     | Disminuye la verbosidad de la salida.         |
| `-H`, `--host`      | Dirección IP del servidor.                    |
| `-p`, `--port`      | Puerto del servidor.                          |
| `-s`, `--storage`   | Directorio donde se almacenarán los archivos. |
| `-r`, `--protocol`  | Algoritmo elegido (saw or sack).              |

#### Ejemplo de uso
```bash
python3 start_server.py -H 10.0.0.1 -p 5000 -s /ruta/de/stotage/
```

## Ejecucion Cliente

### Upload
```bash
python3 upload [-h] [-r PROTOCOL] [-H ADDR] [-p PORT] [-s FILEPATH] [-n FILENAME] [-v |-q]
```

Opciones:

| Opción             | Descripción                                  |
|--------------------|----------------------------------------------|
| `-h`, `--help`     | Muestra el mensaje de ayuda y sale.          |
| `-v`, `--verbose`  | Incrementa la verbosidad de la salida.       |
| `-q`, `--quiet`    | Disminuye la verbosidad de la salida.        |
| `-H`, `--host`     | Dirección IP del servidor.                   |
| `-P`, `--port`     | Puerto del servidor.                         |
| `-s`, `--src`      | Ruta del archivo fuente que se desea subir.  |
| `-n`, `--name`     | Nombre del archivo.                          |
| `-r`, `--protocol` | Protocolo elegido (saw or sack)              |



#### Ejemplo de uso
```bash
python3 upload.py -r sack -H 10.0.0.1 -p 5000 -s /ruta/al/archivo.txt -n archivo.txt
```

### Download
```bash
python3 download [-h] [-r PROTOCOL] [-H ADDR] [-p PORT] [-s FILEPATH] [-n FILENAME] [-v |-q]
```

Opciones:

| Opción             | Descripción                                      |
|--------------------|--------------------------------------------------|
| `-h`, `--help`     | Muestra el mensaje de ayuda y sale.              |
| `-v`, `--verbose`  | Incrementa la verbosidad de la salida.           |
| `-q`, `--quiet`    | Disminuye la verbosidad de la salida.            |
| `-H`, `--host`     | Dirección IP del servidor.                       |
| `-p`, `--port`     | Puerto del servidor.                             |
| `-d`, `--dst`      | Ruta de destino del archivo descargado.          |
| `-n`, `--name`     | Nombre del archivo.                              |
| `-r`, `--protocol` | Protocolo elegido (saw or sack)                  |


#### Ejemplo de uso
```bash
python3 download.py -r sack -H 10.0.0.100 -p 5000 -s /ruta/al/archivo.txt -n archivo.txt
```

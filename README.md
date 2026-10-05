# Redes-TP-1

Como levantar la topologia:
sudo python3 topologia.py
xterm server h1 h2 

Levantar el servidor:
python3 start-server.py -H 0.0.0.0 -p 5000 -s storage -v

Hacer un upload (sack):
python3 upload.py -r sack -H 10.0.0.100 -p 5000 -s (nombre del archivo que queres subir) -n (como va a llamar el servidor a lo subido)

Hacer un download (sack):
python3 download.py -r sack -H 10.0.0.100 -p 5000 -n (nombre del archivo que queres descargar) -d (como vas a llamar a lo descargado)
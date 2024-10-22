from scapy.all import *
import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import TCP

# Mostramos todas las interfaces
print(conf.ifaces)

interface = "Software Loopback Interface 1" # Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.

listen_port = 8000  # Elegir el puerto que esta escuchando

print(f"Listening for TCP packets on port {listen_port}...")
filter_str = f"tcp port {listen_port}"

# Escuchar en ese puerto
pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = 60)

pkt_corrupto = pkt_capturado[0][TCP].chksum != len(bytes(pkt_capturado[0][TCP]))
if not(pkt_corrupto):
    ip = IP(dst = pkt_capturado[0][IP].src, src = pkt_capturado[0][IP].dst)
    tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, flags = ['S', 'A'])
    syn_ack_packet = ip/tcp
    f.envio_paquetes_inseguro(syn_ack_packet)
    

interface = "Software Loopback Interface 1" 
listen_port = 8000  
print(f"Listening for TCP packets on port {listen_port}...")
filter_str = f"tcp port {listen_port}"
pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = 60)


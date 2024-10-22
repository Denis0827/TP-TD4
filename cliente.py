import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import * # Correr pip install scapy en la terminal

def calculo_chksum(packet):
    packet[TCP].chksum = None
    longitud_bytes = len(bytes(packet[TCP]))
    packet[TCP].chksum = longitud_bytes
    
def esperar_paquete(listen_port, timeout, mostrar) -> List:
    interface = "Software Loopback Interface 1" 
    print(f"Listening for TCP packets on port {listen_port}...")
    filter_str = f"tcp port {listen_port}"
    if mostrar:
        pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = 3)
    else: 
        pkt_capturado = sniff(iface = interface, filter = filter_str, count = 1, timeout = 3)
    return pkt_capturado

# Elegimos parametros
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 8000
src_port = 5000

# Creamos la parte de IP
ip = IP(dst=dest_ip,src =source_ip)

# Creamos la parte de TCP
tcp = TCP(dport=dest_port, sport =src_port)

# Los combinamos
packet = ip/tcp
calculo_chksum(packet)

# "Enviamos" el paquete
f.envio_paquetes_inseguro(packet)

pkt_capturado = []
cant_retransmisiones = 0
pkt_capturado = esperar_paquete(5000, 3, False)
while(len(pkt_capturado) == 0):
    cant_retransmisiones += 1
    f.envio_paquetes_inseguro(packet)
    pkt_capturado = esperar_paquete(5000, 3, False)
    print("Cantidad de retransmisiones del SYN: " + str(cant_retransmisiones))

ip = IP(dst = pkt_capturado[0][IP].src, src = pkt_capturado[0][IP].dst)
tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, flags = ['A'])
ack_packet = ip/tcp
f.envio_paquetes_inseguro(ack_packet)

    





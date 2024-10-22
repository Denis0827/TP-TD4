from scapy.all import *
import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.layers.inet import IP,TCP

# Mostramos todas las interfaces
# print(conf.ifaces)

def calcular_chksum(packet):
    packet[TCP].chksum = None
    longitud_bytes = len(bytes(packet[TCP]))
    packet[TCP].chksum = longitud_bytes

def esperar_paquete(listen_port, tiempo_timeout, mostrar) -> List:
    interface = "Software Loopback Interface 1" 
    print(f"Listening for TCP packets on port {listen_port}...")
    filter_str = f"tcp port {listen_port}"
    pkt_capturado = []
    if mostrar:
        pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = tiempo_timeout)
    else: 
        pkt_capturado = sniff(iface = interface, filter = filter_str, count = 1, timeout = tiempo_timeout)
    return pkt_capturado

def crear_respuesta(pkt_capturado, nro_seq):
    ip = IP(dst = pkt_capturado[0][IP].src, src = pkt_capturado[0][IP].dst)
    if 'S' in pkt_capturado[0][TCP].flags: 
        tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, seq = nro_seq, 
            ack = pkt_capturado[0][TCP].seq + 1, flags = ['S', 'A'])
    else:
        tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, seq = nro_seq, 
                ack = pkt_capturado[0][TCP].seq + 1, flags = ['A']) 
    packet = ip/tcp
    calcular_chksum(packet)
    return packet


def enviar_respuesta(nro_secuencia):
    pkt_capturado = esperar_paquete(8000, 60, False)
    while True:
        if len(pkt_capturado) != 0:
            pkt_corrupto = pkt_capturado[0][TCP].chksum != len(bytes(pkt_capturado[0][TCP]))
            if not(pkt_corrupto):
                packet = crear_respuesta(pkt_capturado, nro_secuencia)
                f.envio_paquetes_inseguro(packet)
                print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")
                break
    
nro_secuencia = random.randint(1, 10000)
pkt_capturado = esperar_paquete(8000, 60, False)
while True:
    if len(pkt_capturado) != 0:
        pkt_corrupto = pkt_capturado[0][TCP].chksum != len(bytes(pkt_capturado[0][TCP]))
        if not(pkt_corrupto):
            packet = crear_respuesta(pkt_capturado, nro_secuencia)
            f.envio_paquetes_inseguro(packet)
            print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")
            break

while True:
    pkt_capturado = esperar_paquete(8000, 60, False)
    if len(pkt_capturado) != 0:
        packet = crear_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
        f.envio_paquetes_inseguro(packet)
        print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")


import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import * # Correr pip install scapy en la terminal
from scapy.layers.inet import IP,TCP
import random

def calcular_checksum(packet):
    packet[TCP].chksum = None
    suma_bytes = sum(bytes(packet[TCP]))
    packet[TCP].chksum = suma_bytes

def verificar_checksum(packet) -> bool:
    checksum = packet[TCP].chksum
    packet[TCP].chksum = None
    suma_bytes = sum(bytes(packet[TCP]))
    packet[TCP].chksum = checksum
    return suma_bytes == checksum  

def crear_paquete(puerto_origen, puerto_destino, nro_seq, nro_ack, flags_a_enviar) -> packet:
    source_ip = '127.0.0.1'
    dest_ip = '127.0.0.1'
    src_port = puerto_origen
    dest_port = puerto_destino

    # Creamos la parte de IP
    ip = IP(dst = dest_ip, src = source_ip)

    # Creamos la parte de TCP
    tcp = TCP(dport = dest_port, sport = src_port, seq = nro_seq, ack = nro_ack, flags = flags_a_enviar)

    # Los combinamos
    packet = ip/tcp
    calcular_checksum(packet)
    
    return packet


def esperar_ack(listen_port, tiempo_timeout, mostrar) -> List:
    interface = "Software Loopback Interface 1" 
    print(f"Escuchando paquetes TCP en el puerto {listen_port}...")
    filter_str = f"tcp port {listen_port}"
    pkt_capturado = []
    if mostrar:
        pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = tiempo_timeout)
    else: 
        pkt_capturado = sniff(iface = interface, filter = filter_str, count = 1, timeout = tiempo_timeout)
    return pkt_capturado

def enviar_paquete(flags_a_enviar, seq_ack):
    pkt = crear_paquete(5000, 8000, seq_ack[0], seq_ack[1], flags_a_enviar)
    f.envio_paquetes_inseguro(pkt)
    print("Se ha enviado el paquete de seq " + str(pkt[TCP].seq) + " y ack " + str(pkt[TCP].ack) + ".")
    
def esperar_request(flags_a_enviar, seq_ack):
    pkt_capturado = []
    pkt_capturado = esperar_ack(5000, 3, False)
    if len(pkt_capturado) == 0: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout.")
        enviar_paquete(flags_a_enviar, seq_ack)
    elif pkt_capturado[0][TCP].ack != seq_ack[0] + 1:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        enviar_paquete(flags_a_enviar, seq_ack) 
    elif verificar_checksum(pkt_capturado[0]) == False:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos.")
        enviar_paquete(flags_a_enviar, seq_ack)
    else:
        print("Se ha recibido correctamente el paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + ".")
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1

nro_random = random.randint(1, 10000)
seq_y_ack = [nro_random, 0]
enviar_paquete(['S'], seq_y_ack)
esperar_request(['S'], seq_y_ack)

seq_y_ack[0] += 1
enviar_paquete(['A'], seq_y_ack)






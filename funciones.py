import canalruidoso as f
from scapy.all import * 
from scapy.layers.inet import IP,TCP

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

def crear_request(puerto_origen, puerto_destino, nro_seq, nro_ack, flags_a_enviar) -> packet:
    source_ip = '127.0.0.1'
    dest_ip = '127.0.0.1'
    ip = IP(dst = dest_ip, src = source_ip)
    tcp = TCP(dport = puerto_destino, sport = puerto_origen, seq = nro_seq, ack = nro_ack, flags = flags_a_enviar)
    packet = ip/tcp
    
    calcular_checksum(packet)
    return packet

def crear_respuesta(pkt_capturado, nro_seq, nro_ack) -> packet:
    ip = IP(dst = pkt_capturado[0][IP].src, src = pkt_capturado[0][IP].dst)
    tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, seq = nro_seq, 
        ack = nro_ack, flags = ['A']) 
    if pkt_capturado[0][TCP].flags == 'S':
        tcp.flags = ['S', 'A']
    elif pkt_capturado[0][TCP].flags == 'F':
        tcp.flags = ['F', 'A']
    
    packet = ip/tcp
    calcular_checksum(packet)
    return packet

def escuchar(listen_port, tiempo_timeout) -> List:
    interface = "Software Loopback Interface 1" 
    print(f"Escuchando paquetes TCP en el puerto {listen_port}...")
    filter_str = f"tcp port {listen_port}"
    pkt_capturado = []
    pkt_capturado = sniff(iface = interface, filter = filter_str, count = 1, timeout = tiempo_timeout)
    if len(pkt_capturado) != 0:
        print("Se capturó un paquete de secuencia " + str(pkt_capturado[0][TCP].seq) + " y de ack " + str(pkt_capturado[0][TCP].ack) + ". Flags: " + str(pkt_capturado[0][TCP].flags) + ".")
    return pkt_capturado

def enviar_request(puerto_origen, puerto_destino, flags_a_enviar, seq_ack):
    pkt = crear_request(puerto_origen, puerto_destino, seq_ack[0], seq_ack[1], flags_a_enviar)
    f.envio_paquetes_inseguro(pkt)
    print(f"Se ha enviado un paquete de secuencia " + str(pkt[TCP].seq) + " y de ack " + str(pkt[TCP].ack) + ". Flags: " + str(pkt[TCP].flags) + ".")
    print("=====")

def enviar_respuesta(pkt_capturado, nro_seq, nro_ack):
    pkt = crear_respuesta(pkt_capturado, nro_seq, nro_ack)
    f.envio_paquetes_inseguro(pkt)
    print("Se ha enviado un paquete de secuencia " + str(pkt[TCP].seq) + " y de ack " + str(pkt[TCP].ack) + ". Flags: " + str(pkt[TCP].flags) + ".")
    print("=====")

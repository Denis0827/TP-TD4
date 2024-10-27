import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import * # Correr pip install scapy en la terminal
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

def crear_respuesta(pkt_capturado, nro_seq) -> packet:
    ip = IP(dst = pkt_capturado[0][IP].src, src = pkt_capturado[0][IP].dst)
    if 'S' in pkt_capturado[0][TCP].flags: 
        tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, seq = nro_seq, 
            ack = pkt_capturado[0][TCP].seq + 1, flags = ['S', 'A'])
    else:
        tcp = TCP(dport = pkt_capturado[0][TCP].sport, sport = pkt_capturado[0][TCP].dport, seq = nro_seq, 
            ack = pkt_capturado[0][TCP].seq + 1, flags = ['A']) 
    packet = ip/tcp
    calcular_checksum(packet)
    return packet

def escuchar(listen_port, tiempo_timeout, mostrar) -> List:
    interface = "Software Loopback Interface 1" 
    print(f"Escuchando paquetes TCP en el puerto {listen_port}...")
    filter_str = f"tcp port {listen_port}"
    pkt_capturado = []
    if mostrar:
        pkt_capturado = sniff(iface = interface, filter = filter_str, prn = lambda x: x.show(), count = 1, timeout = tiempo_timeout)
    else: 
        pkt_capturado = sniff(iface = interface, filter = filter_str, count = 1, timeout = tiempo_timeout)
    if len(pkt_capturado) != 0:
        print("Se capturó un paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y de ack " + str(pkt_capturado[0][TCP].ack))
    return pkt_capturado

def enviar_request_seguro(puerto_origen, puerto_destino, flags_a_enviar, seq_ack):
    # envia un request de seq = seq_ack[0] y ack = seq_ack[1]
    # chequea si debe retransmitir el request de seq = seq_ack[0] y ack = seq_ack[1]
    pkt = crear_request(puerto_origen, puerto_destino, seq_ack[0], seq_ack[1], flags_a_enviar)
    f.envio_paquetes_inseguro(pkt)
    print("Se ha enviado el paquete de seq " + str(pkt[TCP].seq) + " y ack " + str(pkt[TCP].ack) + ".")
    #chequear_retransmision(puerto_origen, puerto_destino, flags_a_enviar, seq_ack)

def enviar_respuesta(pkt_capturado, nro_seq):
    packet = crear_respuesta(pkt_capturado, nro_seq)
    f.envio_paquetes_inseguro(packet)
    print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")

def esperar_y_reconocer_request(listen_port, seq_ack):
    pkt_capturado = escuchar(listen_port, 60, False)
    if len(pkt_capturado) != 0:
        if not(verificar_checksum(pkt_capturado[0])):  # paquete corrupto
            print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto.")
            esperar_y_reconocer_request(listen_port, seq_ack)
        else:
            if pkt_capturado[0][TCP].ack == 0:
                print(seq_ack)
                enviar_respuesta(pkt_capturado, seq_ack[0])
            elif pkt_capturado[0][TCP].ack != 0 and pkt_capturado[0][TCP].ack == seq_ack[0]:
                print(seq_ack)
                enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
            else:
                esperar_y_reconocer_request(listen_port, seq_ack)
    else:
        esperar_y_reconocer_request(listen_port, seq_ack)


def chequear_retransmision(puerto_origen, puerto_destino, flags_a_enviar, seq_ack):
    # chequea si se debe reenviar el paquete de seq = seq_ack[0] y ack = seq_ack[1]
    
    pkt_capturado = []
    pkt_capturado = escuchar(puerto_origen, 3, False)
    if len(pkt_capturado) == 0: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout.")
        enviar_request_seguro(puerto_origen, puerto_destino, flags_a_enviar, seq_ack)
    elif pkt_capturado[0][TCP].ack != seq_ack[0] + 1:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        enviar_request_seguro(puerto_origen, puerto_destino, flags_a_enviar, seq_ack) 
    elif verificar_checksum(pkt_capturado[0]) == False:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos.")
        enviar_request_seguro(puerto_origen, puerto_destino, flags_a_enviar, seq_ack)
    else:
        print("Se ha recibido correctamente el paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + ".")
        seq_ack[0] = pkt_capturado[0][TCP].ack
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1
        
        


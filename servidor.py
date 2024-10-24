from scapy.all import *
import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.layers.inet import IP,TCP

# Mostramos todas las interfaces
# print(conf.ifaces)

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
    calcular_checksum(packet)
    return packet



def enviar_respuesta(pkt_capturado):
    pkt_capturado = esperar_paquete(8000, 3, False)
    if len(pkt_capturado) != 0:
        pkt_corrupto = verificar_checksum(pkt_capturado[0])
        obtener_ack = pkt_capturado[0][TCP].flags == ['A']
        if pkt_corrupto:
            print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto.")
        elif not(pkt_corrupto) and not(obtener_ack):
            if pkt_capturado[0][TCP].ack == 0:
                packet = crear_respuesta(pkt_capturado, nro_secuencia)
            else:
                packet = crear_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
            f.envio_paquetes_inseguro(packet)
            print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")
    else:
        enviar_respuesta(packet)




def enviar_paquete(flags_a_enviar, seq_ack):
    pkt = crear_respuesta(5000, 8000, seq_ack[0], flags_a_enviar)
    f.envio_paquetes_inseguro(pkt)
    print("Se ha enviado el paquete de seq " + str(pkt[TCP].seq) + " y ack " + str(pkt[TCP].ack) + ".")
    

def esperar_request(flags_a_enviar, seq_ack): #terminar
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

    
nro_secuencia = random.randint(1, 10000)
pkt_capturado = []
while pkt_capturado[0][TCP].ack != nro_secuencia + 2:
    pkt_capturado = esperar_paquete(8000, 60, False)
    if len(pkt_capturado) != 0:
        pkt_corrupto = verificar_checksum(pkt_capturado[0])
        obtener_ack = pkt_capturado[0][TCP].flags == ['A']
        if pkt_corrupto:
            print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto.")
        elif not(pkt_corrupto) and not(obtener_ack):
            if pkt_capturado[0][TCP].ack == 0:
                packet = crear_respuesta(pkt_capturado, nro_secuencia)
            else:
                packet = crear_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
            f.envio_paquetes_inseguro(packet)
            print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")


nro_secuencia = random.randint(1, 10000)
while True:
    pkt_capturado = esperar_paquete(8000, 60, False)
    if len(pkt_capturado) != 0:
        pkt_corrupto = pkt_capturado[0][TCP].chksum != len(bytes(pkt_capturado[0][TCP]))
        obtener_ack_vacio = len(bytes(pkt_capturado[0][TCP])) == 20 and pkt_capturado[0][TCP].flags == ['A']
        if not(pkt_corrupto) and not(obtener_ack_vacio):
            if pkt_capturado[0][TCP].ack == 0:
                packet = crear_respuesta(pkt_capturado, nro_secuencia)
            else:
                packet = crear_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
            f.envio_paquetes_inseguro(packet)
            print(f"Se ha enviado un paquete de secuencia {packet[TCP].seq} y de ack {packet[TCP].ack}")

    
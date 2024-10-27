from funciones import *
import random

nro_random = random.randint(1, 10000)
seq_ack = [nro_random, 0]

pkt = crear_request(5000, 8000, seq_ack[0], seq_ack[1], ['S'])
f.envio_paquetes_inseguro(pkt)
print("Se ha enviado el paquete de seq " + str(pkt[TCP].seq) + " y ack " + str(pkt[TCP].ack) + ".")
while True:
    pkt_capturado = []
    pkt_capturado = escuchar(5000, 3, False)
    if len(pkt_capturado) == 0: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout.")
        enviar_request_seguro(5000, 8000, ['S'], seq_ack)
    elif pkt_capturado[0][TCP].ack != seq_ack[0] + 1:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        enviar_request_seguro(5000, 8000, ['S'], seq_ack)
    elif verificar_checksum(pkt_capturado[0]) == False:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos.")
        enviar_request_seguro(5000, 8000, ['S'], seq_ack)
    else:
        print("Se ha recibido correctamente el paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + ".")
        seq_ack[0] = pkt_capturado[0][TCP].ack
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1
        enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
        
        while True:
            pkt_capturado = escuchar(5000, 10, False)
            if len(pkt_capturado) != 0:
                if not(verificar_checksum(pkt_capturado[0])):  # paquete corrupto
                    print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto.")
                else:
                    if pkt_capturado[0][TCP].ack == 0:
                        enviar_respuesta(pkt_capturado, seq_ack[0])
                    elif pkt_capturado[0][TCP].ack != 0 and pkt_capturado[0][TCP].ack == seq_ack[0]:
                        enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
            else:
                break
        break



from funciones import *
import random

nro_random = random.randint(1, 10000)
seq_ack = [nro_random, 0]

enviar_request(5000, 8000, ['S'], seq_ack)
pkt_capturado = []
enviar_syn = True

while enviar_syn:
    pkt_capturado = escuchar(5000, 3, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_inesperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack != seq_ack[0] + 1 # tengo que chequear tmb si el ack = seq y seq = ack?
    
    if paquete_perdido: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout. Flags: S.")
        print("=====")
        enviar_request(5000, 8000, ['S'], seq_ack)
    elif paquete_inesperado: # esta al pedo esto porque solo le puede llegar el synack
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        print("=====")
        enviar_request(5000, 8000, ['S'], seq_ack)
    elif paquete_corrupto:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos. Flags: S.")
        print("=====")
        enviar_request(5000, 8000, ['S'], seq_ack)
    else:
        print("Se ha reconocido correctamente el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ". Flags: S.")
        print("=====")
        seq_ack[0] += 1
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1
        enviar_respuesta(pkt_capturado, seq_ack[0])
        enviar_syn = False

pkt_capturado = []
enviar_ack = True

while enviar_ack:
    pkt_capturado = escuchar(5000, 10, False)
    ack_recibido = len(pkt_capturado) == 0   # si le llegó correctamente el ack al servidor, no debería capturar ningún otro paquete
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_esperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack == seq_ack[0]
    
    if paquete_corrupto: 
        print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto. Flags: SA.")
        print("=====")
    elif paquete_esperado:
        enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
    elif ack_recibido: 
        print("Se ha establecido correctamente el handshake.")
        print("=====")
        enviar_ack = False

pkt_capturado = []
esperar_fin = True
seq_ack[0] += 1

while esperar_fin:
    pkt_capturado = escuchar(5000, 30, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_inesperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack != seq_ack[0] 

    if paquete_perdido:
        print("No se ha capturado ningún paquete.")
        print("=====")
    elif paquete_corrupto: 
        print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto. Flags: F.")
        print("=====")
    elif paquete_inesperado:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        print("=====")
    else:
        seq_ack[1] += 1
        enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
        esperar_fin = False
    
pkt_capturado = []
enviar_fin_ack = True

while enviar_fin_ack:
    pkt_capturado = escuchar(5000, 3, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_inesperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack != seq_ack[0] + 1
    
    if paquete_perdido: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout. Flags: FA.")
        print("=====")
        enviar_request(5000, 8000, ['F', 'A'], seq_ack)
    elif paquete_inesperado:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        print("=====")
        enviar_request(5000, 8000, ['F', 'A'], seq_ack)
    elif paquete_corrupto:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos. Flags: FA.")
        print("=====")
        enviar_request(5000, 8000, ['F', 'A'], seq_ack)
    else:
        print("Se ha reconocido correctamente el paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + ". Flags: FA.")
        print("=====")
        seq_ack[0] = pkt_capturado[0][TCP].ack
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1
        enviar_fin_ack = False




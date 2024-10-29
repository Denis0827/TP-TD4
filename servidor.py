from funciones import *
import random

nro_random = random.randint(1, 10000)
seq_ack = [nro_random, 0]
pkt_capturado = []
esperar_syn = True

while esperar_syn:
    pkt_capturado = escuchar(8000, 30, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))

    if paquete_perdido:
        print("No se ha capturado ningún paquete.")
        print("=====")
    elif paquete_corrupto: 
        print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto. Flags: S.")
        print("=====")
    else: 
        seq_ack[1] = pkt_capturado[0][TCP].seq + 1
        enviar_respuesta(pkt_capturado, seq_ack[0])
        esperar_syn = False

pkt_capturado = []
enviar_syn_ack = True

while enviar_syn_ack:
    pkt_capturado = escuchar(8000, 3, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_inesperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack != seq_ack[0] + 1 
    
    if paquete_perdido: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout. Flags: SA.")
        print("=====")
        enviar_request(8000, 5000, ['S', 'A'], seq_ack)
    elif paquete_inesperado:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        print("=====")
        enviar_request(8000, 5000, ['S', 'A'], seq_ack)
    elif paquete_corrupto:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos. Flags: SA.")
        print("=====")
        enviar_request(8000, 5000, ['S', 'A'], seq_ack)
    else:
        print("Se ha reconocido correctamente el paquete de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + ". Flags: SA.")
        print("=====")
        
        enviar_syn_ack = False

seq_ack[0] = pkt_capturado[0][TCP].ack
seq_ack[1] = pkt_capturado[0][TCP].seq + 1
print("Esperando 20 segundos...")
print("=====")
time.sleep(20)

enviar_request(8000, 5000, ['F'], seq_ack)
pkt_capturado = []
enviar_fin = True

while enviar_fin:
    pkt_capturado = escuchar(8000, 3, False)
    paquete_perdido = len(pkt_capturado) == 0
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    paquete_inesperado = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack != seq_ack[0] + 1 
    
    if paquete_perdido: 
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por timeout. Flags: F.")
        print("=====")
        enviar_request(8000, 5000, ['F'], seq_ack)
    elif paquete_inesperado:
        print("Se ha recibido un paquete distinto al apropiado. Se espera que se reconozca el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ".")   
        print("=====")
        enviar_request(8000, 5000, ['F'], seq_ack)
    elif paquete_corrupto:
        print("Se retransmite el paquete de seq " + str(seq_ack[0]) + " por corrupción de datos. Flags: F.")
        print("=====")
        enviar_request(8000, 5000, ['F'], seq_ack)
    else:
        print("Se ha reconocido correctamente el paquete de seq " + str(seq_ack[0]) + " y ack " + str(seq_ack[1]) + ". Flags: F.")
        print("=====")
        
        enviar_fin = False

seq_ack[0] = pkt_capturado[0][TCP].ack
seq_ack[1] = pkt_capturado[0][TCP].seq + 1
enviar_respuesta(pkt_capturado, seq_ack[0])
pkt_capturado = []
enviar_ack = True

while enviar_ack:
    pkt_capturado = escuchar(8000, 10, False)
    ack_recibido = len(pkt_capturado) == 0  
    paquete_corrupto = len(pkt_capturado) != 0 and not(verificar_checksum(pkt_capturado[0]))
    fin_ack_retransmitido = len(pkt_capturado) != 0 and pkt_capturado[0][TCP].ack == seq_ack[0] 
    
    if paquete_corrupto: 
        print("El paquete recibido de seq " + str(pkt_capturado[0][TCP].seq) + " y ack " + str(pkt_capturado[0][TCP].ack) + " está corrupto. Flags: FA.")
        print("=====")
    elif fin_ack_retransmitido:
        enviar_respuesta(pkt_capturado, pkt_capturado[0][TCP].ack)
    elif ack_recibido: 
        print("Se ha cerrado correctamente la conexión.")
        print("=====")
        enviar_ack = False


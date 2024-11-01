from funciones import *
import time
from datetime import datetime
import pandas as pd

nro_seq = 28
cantidad_delays = 0
cantidad_corrupcion = 0
cantidad_perdida = 0
cantidad_correcto = 0
cantidad_enviados = 0
tiempo_delay_total = 0

def generar_archivo_excel(datos, nombre_archivo):
    columnas = ['Enviados', 'Delay', 'Corrupcion', 'Perdida', 'Correctos', 'Delay Total', 'Delay Promedio']
    df = pd.DataFrame(datos, columns=columnas)
    
    df.to_excel(nombre_archivo, index=False)

datos = {
    'Enviados': [],
    'Delay': [],
    'Corrupcion': [],
    'Perdida': [],
    'Correctos': [],
    'Delay Total': [],
    'Delay Promedio': []
}

while True:
    pkt_capturado = escuchar(8000, 15)
    tiempo_recibido = time.time()
    
    if len(pkt_capturado) != 0:
        tiempo_envio = float(pkt_capturado[0][Raw].load.decode('utf-8'))
        tiempo_transcurrido = tiempo_recibido - tiempo_envio
        
        if tiempo_transcurrido > 3:
            cantidad_delays += 1
            tiempo_delay_total += tiempo_transcurrido
            
        elif not(verificar_checksum(pkt_capturado[0])):
            cantidad_corrupcion += 1
            
        else:
            cantidad_correcto += 1
            
        if pkt_capturado[0][TCP].seq > nro_seq:
            cantidad_perdida += pkt_capturado[0][TCP].seq - nro_seq
        
        nro_seq = pkt_capturado[0][TCP].seq + 1
    
    cantidad_enviados = cantidad_correcto + cantidad_delays + cantidad_perdida + cantidad_corrupcion
    
    datos['Enviados'].append(cantidad_enviados)
    datos['Delay'].append(cantidad_delays)
    datos['Corrupcion'].append(cantidad_corrupcion)
    datos['Perdida'].append(cantidad_perdida)
    datos['Correctos'].append(cantidad_correcto)
    datos['Delay Total'].append(tiempo_delay_total)
    
    if cantidad_delays != 0:
        datos['Delay Promedio'].append(tiempo_delay_total/cantidad_delays)
    else:
        datos['Delay Promedio'].append(0)
    
    print("Paquetes enviados: " + str(cantidad_enviados))
    print("Paquetes correctos: " + str(cantidad_correcto))
    print("Paquetes demorados: " + str(cantidad_delays))
    print("Paquetes perdidos: " + str(cantidad_perdida))
    print("Paquetes corruptos: " + str(cantidad_corrupcion))
    print("Delay total: " + str(tiempo_delay_total))
    print("=====")
    
    if cantidad_enviados == 1000:
        break

generar_archivo_excel(datos, "datos_experimento2.xlsx")

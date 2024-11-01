from funciones import *
import time

nro_seq = 28

for experimento in range(0, 1000):
    tiempo_envio = time.time()
    
    ip = IP(dst = '127.0.0.1', src = '127.0.0.1')
    tcp = TCP(dport = 8000, sport = 5000, seq = nro_seq, ack = 6, flags = ['A'])
    paquete = ip/tcp/Raw(load = str(tiempo_envio))
    
    calcular_checksum(paquete)
    f.envio_paquetes_inseguro(paquete)
    time.sleep(8)
    
    nro_seq += 1
    

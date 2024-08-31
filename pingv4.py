from scapy.all import *
import time

def enviar_datos_ocultos(destino, texto):
    # Realiza un ping inicial para capturar el paquete ICMP y usarlo como plantilla
    ping_inicial = sr1(IP(dst=destino)/ICMP(), timeout=1)
    
    if not ping_inicial:
        print("No se recibió respuesta al ping inicial. Abortando.")
        return
    
    # Extraer el payload base del paquete inicial
    payload_base = ping_inicial[Raw].load if Raw in ping_inicial else b'\x00' * 32
    
    # Obtener el ID, el número de secuencia y el timestamp inicial
    id_inicial = ping_inicial[ICMP].id
    seq_inicial = ping_inicial[ICMP].seq
    timestamp_inicial = ping_inicial[ICMP].ts_ori if ICMP in ping_inicial and hasattr(ping_inicial[ICMP], 'ts_ori') else None

    identificador_actual = id_inicial

    for i, caracter in enumerate(texto):
        # Crear el nuevo payload con el carácter oculto
        nuevo_payload = payload_base[:8] + caracter.encode() + payload_base[9:]
        
        # Crear el paquete ICMP manteniendo el timestamp y ajustando ID y seq
        paquete = IP(dst=destino)/ICMP(id=identificador_actual, seq=seq_inicial + i)/Raw(load=nuevo_payload)
        
        # Mantener el timestamp si está presente en el paquete inicial
        if timestamp_inicial:
            paquete[ICMP].ts_ori = timestamp_inicial
            paquete[ICMP].ts_rx = timestamp_inicial  # Mantener coherencia en la recepción
            paquete[ICMP].ts_tx = int(time.time() * 1000) & 0xffffffff  # Actualizar el timestamp de envío
        
        send(paquete)
        
        # Incrementar el ID de manera coherente
        identificador_actual += 1
        
        # Pequeña pausa entre paquetes para evitar detección
        time.sleep(0.1)

if __name__ == "__main__":
    destino = "8.8.8.8"  # Cambia esto por la IP de destino
    texto = "larycxpajorj h bnpdarmjm nw anmnb"
    enviar_datos_ocultos(destino, texto)

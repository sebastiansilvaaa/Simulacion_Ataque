from scapy.all import *
from termcolor import colored
import re
from collections import Counter
import nltk
from nltk.util import ngrams

# Descargar lista de palabras en español de NLTK
nltk.download('words')

# Lista de palabras en español (puedes expandirla con un diccionario más completo)
PALABRAS_COMUNES = set([
    'el', 'la', 'de', 'y', 'a', 'en', 'que', 'los', 'del', 'se', 'las', 'un', 'por', 'con', 'no', 'una', 'es', 'para', 'su', 'al', 'lo', 'como', 'o', 'pero', 'más', 'este', 'ya', 'me', 'todo', 'hoy', 'también', 'cuando', 'esta', 'sus', 'entre',# Añade palabras específicas para detectar frases comunes
])

def cifrar_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isupper():
            resultado += chr((ord(char) + corrimiento - 65) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) + corrimiento - 97) % 26 + 97)
        else:
            resultado += char
    return resultado

def extraer_mensaje_pcap(pcap_file):
    paquetes = rdpcap(pcap_file)
    mensaje_cifrado = ""
    for paquete in paquetes:
        if ICMP in paquete and Raw in paquete:
            if paquete[ICMP].type == 8:  # Tipo 8 es Echo Request
                payload = paquete[Raw].load.decode(errors='ignore')
                if payload:
                    mensaje_cifrado += payload
    return mensaje_cifrado

def evaluar_legibilidad(texto):
    palabras = re.findall(r'\b\w+\b', texto.lower())
    if not palabras:
        return 0
    
    contador_palabras = Counter(palabras)
    puntuacion_palabras = sum(1 for palabra in palabras if palabra in PALABRAS_COMUNES)
    
    # Agregar puntuación por bigramas comunes
    bigramos = list(ngrams(palabras, 2))
    puntuacion_bigramos = sum(1 for bigrama in bigramos if ' '.join(bigrama) in PALABRAS_COMUNES)
    
    puntuacion_total = puntuacion_palabras + puntuacion_bigramos
    total_elementos = len(palabras) + len(bigramos)
    return puntuacion_total / total_elementos if total_elementos > 0 else 0

def generar_todas_combinaciones(mensaje_cifrado):
    mejor_puntuacion = 0
    mejor_opcion = None
    opciones = []
    
    for corrimiento in range(26):
        mensaje_descifrado = cifrar_cesar(mensaje_cifrado, -corrimiento)
        puntuacion = evaluar_legibilidad(mensaje_descifrado)
        opciones.append((corrimiento, puntuacion, mensaje_descifrado))
        
        # Actualizar la mejor opción
        if puntuacion > mejor_puntuacion:
            mejor_puntuacion = puntuacion
            mejor_opcion = (corrimiento, puntuacion, mensaje_descifrado)
    
    # Imprimir todas las opciones, marcando en verde solo la mejor opción
    for corrimiento, puntuacion, mensaje_descifrado in opciones:
        if (corrimiento, puntuacion, mensaje_descifrado) == mejor_opcion:
            print(colored(f"Corrimiento {corrimiento}: {mensaje_descifrado} (Puntuación: {puntuacion})", 'green'))
        else:
            print(f"Corrimiento {corrimiento}: {mensaje_descifrado} (Puntuación: {puntuacion})")
    
    return mejor_opcion

def analizar_mensaje(mensaje_cifrado):
    print(f"\nAnalizando mensaje cifrado completo: {mensaje_cifrado}")
    mejor_opcion = generar_todas_combinaciones(mensaje_cifrado)
    if mejor_opcion:
        corrimiento, puntuacion, mensaje_descifrado = mejor_opcion
        print(f"\nMejor opción:\nCorrimiento {corrimiento}: {mensaje_descifrado} (Puntuación: {puntuacion})")

if __name__ == "__main__":
    pcap_file = "caesar.pcapng"  # Cambia esto al nombre de tu archivo pcap
    mensaje_cifrado = extraer_mensaje_pcap(pcap_file)
    if not mensaje_cifrado:
        print("No se encontraron mensajes ICMP Echo Request en el archivo.")
    else:
        analizar_mensaje(mensaje_cifrado)

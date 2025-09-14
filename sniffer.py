
from scapy.all import *

def procesar_paquete(paquete):

    print(paquete.summary())

def main():

    print("Iniciando sniffer... Presiona Ctrl+C para detener.")
    
    # sniff() es la función de scapy que hace la magia de capturar.
    # prn=procesar_paquete -> Llama a nuestra función por cada paquete.
    # count=1 -> Le decimos que capture solo 1 paquete y luego se detenga.
    sniff(prn=procesar_paquete)

# Esta línea asegura que la función main() se ejecute al correr el script.
if __name__ == "__main__":
    main()
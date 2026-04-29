import random
import concurrent.futures
from scapy.all import IP, TCP, sr1, send

def scaning_port(target, port):
    # Generamos un puerto de origen aleatorio
    Origen_port = random.randint(1024, 65535)
    # Creamos el paquete SYN
    packet = IP(dst=target)/TCP(sport=Origen_port, dport=port, flags="S")
    # Enviamos y esperamos respuesta
    response = sr1(packet, timeout=1, verbose=0)

    if response is None:
        return port, "Puerto filtrado"
    
    if response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN/ACK
            # Enviamos un RST para cerrar la conexión 
            send(IP(dst=target)/TCP(sport=Origen_port, dport=port, flags="R"), verbose=0)
            return port, "Puerto abierto"
        elif response[TCP].flags == 0x14:  # RST/ACK (Puerto cerrado)
            return port, "Puerto cerrado"
    return None

def run_scanner():
    target = input("Ingrese una IP a escanear: ")
    # Definimos el rango de puertos
    ports = range(1024, 1591)
    
    print(f"\n--- Escaneando {target} con múltiples hilos ---")

    # Usamos ThreadPoolExecutor para manejar los hilos probando 50 puertos al mismo tiempo
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Mapeamos la función a los puertos
        futures = [executor.submit(scaning_port, target, port) for port in ports]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port_num, status = result
                # Solo imprimimos los abiertos
                if status == "Puerto abierto":
                    print(f"[+] {port_num} - {status}")

if __name__ == "__main__":
    run_scanner()

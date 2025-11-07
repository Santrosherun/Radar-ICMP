import time
import threading
from scapy.all import IP, ICMP, sr1, conf
import psutil
import ipaddress
import warnings
from threading import Lock, RLock
from collections import defaultdict
import queue

# Configurar Scapy para ser menos verboso y suprimir warnings
conf.verb = 0
warnings.filterwarnings("ignore", message=".*Scapy.*")
warnings.filterwarnings("ignore", message=".*threading.*")

class ICMPScanner:
    def __init__(self, network_range="192.168.1.0/24", timeout=0.5, host_persistence=30):
        """
        Inicializa el escáner ICMP
        
        Args:
            network_range (str): Rango de red a escanear (ej: "192.168.1.0/24")
            timeout (float): Tiempo de espera para cada ping en segundos
            host_persistence (int): Tiempo en segundos antes de considerar un host como inactivo
        """
        self.network_range = network_range
        self.timeout = timeout
        self.host_persistence = host_persistence
        
        # Thread-safe data structures
        self.active_hosts = {}
        self.learned_macs = {}
        self.known_hosts = set()
        
        # Locks para thread safety
        self.hosts_lock = RLock()
        self.macs_lock = RLock()
        self.known_hosts_lock = RLock()
        
        # Threading control
        self.scanning = False
        self.scan_thread = None
        self.continuous_ping_thread = None
        self.continuous_ping_running = False
        self.cleanup_thread = None
        self.cleanup_running = False
        
        # Queue para comunicación entre threads
        self.host_updates_queue = queue.Queue(maxsize=1000)
        
    def get_local_network(self):
        """
        Detecta automáticamente la red local
        """
        try:
            # Obtener la interfaz de red activa
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        ip = addr.address
                        netmask = addr.netmask
                        if ip != "127.0.0.1" and not ip.startswith("169.254"):
                            # Calcular la red
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            return str(network)
        except:
            pass
        return "192.168.1.0/24"  # Fallback por defecto
    
    def _learn_mac_via_arp(self, ip):
        """
        Aprende la dirección MAC de una IP usando ARP request
        
        Args:
            ip (str): Dirección IP para resolver
        """
        try:
            from scapy.all import ARP, Ether, srp
            
            # Crear request ARP
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Enviar y recibir
            answered_list, _ = srp(arp_request_broadcast, timeout=1, verbose=0)
            
            if answered_list:
                for element in answered_list:
                    mac_address = element[1].hwsrc
                    # Actualizar MACs de forma thread-safe
                    with self.macs_lock:
                        self.learned_macs[ip] = mac_address
                    print(f"[ARP-LEARN] {ip} -> {mac_address}")
                    break
                    
        except Exception as e:
            # Si falla ARP, no es crítico
            pass
    
    def ping_host(self, ip, retries=2):
        """
        Envía un ping ICMP a una IP específica, aprendiendo direcciones MAC
        
        Args:
            ip (str): Dirección IP a hacer ping
            retries (int): Número de reintentos si falla el primer ping
            
        Returns:
            tuple: (ip, latencia_ms) si responde, (ip, None) si no responde
        """
        # Intentar múltiples pings para mayor probabilidad de respuesta
        for attempt in range(retries + 1):
            try:
                # Crear paquete ICMP (siempre a nivel IP)
                packet = IP(dst=ip) / ICMP()
                
                # Enviar paquete y medir tiempo
                start_time = time.time()
                reply = sr1(packet, timeout=self.timeout, verbose=0)
                end_time = time.time()
                
                if reply:
                    latency = (end_time - start_time) * 1000  # Convertir a ms
                    
                    # Solo aprender MAC si no la conocemos (evita ARP redundantes)
                    # Verificar MACs de forma thread-safe
                    with self.macs_lock:
                        mac_known = ip in self.learned_macs
                    
                    if not mac_known:
                        self._learn_mac_via_arp(ip)
                    else:
                        print(f"[MAC-SKIP] Ya conocemos MAC de {ip}, omitiendo ARP")
                    
                    return (ip, latency)
                
                # Si no responde y no es el último intento, esperar un poco
                if attempt < retries:
                    time.sleep(0.1)  # Pausa breve entre reintentos
                    
            except Exception as e:
                if attempt < retries:
                    time.sleep(0.1)
                    continue
                    
        return (ip, None)
    
    def scan_network(self):
        """
        Escanea toda la red en busca de hosts activos
        """
        try:
            network = ipaddress.IPv4Network(self.network_range, strict=False)
            threads = []
            results = []
            
            def ping_worker(ip_str):
                result = self.ping_host(ip_str)
                if result[1] is not None:  # Si el host responde
                    results.append(result)
            
            # Crear threads para ping paralelo
            for ip in network.hosts():
                if len(threads) >= 20:  # Reducir threads concurrentes para mejor rendimiento
                    for t in threads:
                        t.join()
                    threads.clear()
                
                thread = threading.Thread(target=ping_worker, args=(str(ip),))
                thread.start()
                threads.append(thread)
            
            # Esperar a que terminen todos los threads
            for thread in threads:
                thread.join()
            
                # Actualizar hosts activos (thread-safe)
                current_time = time.time()
                for ip, latency in results:
                    host_info = {
                        'latency': latency,
                        'last_seen': current_time,
                        'angle': hash(ip) % 360  # Asignar ángulo único basado en IP
                    }
                    
                    with self.hosts_lock:
                        self.active_hosts[ip] = host_info
                    
                    with self.known_hosts_lock:
                        self.known_hosts.add(ip)
                    
        except Exception as e:
            print(f"Error durante el escaneo: {e}")
    
    def start_continuous_ping(self):
        """
        Inicia ping continuo a hosts conocidos cada pocos segundos
        """
        if self.continuous_ping_running:
            return
            
        self.continuous_ping_running = True
        
        def continuous_ping_worker():
            while self.continuous_ping_running:
                try:
                    # Hacer ping a hosts conocidos más frecuentemente
                    for ip in list(self.known_hosts):
                        if not self.continuous_ping_running:
                            break
                            
                        result = self.ping_host(ip, retries=1)  # Solo 1 reintento para ser rápido
                        
                        if result[1] is not None:  # Si responde
                            # Actualizar información del host (thread-safe)
                            current_time = time.time()
                            with self.hosts_lock:
                                existing_angle = self.active_hosts.get(ip, {}).get('angle', hash(ip) % 360)
                                self.active_hosts[ip] = {
                                    'latency': result[1],
                                    'last_seen': current_time,
                                    'angle': existing_angle
                                }
                            print(f"[PING-CONT] {ip}: {result[1]:.1f}ms")
                        
                        # Pequeña pausa entre pings para no saturar
                        time.sleep(0.1)
                    
                    # Pausa antes del siguiente ciclo de ping continuo
                    time.sleep(2)  # Ping continuo cada 2 segundos
                    
                except Exception as e:
                    time.sleep(1)
        
        self.continuous_ping_thread = threading.Thread(target=continuous_ping_worker, daemon=True)
        self.continuous_ping_thread.start()
    
    def stop_continuous_ping(self):
        """
        Detiene el ping continuo
        """
        self.continuous_ping_running = False
        if self.continuous_ping_thread:
            self.continuous_ping_thread.join(timeout=2)
    
    def start_continuous_scan(self, interval=5):
        """
        Inicia escaneo continuo en segundo plano
        
        Args:
            interval (int): Intervalo entre escaneos en segundos
        """
        if self.scanning:
            return
            
        self.scanning = True
        
        def scan_loop():
            while self.scanning:
                self.scan_network()
                time.sleep(interval)
        
        self.scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """
        Detiene todos los threads de escaneo
        """
        self.scanning = False
        self.stop_continuous_ping()
        self.stop_cleanup_thread()
        
        if self.scan_thread:
            self.scan_thread.join()
            
    def get_learned_macs(self):
        """
        Retorna las MACs aprendidas de forma thread-safe
        """
        with self.macs_lock:
            return self.learned_macs.copy()
    
    def start_cleanup_thread(self):
        """
        Inicia thread de limpieza de hosts expirados
        """
        if self.cleanup_running:
            return
            
        self.cleanup_running = True
        
        def cleanup_worker():
            while self.cleanup_running:
                try:
                    current_time = time.time()
                    expired_hosts = []
                    
                    # Usar lock para acceso thread-safe
                    with self.hosts_lock:
                        for ip, info in list(self.active_hosts.items()):
                            if current_time - info['last_seen'] > self.host_persistence:
                                expired_hosts.append(ip)
                        
                        # Remover hosts expirados
                        for ip in expired_hosts:
                            if ip in self.active_hosts:
                                del self.active_hosts[ip]
                                print(f"[CLEANUP] Host expirado: {ip}")
                    
                    # Limpiar hosts conocidos también
                    if expired_hosts:
                        with self.known_hosts_lock:
                            for ip in expired_hosts:
                                self.known_hosts.discard(ip)
                    
                    # Ejecutar limpieza cada 5 segundos
                    time.sleep(5)
                    
                except Exception as e:
                    time.sleep(1)
        
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def stop_cleanup_thread(self):
        """
        Detiene el thread de limpieza
        """
        self.cleanup_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2)
    
    def get_active_hosts(self):
        """
        Retorna la lista de hosts activos (thread-safe, sin limpieza)
        
        Returns:
            dict: Diccionario con hosts activos {ip: {latency, last_seen, angle}}
        """
        with self.hosts_lock:
            return self.active_hosts.copy()
    
    def get_learned_macs_count(self):
        """
        Retorna el número de direcciones MAC aprendidas
        
        Returns:
            int: Número de MACs en la tabla aprendida
        """
        return len(self.learned_macs)
    
    def print_learned_macs(self):
        """
        Muestra la tabla ARP aprendida
        """
        if self.learned_macs:
            print(f"\n[ARP-TABLE] Direcciones MAC aprendidas ({len(self.learned_macs)}):")
            for ip, mac in self.learned_macs.items():
                print(f"  {ip:15} -> {mac}")
        else:
            print("\n[ARP-TABLE] No hay direcciones MAC aprendidas aún")

if __name__ == "__main__":
    # Ejemplo de uso
    scanner = ICMPScanner()
    
    # Detectar red local automáticamente
    local_network = scanner.get_local_network()
    print(f"Escaneando red: {local_network}")
    scanner.network_range = local_network
    
    # Realizar primer escaneo (aprenderá MACs)
    print("\n[SCAN-1] Primer escaneo (aprendiendo MACs)...")
    scanner.scan_network()
    
    hosts = scanner.get_active_hosts()
    print(f"\nHosts activos encontrados: {len(hosts)}")
    for ip, info in hosts.items():
        print(f"  {ip}: {info['latency']:.2f}ms (ángulo: {info['angle']}°)")
    
    # Mostrar MACs aprendidas
    scanner.print_learned_macs()
    
    # Realizar segundo escaneo (usará MACs aprendidas)
    print(f"\n[SCAN-2] Segundo escaneo (usando {scanner.get_learned_macs_count()} MACs aprendidas)...")
    scanner.scan_network()
    
    hosts = scanner.get_active_hosts()
    print(f"\nHosts activos encontrados: {len(hosts)}")
    for ip, info in hosts.items():
        print(f"  {ip}: {info['latency']:.2f}ms")

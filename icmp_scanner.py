import time
import threading
from scapy.all import IP, ICMP, sr1, conf
import psutil
import warnings
from collections import defaultdict
import queue
import socket
import struct

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
        
        # Estructuras de datos compartidas
        self.active_hosts = {}
        self.learned_macs = {}
        self.known_hosts = set()
        self.offline_hosts = {}  # Hosts que estuvieron online pero ahora están offline
        
        # Threading control
        self.scanning = False
        self.scan_thread = None
        self.continuous_ping_thread = None
        self.continuous_ping_running = False
        self.cleanup_thread = None
        self.cleanup_running = False
        
        # Queue para comunicación entre threads
        self.host_updates_queue = queue.Queue(maxsize=1000)
        
        # ═══════════════════════════════════════════════════════
        # ESTADÍSTICAS GLOBALES
        # ═══════════════════════════════════════════════════════
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'packets_lost': 0,
            'total_latency': 0.0,
            'min_latency': float('inf'),
            'max_latency': 0.0,
            'start_time': time.time()
        }
        
        # Historial de latencia por host (últimos 30 valores)
        self.latency_history = defaultdict(lambda: [])
        
        # Información de hosts (hostname, tipo de dispositivo)
        self.host_info = {}  # {ip: {'hostname': str, 'device_type': str}}
        
    def _resolve_hostname_and_type(self, ip):
        """
        Resuelve el hostname y detecta el tipo de dispositivo
        
        Args:
            ip (str): Dirección IP
            
        Returns:
            tuple: (hostname, device_type)
        """
        # Nombre básico generado por IP (sin DNS)
        last_octet = ip.split('.')[-1]
        hostname = f"Host-{last_octet}"
        device_type = "Device"

        # Gateway típico por IP
        if ip.endswith('.1') or ip.endswith('.254'):
            hostname = "Gateway"
            device_type = "🌐 Router"
        else:
            # Intentar inferir tipo por MAC (OUI)
            mac = self.learned_macs.get(ip)
            if mac:
                mac_norm = mac.upper().replace('-', ':')
                oui = ':'.join(mac_norm.split(':')[0:3])

                # Mapa ampliado de OUIs -> (vendor, tipo de dispositivo)
                # Lista expandida con fabricantes comunes
                oui_vendor_type_map = {
                    # Routers / APs domésticos
                    "14:82:5B": ("TP-Link", "Router/AP"),
                    "F4:F2:6D": ("TP-Link", "Router/AP"),
                    "C8:3A:35": ("TP-Link", "Router/AP"),
                    "50:C7:BF": ("TP-Link", "Router/AP"),
                    "D4:6E:0E": ("Huawei", "Router/AP"),
                    "28:28:5D": ("Huawei", "Router/AP"),
                    "00:9A:CD": ("Huawei", "Router/AP"),
                    "50:64:2B": ("ZTE", "Router/AP"),
                    "00:1F:33": ("Netgear", "Router/AP"),
                    "2C:B0:5D": ("Netgear", "Router/AP"),
                    "84:16:F9": ("Asus", "Router/AP"),
                    "00:1D:7E": ("Asus", "Router/AP"),
                    "00:1B:11": ("Linksys", "Router/AP"),
                    "00:1A:70": ("D-Link", "Router/AP"),
                    "00:1E:58": ("D-Link", "Router/AP"),
                    "00:0C:41": ("MikroTik", "Router/AP"),

                    # PCs / Laptops
                    "58:6C:25": ("Intel", "PC/Laptop"),
                    "3C:97:0E": ("Intel", "PC/Laptop"),
                    "00:1B:21": ("Dell", "PC/Laptop"),
                    "F8:B1:56": ("HP", "PC/Laptop"),
                    "A4:34:D9": ("Realtek", "PC/Laptop"),
                    "00:1E:68": ("Lenovo", "PC/Laptop"),
                    "00:21:70": ("Lenovo", "PC/Laptop"),
                    "00:1D:72": ("Acer", "PC/Laptop"),
                    "00:1E:EC": ("Acer", "PC/Laptop"),
                    "00:1B:44": ("Asus", "PC/Laptop"),
                    "00:1E:8C": ("Asus", "PC/Laptop"),
                    "00:1F:3A": ("MSI", "PC/Laptop"),
                    "00:1A:92": ("Sony", "PC/Laptop"),

                    # Teléfonos / tablets Samsung
                    "B4:B0:24": ("Samsung", "Phone/Tablet"),
                    "F4:09:D8": ("Samsung", "Phone/Tablet"),
                    "C0:BD:D1": ("Samsung", "Phone/Tablet"),
                    "60:03:08": ("Samsung", "Phone/Tablet"),
                    "5C:49:79": ("Samsung", "Phone/Tablet"),
                    "00:16:6C": ("Samsung", "Phone/Tablet"),

                    # Dispositivos Apple
                    "C0:95:6D": ("Apple", "iPhone/iPad/Mac"),
                    "D8:9E:3F": ("Apple", "iPhone/iPad/Mac"),
                    "F0:99:BF": ("Apple", "iPhone/iPad/Mac"),
                    "FC:FC:48": ("Apple", "iPhone/iPad/Mac"),
                    "F0:18:98": ("Apple", "iPhone/iPad/Mac"),
                    "00:0A:95": ("Apple", "iPhone/iPad/Mac"),
                    "00:1E:C2": ("Apple", "iPhone/iPad/Mac"),
                    "00:23:DF": ("Apple", "iPhone/iPad/Mac"),
                    "00:25:00": ("Apple", "iPhone/iPad/Mac"),

                    # Xiaomi / Redmi
                    "18:83:BF": ("Xiaomi", "Phone/IoT"),
                    "64:09:80": ("Xiaomi", "Phone/IoT"),
                    "40:31:3C": ("Xiaomi", "Phone/IoT"),
                    "28:E3:1F": ("Xiaomi", "Phone/IoT"),
                    "F4:8E:38": ("Xiaomi", "Phone/IoT"),

                    # Huawei móviles
                    "00:9A:CD": ("Huawei", "Phone/Tablet"),
                    "00:E0:FC": ("Huawei", "Phone/Tablet"),
                    "00:46:4B": ("Huawei", "Phone/Tablet"),
                    "AC:E2:D3": ("Huawei", "Phone/Tablet"),

                    # OnePlus
                    "00:50:C2": ("OnePlus", "Phone"),
                    "F8:A4:5F": ("OnePlus", "Phone"),

                    # Motorola
                    "00:1A:6B": ("Motorola", "Phone"),
                    "00:1B:77": ("Motorola", "Phone"),

                    # Google / Pixel
                    "00:1A:11": ("Google", "Phone/Tablet"),
                    "F8:8F:CA": ("Google", "Phone/Tablet"),

                    # Impresoras
                    "3C:D9:2B": ("HP", "Printer"),
                    "00:1E:8F": ("Epson", "Printer"),
                    "00:80:77": ("Canon", "Printer"),
                    "00:1B:63": ("Brother", "Printer"),
                    "00:1D:7E": ("Canon", "Printer"),

                    # Smart TVs y dispositivos multimedia
                    "00:1E:3D": ("Samsung", "Smart TV"),
                    "00:1B:98": ("LG", "Smart TV"),
                    "00:1E:75": ("Sony", "Smart TV"),
                    "00:1A:79": ("Panasonic", "Smart TV"),
                    "E8:50:8B": ("Roku", "Streaming Device"),
                    "00:0D:4B": ("Roku", "Streaming Device"),
                    "00:1A:11": ("Google", "Chromecast"),

                    # Consolas de videojuegos
                    "00:1B:DC": ("Sony", "PlayStation"),
                    "00:1F:A7": ("Sony", "PlayStation"),
                    "00:1D:D8": ("Microsoft", "Xbox"),
                    "00:1F:5B": ("Microsoft", "Xbox"),
                    "00:1E:44": ("Nintendo", "Switch/Wii"),

                    # Dispositivos IoT / Smart Home
                    "00:1D:45": ("Amazon", "Echo/IoT"),
                    "00:1E:3A": ("Amazon", "Echo/IoT"),
                    "00:1A:11": ("Google", "Nest/IoT"),
                    "00:1B:63": ("Philips", "Hue/IoT"),

                    # Dispositivos virtuales / desconocidos
                    "42:11:9E": ("Random", "Virtual Device"),
                    "5E:55:48": ("Random", "Virtual Device"),
                    "0A:1B:E2": ("Random", "Virtual Device"),
                    "06:18:8F": ("Random", "Virtual Device"),
                }

                vendor_type = oui_vendor_type_map.get(oui)
                if vendor_type:
                    vendor_name, inferred_type = vendor_type
                    hostname = f"{vendor_name}-{last_octet}"
                    device_type = inferred_type

        return hostname, device_type
    
    def _ip_to_int(self, ip):
        """Convierte IP string a entero"""
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    
    def _int_to_ip(self, ip_int):
        """Convierte entero a IP string"""
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    
    def _netmask_to_cidr(self, netmask):
        """Convierte netmask a notación CIDR (/24, etc)"""
        netmask_int = self._ip_to_int(netmask)
        # Contar bits en 1
        cidr = bin(netmask_int).count('1')
        return cidr
    
    def _calculate_network(self, ip, netmask):
        """Calcula la IP de red a partir de IP y netmask"""
        ip_int = self._ip_to_int(ip)
        netmask_int = self._ip_to_int(netmask)
        network_int = ip_int & netmask_int
        return self._int_to_ip(network_int)
    
    def _parse_network_range(self, network_str):
        """
        Parsea un rango de red (ej: "192.168.1.0/24")
        Retorna (network_ip, cidr)
        """
        if '/' in network_str:
            network_ip, cidr = network_str.split('/')
            return network_ip, int(cidr)
        else:
            # Si no tiene CIDR, asumir /24
            return network_str, 24
    
    def _generate_host_ips(self, network_str):
        """
        Genera todas las IPs de hosts en un rango de red
        Ej: "192.168.1.0/24" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
        """
        network_ip, cidr = self._parse_network_range(network_str)
        network_int = self._ip_to_int(network_ip)
        
        # Calcular máscara
        host_bits = 32 - cidr
        num_hosts = (2 ** host_bits) - 2  # Excluir red y broadcast
        
        # Generar IPs (empezar desde .1, terminar en .254 para /24)
        start_ip = network_int + 1
        end_ip = network_int + num_hosts
        
        for ip_int in range(start_ip, end_ip + 1):
            yield self._int_to_ip(ip_int)
    
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
                            # Calcular la red usando funciones propias
                            network_ip = self._calculate_network(ip, netmask)
                            cidr = self._netmask_to_cidr(netmask)
                            return f"{network_ip}/{cidr}"
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
                    # Actualizar MACs
                    self.learned_macs[ip] = mac_address
                    break
                    
        except Exception as e:
            # Si falla ARP, no es crítico
            pass
    
    def ping_host(self, ip, retries=1):
        """
        Envía un ping ICMP a una IP específica, aprendiendo direcciones MAC
        
        Args:
            ip (str): Dirección IP a hacer ping
            retries (int): Número de reintentos si falla el primer ping (default: 1)
            
        Returns:
            tuple: (ip, latencia_ms) si responde, (ip, None) si no responde
        """
        packets_sent_this_call = 0
        packets_received_this_call = 0
        
        # Intentar múltiples pings para mayor probabilidad de respuesta
        for attempt in range(retries + 1):
            try:
                # Contar paquete enviado
                packets_sent_this_call += 1
                
                # Crear paquete ICMP (siempre a nivel IP)
                packet = IP(dst=ip) / ICMP()
                
                # Enviar paquete y medir tiempo
                start_time = time.time()
                reply = sr1(packet, timeout=self.timeout, verbose=0)
                end_time = time.time()
                
                if reply:
                    latency = (end_time - start_time) * 1000  # Convertir a ms
                    packets_received_this_call = 1
                    
                    # Actualizar estadísticas
                    self.stats['packets_sent'] += packets_sent_this_call
                    self.stats['packets_received'] += 1
                    self.stats['packets_lost'] += (packets_sent_this_call - 1)  # Intentos fallidos anteriores
                    self.stats['total_latency'] += latency
                    self.stats['min_latency'] = min(self.stats['min_latency'], latency)
                    self.stats['max_latency'] = max(self.stats['max_latency'], latency)
                    
                    # Agregar al historial de latencia (máximo 30 valores)
                    self.latency_history[ip].append(latency)
                    if len(self.latency_history[ip]) > 30:
                        self.latency_history[ip].pop(0)
                    
                    # Solo aprender MAC si no la conocemos
                    mac_known = ip in self.learned_macs
                    
                    if not mac_known:
                        self._learn_mac_via_arp(ip)
                    
                    return (ip, latency)
                
                # Si no responde y no es el último intento, esperar un poco
                if attempt < retries:
                    time.sleep(0.1)
                    
            except Exception as e:
                # En caso de error, contar como enviado pero no continuar reintentos
                if attempt < retries:
                    time.sleep(0.1)
                    continue
                break
        
        # Si llegamos aquí, ningún intento tuvo éxito
        self.stats['packets_sent'] += packets_sent_this_call
        self.stats['packets_lost'] += packets_sent_this_call
                    
        return (ip, None)
    
    def scan_network(self):
        """
        Escanea toda la red en busca de hosts activos
        """
        try:
            threads = []
            results = []
            
            def ping_worker(ip_str):
                result = self.ping_host(ip_str)
                if result[1] is not None:  # Si el host responde
                    results.append(result)
            
            # Crear threads para ping paralelo usando generador propio
            for ip in self._generate_host_ips(self.network_range):
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
            
                # Actualizar hosts activos
                current_time = time.time()
                for ip, latency in results:
                    # Resolver hostname y tipo si es nuevo
                    if ip not in self.host_info:
                        hostname, device_type = self._resolve_hostname_and_type(ip)
                        self.host_info[ip] = {
                            'hostname': hostname,
                            'device_type': device_type
                        }
                    
                    host_info = {
                        'latency': latency,
                        'last_seen': current_time,
                        'angle': hash(ip) % 360  # Asignar ángulo único basado en IP
                    }
                    
                    self.active_hosts[ip] = host_info
                    # Si vuelve a estar online, quitarlo de offline
                    if ip in self.offline_hosts:
                        del self.offline_hosts[ip]
                    
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
                            
                        result = self.ping_host(ip, retries=0)  # Sin reintentos en ping continuo
                        
                        if result[1] is not None:  # Si responde
                            # Actualizar información del host
                            current_time = time.time()
                            existing_angle = self.active_hosts.get(ip, {}).get('angle', hash(ip) % 360)
                            self.active_hosts[ip] = {
                                'latency': result[1],
                                'last_seen': current_time,
                                'angle': existing_angle
                            }
                            # Si vuelve a estar online, quitarlo de offline
                            if ip in self.offline_hosts:
                                del self.offline_hosts[ip]
                        
                        # Pequeña pausa entre pings para no saturar
                        time.sleep(0.1)
                    
                    # Pausa antes del siguiente ciclo de ping continuo
                    time.sleep(5)  # Ping continuo cada 5 segundos (reducido de 2s)
                    
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
        Retorna las MACs aprendidas
        """
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
                    
                    # Identificar hosts expirados
                    for ip, info in list(self.active_hosts.items()):
                        if current_time - info['last_seen'] > self.host_persistence:
                            expired_hosts.append(ip)
                    
                    # Remover hosts expirados y moverlos a offline
                    for ip in expired_hosts:
                        if ip in self.active_hosts:
                            # Guardar en offline_hosts con timestamp
                            self.offline_hosts[ip] = {
                                'last_seen': self.active_hosts[ip]['last_seen'],
                                'went_offline': current_time,
                                'last_latency': self.active_hosts[ip].get('latency', 0)
                            }
                            del self.active_hosts[ip]
                    
                    # Limpiar hosts conocidos también
                    if expired_hosts:
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
        Retorna la lista de hosts activos
        
        Returns:
            dict: Diccionario con hosts activos {ip: {latency, last_seen, angle}}
        """
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
    
    def get_statistics(self):
        """
        Retorna estadísticas globales de la red
        
        Returns:
            dict: Diccionario con estadísticas
        """
        stats_copy = self.stats.copy()
        
        # Calcular métricas derivadas
        if stats_copy['packets_sent'] > 0:
            stats_copy['packet_loss_rate'] = (stats_copy['packets_lost'] / stats_copy['packets_sent']) * 100
        else:
            stats_copy['packet_loss_rate'] = 0.0
        
        if stats_copy['packets_received'] > 0:
            stats_copy['avg_latency'] = stats_copy['total_latency'] / stats_copy['packets_received']
        else:
            stats_copy['avg_latency'] = 0.0
        
        # Calcular throughput (paquetes por segundo)
        elapsed_time = time.time() - stats_copy['start_time']
        if elapsed_time > 0:
            stats_copy['throughput'] = stats_copy['packets_sent'] / elapsed_time
        else:
            stats_copy['throughput'] = 0.0
        
        return stats_copy
    
    def get_offline_hosts(self):
        """
        Retorna la lista de hosts offline
        
        Returns:
            dict: Diccionario con hosts offline {ip: {last_seen, went_offline, last_latency}}
        """
        return self.offline_hosts.copy()
    
    def get_latency_history(self, ip):
        """
        Retorna el historial de latencia de un host específico
        
        Args:
            ip (str): Dirección IP del host
            
        Returns:
            list: Lista de latencias (últimas 30)
        """
        return self.latency_history.get(ip, []).copy()
    
    def get_host_info(self, ip):
        """
        Retorna información del host (hostname y tipo de dispositivo)
        
        Args:
            ip (str): Dirección IP del host
            
        Returns:
            dict: {'hostname': str, 'device_type': str} o None
        """
        return self.host_info.get(ip, None)
    
    def send_custom_icmp(self, ip, icmp_type=8, icmp_code=0, payload_size=32):
        """
        Envía un paquete ICMP personalizado
        
        Args:
            ip (str): IP destino
            icmp_type (int): Tipo de ICMP
                8 = Echo Request (ping normal)
            icmp_code (int): Código ICMP (normalmente 0)
            payload_size (int): Tamaño del payload en bytes
            
        Returns:
            tuple: (respuesta, latencia_ms) o (None, None) si no responde
        """
        try:
            # Actualizar estadísticas
            self.stats['packets_sent'] += 1
            
            # Crear payload
            payload = b'X' * payload_size
            
            # Crear paquete ICMP personalizado
            if icmp_type == 8:  # Echo Request
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code) / payload
        
            # Enviar y medir
            start_time = time.time()
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            end_time = time.time()
            
            if reply:
                latency = (end_time - start_time) * 1000
                
                # Actualizar estadísticas
                self.stats['packets_received'] += 1
                self.stats['total_latency'] += latency
                
                return (reply, latency)
            else:
                # Paquete perdido
                self.stats['packets_lost'] += 1
                return (None, None)
                
        except Exception as e:
            self.stats['packets_lost'] += 1
            return (None, None)
    
    def detect_anomalies(self):
        """
        Detecta anomalías en la red (latencia alta, jitter, hosts offline)
        
        Returns:
            dict: Diccionario con anomalías detectadas por tipo
        """
        anomalies = {
            'high_latency': [],
            'high_jitter': [],
            'packet_loss': [],
            'recently_offline': []
        }
        
        # Calcular latencia promedio global
        all_latencies = []
        for history in self.latency_history.values():
            all_latencies.extend(history)
        
        if all_latencies:
            global_avg = sum(all_latencies) / len(all_latencies)
        else:
            global_avg = 0
        
        # Detectar hosts con latencia alta
        for ip, info in self.active_hosts.items():
            current_latency = info.get('latency', 0)
            
            # Latencia alta: más del doble del promedio global o > 100ms
            if current_latency > global_avg * 2 or current_latency > 100:
                anomalies['high_latency'].append({
                    'ip': ip,
                    'latency': current_latency,
                    'threshold': max(global_avg * 2, 100)
                })
            
            # Detectar jitter alto (variación de latencia)
            if ip in self.latency_history and len(self.latency_history[ip]) >= 5:
                history = self.latency_history[ip]
                avg_lat = sum(history) / len(history)
                variance = sum((x - avg_lat) ** 2 for x in history) / len(history)
                std_dev = variance ** 0.5
                
                # Jitter alto: desviación estándar > 30ms
                if std_dev > 30:
                    anomalies['high_jitter'].append({
                        'ip': ip,
                        'jitter': std_dev,
                        'avg_latency': avg_lat
                    })
        
        # Hosts recientemente offline (últimos 60 segundos)
        current_time = time.time()
        for ip, info in self.offline_hosts.items():
            if current_time - info['went_offline'] < 60:
                anomalies['recently_offline'].append({
                    'ip': ip,
                    'offline_since': info['went_offline'],
                    'last_latency': info['last_latency']
                })
        
        return anomalies

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

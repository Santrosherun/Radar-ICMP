import time
import threading
from scapy.all import IP, ICMP, sr1, conf
import psutil
import ipaddress
import warnings
from threading import Lock, RLock
from collections import defaultdict
import queue
import socket

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
        self.offline_hosts = {}  # Hosts que estuvieron online pero ahora están offline
        
        # Locks para thread safety
        self.hosts_lock = RLock()
        self.macs_lock = RLock()
        self.known_hosts_lock = RLock()
        self.stats_lock = RLock()
        
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
        hostname = None
        device_type = "Device"
        
        # Intentar resolver hostname vía DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            # Si falla DNS, usar identificador de IP
            last_octet = ip.split('.')[-1]
            if last_octet == '1' or last_octet == '254':
                hostname = "Gateway"
            else:
                hostname = f"Host-{last_octet}"
        
        # Detectar tipo de dispositivo basado en hostname
        hostname_lower = hostname.lower()
        
        # Móviles Android
        if any(x in hostname_lower for x in ['android', 'samsung', 'galaxy', 'xiaomi', 'huawei', 
                                               'motorola', 'oppo', 'vivo', 'realme', 'oneplus', 
                                               'pixel', 'redmi', 'poco']):
            device_type = "📱 Android"
        
        # Dispositivos Apple
        elif any(x in hostname_lower for x in ['iphone', 'ipad', 'apple', 'macbook', 'imac', 
                                                 'airpods', 'watch', 'appletv']):
            device_type = "🍎 Apple"
        
        # Routers y gateways
        elif any(x in hostname_lower for x in ['router', 'gateway', 'modem', 'ap-', 'access-point',
                                                 'tp-link', 'tplink', 'asus', 'netgear', 'linksys',
                                                 'dlink', 'd-link', 'mercusys']):
            device_type = "🌐 Router"
        
        # PCs Windows
        elif any(x in hostname_lower for x in ['desktop', 'pc-', 'windows', 'win-', 'laptop']):
            device_type = "💻 Windows PC"
        
        # Smart TVs
        elif any(x in hostname_lower for x in ['tv', 'smarttv', 'chromecast', 'roku', 'firestick']):
            device_type = "📺 Smart TV"
        
        # Impresoras
        elif any(x in hostname_lower for x in ['printer', 'print', 'hp-', 'canon', 'epson', 'brother']):
            device_type = "🖨️ Printer"
        
        # Consolas
        elif any(x in hostname_lower for x in ['playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch']):
            device_type = "🎮 Console"
        
        # Smart Home / IoT
        elif any(x in hostname_lower for x in ['alexa', 'echo', 'nest', 'ring', 'camera', 'cam-',
                                                 'smart', 'iot-', 'sensor']):
            device_type = "🏠 IoT"
        
        # Por IP común
        elif ip.endswith('.1') or ip.endswith('.254'):
            device_type = "🌐 Gateway"
        
        return hostname, device_type
    
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
                    
                    # Actualizar estadísticas en un solo lock
                    with self.stats_lock:
                        self.stats['packets_sent'] += packets_sent_this_call
                        self.stats['packets_received'] += 1
                        self.stats['packets_lost'] += (packets_sent_this_call - 1)  # Intentos fallidos anteriores
                        self.stats['total_latency'] += latency
                        self.stats['min_latency'] = min(self.stats['min_latency'], latency)
                        self.stats['max_latency'] = max(self.stats['max_latency'], latency)
                    
                    # Agregar al historial de latencia (máximo 30 valores)
                    with self.hosts_lock:
                        self.latency_history[ip].append(latency)
                        if len(self.latency_history[ip]) > 30:
                            self.latency_history[ip].pop(0)
                    
                    # Solo aprender MAC si no la conocemos
                    with self.macs_lock:
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
        with self.stats_lock:
            self.stats['packets_sent'] += packets_sent_this_call
            self.stats['packets_lost'] += packets_sent_this_call
                    
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
                    # Resolver hostname y tipo si es nuevo
                    if ip not in self.host_info:
                        hostname, device_type = self._resolve_hostname_and_type(ip)
                        with self.hosts_lock:
                            self.host_info[ip] = {
                                'hostname': hostname,
                                'device_type': device_type
                            }
                    
                    host_info = {
                        'latency': latency,
                        'last_seen': current_time,
                        'angle': hash(ip) % 360  # Asignar ángulo único basado en IP
                    }
                    
                    with self.hosts_lock:
                        self.active_hosts[ip] = host_info
                        # Si vuelve a estar online, quitarlo de offline
                        if ip in self.offline_hosts:
                            del self.offline_hosts[ip]
                    
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
                            
                        result = self.ping_host(ip, retries=0)  # Sin reintentos en ping continuo
                        
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
    
    def get_statistics(self):
        """
        Retorna estadísticas globales de la red
        
        Returns:
            dict: Diccionario con estadísticas
        """
        with self.stats_lock:
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
        with self.hosts_lock:
            return self.offline_hosts.copy()
    
    def get_latency_history(self, ip):
        """
        Retorna el historial de latencia de un host específico
        
        Args:
            ip (str): Dirección IP del host
            
        Returns:
            list: Lista de latencias (últimas 30)
        """
        with self.hosts_lock:
            return self.latency_history.get(ip, []).copy()
    
    def get_host_info(self, ip):
        """
        Retorna información del host (hostname y tipo de dispositivo)
        
        Args:
            ip (str): Dirección IP del host
            
        Returns:
            dict: {'hostname': str, 'device_type': str} o None
        """
        with self.hosts_lock:
            return self.host_info.get(ip, None)
    
    def send_custom_icmp(self, ip, icmp_type=8, icmp_code=0, payload_size=32):
        """
        Envía un paquete ICMP personalizado
        
        Args:
            ip (str): IP destino
            icmp_type (int): Tipo de ICMP
                8 = Echo Request (ping normal)
                13 = Timestamp Request
                15 = Information Request
                17 = Address Mask Request
            icmp_code (int): Código ICMP (normalmente 0)
            payload_size (int): Tamaño del payload en bytes
            
        Returns:
            tuple: (respuesta, latencia_ms) o (None, None) si no responde
        """
        try:
            # Actualizar estadísticas
            with self.stats_lock:
                self.stats['packets_sent'] += 1
            
            # Crear payload
            payload = b'X' * payload_size
            
            # Crear paquete ICMP personalizado
            if icmp_type == 8:  # Echo Request
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code) / payload
            elif icmp_type == 13:  # Timestamp Request
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
            elif icmp_type == 15:  # Information Request
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
            elif icmp_type == 17:  # Address Mask Request
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
            else:
                packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code) / payload
            
            # Enviar y medir
            start_time = time.time()
            reply = sr1(packet, timeout=self.timeout, verbose=0)
            end_time = time.time()
            
            if reply:
                latency = (end_time - start_time) * 1000
                
                # Actualizar estadísticas
                with self.stats_lock:
                    self.stats['packets_received'] += 1
                    self.stats['total_latency'] += latency
                
                return (reply, latency)
            else:
                # Paquete perdido
                with self.stats_lock:
                    self.stats['packets_lost'] += 1
                return (None, None)
                
        except Exception as e:
            with self.stats_lock:
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
        
        with self.hosts_lock:
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

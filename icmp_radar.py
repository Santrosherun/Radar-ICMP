#!/usr/bin/env python3
import sys
import time
import threading
import argparse
import pygame
import warnings
import logging
from icmp_scanner import ICMPScanner
from radar_display import RadarDisplay

# Suprimir warnings de Scapy threading en Windows
warnings.filterwarnings("ignore", category=RuntimeWarning, module="scapy")
logging.getLogger("scapy").setLevel(logging.ERROR)

# Manejador global para excepciones en threads
def handle_thread_exception(args):
    """Maneja excepciones silenciosamente en threads de Scapy"""
    if "scapy" in str(args.exc_traceback) or "_sndrcv_snd" in str(args.thread):
        pass  # Ignorar errores conocidos de Scapy
    else:
        # Solo mostrar errores no relacionados con Scapy
        print(f"[THREAD-ERROR] {args.exc_type.__name__}: {args.exc_value}")

threading.excepthook = handle_thread_exception

class ICMPRadarApp:
    def __init__(self, network_range=None, scan_interval=3, window_size=(1400, 800)):
        """
        Inicializa la aplicación ICMP Radar
        
        Args:
            network_range (str): Rango de red a escanear (None para auto-detectar)
            scan_interval (int): Intervalo entre escaneos en segundos
            window_size (tuple): Tamaño de la ventana (ancho, alto)
        """
        self.network_range = network_range
        self.scan_interval = scan_interval
        
        # Inicializar componentes
        self.scanner = ICMPScanner(timeout=0.5, host_persistence=30)
        self.radar = RadarDisplay(window_size[0], window_size[1])
        
        # Variables de estado
        self.running = False
        self.scan_status = "Inicializando"
        self.last_scan_time = 0
        
        # Cache para optimización de rendimiento
        self.cached_anomalies = {}
        self.last_anomaly_check = 0
        
        # Configurar red
        self._setup_network()
    
    def _setup_network(self):
        """
        Configura el rango de red a escanear
        """
        if self.network_range:
            self.scanner.network_range = self.network_range
            self.scan_status = f"Red configurada: {self.network_range}"
        else:
            # Auto-detectar red local
            detected_network = self.scanner.get_local_network()
            self.scanner.network_range = detected_network
            self.scan_status = f"Red detectada: {detected_network}"
        
        print(f"[NETWORK] {self.scan_status}")
    
    def start_scanning(self):
        """
        Inicia el escaneo continuo en segundo plano
        """
        def scan_worker():
            while self.running:
                try:
                    self.scan_status = "Escaneando..."
                    start_time = time.time()
                    
                    # Realizar escaneo
                    self.scanner.scan_network()
                    
                    scan_duration = time.time() - start_time
                    self.last_scan_time = time.time()
                    
                    hosts_found = len(self.scanner.get_active_hosts())
                    macs_learned = self.scanner.get_learned_macs_count()
                    self.scan_status = f"Completado - {hosts_found} hosts, {macs_learned} MACs ({scan_duration:.1f}s)"
                    
                    # Esperar antes del próximo escaneo
                    time.sleep(self.scan_interval)
                    
                except Exception as e:
                    self.scan_status = f"Error: {str(e)}"
                    time.sleep(2)
        
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
    
    def run(self):
        """
        Ejecuta el bucle principal de la aplicación
        """
        print("[START] Iniciando ICMP Radar...")
        print("[INFO] Presiona ESC o cierra la ventana para salir")
        
        # Verificar permisos
        if not self._check_permissions():
            return
        
        self.running = True
        
        try:
            # Iniciar todos los threads de escaneo
            self.start_scanning()
            self.scanner.start_continuous_ping()
            self.scanner.start_cleanup_thread()
            
            # Bucle principal de visualización
            clock = pygame.time.Clock()
            
            while self.running:
                # Manejar eventos de Pygame (pasar scanner para paquetes personalizados)
                if not self.radar.handle_events(self.scanner):
                    break
                
                # Obtener hosts activos y MACs aprendidas (thread-safe)
                active_hosts = self.scanner.get_active_hosts()
                learned_macs = self.scanner.get_learned_macs()
                offline_hosts = self.scanner.get_offline_hosts()
                statistics = self.scanner.get_statistics()
                
                # Detectar anomalías solo cada 2 segundos (optimización de FPS)
                current_time = time.time()
                if current_time - self.last_anomaly_check >= 2.0:
                    self.cached_anomalies = self.scanner.detect_anomalies()
                    self.last_anomaly_check = current_time
                
                # Actualizar visualización con nuevos parámetros
                self.radar.update_display(
                    active_hosts=active_hosts,
                    statistics=statistics,
                    offline_hosts=offline_hosts,
                    anomalies=self.cached_anomalies,
                    learned_macs=learned_macs,
                    scanner=self.scanner
                )
                
                # Control preciso de FPS
                clock.tick(60)  # 60 FPS exactos
        
        except KeyboardInterrupt:
            print("\n[STOP] Deteniendo aplicación...")
        
        except Exception as e:
            print(f"[ERROR] Error inesperado: {e}")
        
        finally:
            self.cleanup()
    
    def _check_permissions(self):
        """
        Verifica si tenemos permisos para enviar paquetes ICMP
        
        Returns:
            bool: True si tenemos permisos, False en caso contrario
        """
        try:
            # Intentar un ping de prueba
            test_result = self.scanner.ping_host("127.0.0.1")
            if test_result[1] is not None:
                print("[OK] Permisos ICMP verificados")
                return True
            else:
                print("[ERROR] No se pudieron enviar paquetes ICMP")
                print("[TIP] Ejecuta como administrador/root para usar ICMP")
                return False
        
        except Exception as e:
            print(f"[ERROR] Error verificando permisos: {e}")
            print("[TIP] Asegurate de ejecutar como administrador/root")
            return False
    
    def cleanup(self):
        """
        Limpia recursos y termina la aplicación
        """
        print("[CLEANUP] Limpiando recursos...")
        
        self.running = False
        
        # Detener escaneo
        if hasattr(self, 'scanner'):
            self.scanner.stop_scan()
        
        # Limpiar Pygame
        if hasattr(self, 'radar'):
            self.radar.cleanup()
        
        print("[OK] Aplicación terminada correctamente")

def main():
    """
    Función principal con argumentos de línea de comandos
    """
    parser = argparse.ArgumentParser(
        description="ICMP Radar - Visualización de Red en Tiempo Real",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python icmp_radar.py                          # Auto-detectar red local
  python icmp_radar.py -n 192.168.1.0/24       # Escanear red específica
  python icmp_radar.py -i 5 -s 1000x800        # Intervalo 5s, ventana 1000x800
  
Nota: Requiere permisos de administrador para enviar paquetes ICMP
        """
    )
    
    parser.add_argument(
        "-n", "--network",
        help="Rango de red a escanear (ej: 192.168.1.0/24)",
        default=None
    )
    
    parser.add_argument(
        "-i", "--interval",
        type=float,
        help="Intervalo entre escaneos en segundos (default: 3.0)",
        default=3.0
    )
    
    parser.add_argument(
        "-s", "--size",
        help="Tamaño de ventana WIDTHxHEIGHT (default: 1400x800)",
        default="1400x800"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Mostrar información detallada"
    )
    
    parser.add_argument(
        "-p", "--persist",
        type=int,
        help="Tiempo de persistencia de hosts en segundos (default: 30)",
        default=30
    )
    
    args = parser.parse_args()
    
    # Parsear tamaño de ventana
    try:
        width, height = map(int, args.size.split('x'))
        window_size = (width, height)
    except ValueError:
        print("[ERROR] Formato de tamaño invalido. Usa WIDTHxHEIGHT (ej: 800x600)")
        return 1
    
    # Mostrar información si es verbose
    if args.verbose:
        print("[CONFIG] Configuracion:")
        print(f"   Red: {args.network or 'Auto-detectar'}")
        print(f"   Intervalo: {args.interval}s")
        print(f"   Persistencia: {args.persist}s")
        print(f"   Ventana: {window_size[0]}x{window_size[1]}")
        print()
    
    # Crear y ejecutar aplicación
    try:
        app = ICMPRadarApp(
            network_range=args.network,
            scan_interval=args.interval,
            window_size=window_size
        )
        
        # Configurar tiempo de persistencia
        app.scanner.host_persistence = args.persist
        
        app.run()
        return 0
    
    except KeyboardInterrupt:
        print("\n[STOP] Aplicacion interrumpida por el usuario")
        return 0
    
    except Exception as e:
        print(f"[FATAL] Error fatal: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

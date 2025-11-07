import pygame
import math
import time
from typing import Dict, Tuple

class RadarDisplay:
    def __init__(self, width=800, height=600):
        """
        Inicializa la pantalla del radar
        
        Args:
            width (int): Ancho de la ventana
            height (int): Alto de la ventana
        """
        pygame.init()
        
        self.width = width
        self.height = height
        self.screen = pygame.display.set_mode((width, height))
        pygame.display.set_caption("ICMP Radar - Descubrimiento de Red")
        
        # Centro del radar
        self.center_x = width // 2
        self.center_y = height // 2
        self.max_radius = min(width, height) // 2 - 50
        
        # Colores
        self.BLACK = (0, 0, 0)
        self.GREEN = (0, 255, 0)
        self.DARK_GREEN = (0, 100, 0)
        self.BRIGHT_GREEN = (0, 255, 100)
        self.RED = (255, 0, 0)
        self.YELLOW = (255, 255, 0)
        self.WHITE = (255, 255, 255)
        self.GRAY = (128, 128, 128)
        
        # Variables de animación
        self.sweep_angle = 0
        self.sweep_speed = 2  # Grados por frame
        self.last_sweep_time = time.time()
        
        # Fuentes
        self.font_small = pygame.font.Font(None, 24)
        self.font_medium = pygame.font.Font(None, 32)
        self.font_large = pygame.font.Font(None, 48)
        
        # Efectos visuales
        self.sweep_trail = []  # Para el efecto de estela del barrido
        self.host_pulses = {}  # Para el efecto de pulso en hosts detectados
        self.host_positions = {}  # Para tracking de posiciones de hosts (hover)
        
        # Sistema de hover
        self.mouse_pos = (0, 0)
        self.hovered_host = None
        
        # Clock para controlar FPS
        self.clock = pygame.time.Clock()
        
        # Cache para optimización
        self.last_hosts_hash = None
        self.cached_surface = None
        
    def draw_radar_grid(self):
        """
        Dibuja la cuadrícula circular del radar
        """
        # Círculos concéntricos
        for i in range(1, 5):
            radius = (self.max_radius * i) // 4
            pygame.draw.circle(self.screen, self.DARK_GREEN, 
                             (self.center_x, self.center_y), radius, 1)
        
        # Líneas radiales (cada 30 grados)
        for angle in range(0, 360, 30):
            end_x = self.center_x + self.max_radius * math.cos(math.radians(angle))
            end_y = self.center_y + self.max_radius * math.sin(math.radians(angle))
            pygame.draw.line(self.screen, self.DARK_GREEN,
                           (self.center_x, self.center_y), (end_x, end_y), 1)
        
        # Círculo exterior
        pygame.draw.circle(self.screen, self.GREEN, 
                         (self.center_x, self.center_y), self.max_radius, 2)
    
    def draw_sweep_line(self):
        """
        Versión optimizada de la línea de barrido (sin estela para mejor rendimiento)
        """
        # Actualizar ángulo de barrido
        self.sweep_angle = (self.sweep_angle + self.sweep_speed) % 360
        
        # Solo dibujar línea principal (sin estela para mejor rendimiento)
        end_x = self.center_x + self.max_radius * math.cos(math.radians(self.sweep_angle))
        end_y = self.center_y + self.max_radius * math.sin(math.radians(self.sweep_angle))
        pygame.draw.line(self.screen, self.BRIGHT_GREEN,
                        (self.center_x, self.center_y), (end_x, end_y), 2)
    
    def latency_to_radius(self, latency_ms):
        """
        Convierte latencia en milisegundos a radio en el radar
        
        Args:
            latency_ms (float): Latencia en milisegundos
            
        Returns:
            int: Radio en píxeles desde el centro
        """
        # Mapear latencia (0-100ms) a radio (20% - 90% del radio máximo)
        min_radius = self.max_radius * 0.2
        max_radius = self.max_radius * 0.9
        
        # Normalizar latencia (máximo 100ms)
        normalized_latency = min(latency_ms / 100.0, 1.0)
        
        return int(min_radius + (max_radius - min_radius) * normalized_latency)
    
    def get_host_byte(self, ip):
        """
        Extrae solo el último byte de la IP para mostrar
        
        Args:
            ip (str): Dirección IP completa
            
        Returns:
            str: Último octeto de la IP (ej: "157" de "192.168.20.157")
        """
        return ip.split('.')[-1]
    
    def get_device_info(self, ip, mac_address=None):
        """
        Determina el tipo de dispositivo basado en IP y MAC
        
        Args:
            ip (str): Dirección IP
            mac_address (str): Dirección MAC (opcional)
            
        Returns:
            tuple: (nombre_sugerido, tipo_dispositivo)
        """
        host_byte = self.get_host_byte(ip)
        
        # Identificar por IP común
        if host_byte == "1":
            return ("Gateway", "Router")
        elif host_byte in ["254", "253", "252"]:
            return ("Router", "Network Device")
        elif mac_address:
            # Identificar por OUI (primeros 3 bytes de MAC)
            oui = mac_address[:8].upper()
            oui_map = {
                "14:82:5B": ("TP-Link", "Router/AP"),
                "58:6C:25": ("Intel", "PC/Laptop"),
                "B4:B0:24": ("Samsung", "Phone/Tablet"),
                "C0:95:6D": ("Apple", "iPhone/iPad"),
                "18:83:BF": ("Xiaomi", "Phone/IoT"),
                "42:11:9E": ("Random", "Virtual Device"),
                "5E:55:48": ("Random", "Virtual Device"),
                "0A:1B:E2": ("Random", "Virtual Device"),
                "06:18:8F": ("Random", "Virtual Device")
            }
            
            if oui in oui_map:
                return oui_map[oui]
        
        # Fallback genérico
        return (f"Host-{host_byte}", "Network Device")
    
    def draw_host(self, ip, angle, latency_ms, is_recently_detected=False, mac_address=None):
        """
        Dibuja un host detectado en el radar
        
        Args:
            ip (str): Dirección IP del host
            angle (float): Ángulo en grados
            latency_ms (float): Latencia en milisegundos
            is_recently_detected (bool): Si fue detectado recientemente
            mac_address (str): Dirección MAC del host (opcional)
        """
        radius = self.latency_to_radius(latency_ms)
        
        # Calcular posición
        x = self.center_x + radius * math.cos(math.radians(angle))
        y = self.center_y + radius * math.sin(math.radians(angle))
        
        # Efecto de pulso para hosts recién detectados
        pulse_size = 6  # Reducido de 8 a 6
        if is_recently_detected:
            if ip not in self.host_pulses:
                self.host_pulses[ip] = time.time()
            
            pulse_age = time.time() - self.host_pulses[ip]
            if pulse_age < 2.0:  # Pulso dura 2 segundos
                pulse_intensity = 1.0 - (pulse_age / 2.0)
                pulse_size = int(6 + 8 * pulse_intensity)  # Reducido
        
        # Color basado en latencia
        if latency_ms < 10:
            color = self.GREEN
        elif latency_ms < 50:
            color = self.YELLOW
        else:
            color = self.RED
        
        # Dibujar punto del host
        pygame.draw.circle(self.screen, color, (int(x), int(y)), pulse_size)
        pygame.draw.circle(self.screen, self.WHITE, (int(x), int(y)), pulse_size, 2)
        
        # Etiqueta compacta con solo el byte de host
        host_byte = self.get_host_byte(ip)
        label = f".{host_byte}\n{latency_ms:.0f}ms"  # Sin decimales para ser más compacto
        lines = label.split('\n')
        
        for i, line in enumerate(lines):
            text_surface = self.font_small.render(line, True, self.WHITE)
            text_rect = text_surface.get_rect()
            text_rect.centerx = int(x)
            text_rect.centery = int(y) + 12 + (i * 16)  # Más compacto
            
            # Fondo semi-transparente para el texto
            bg_surface = pygame.Surface((text_rect.width + 2, text_rect.height + 1), pygame.SRCALPHA)
            bg_surface.fill((0, 0, 0, 128))
            self.screen.blit(bg_surface, (text_rect.x - 1, text_rect.y))
            self.screen.blit(text_surface, text_rect)
        
        # Guardar información del host para hover
        self.host_positions[ip] = {
            'x': int(x),
            'y': int(y),
            'radius': pulse_size + 5,  # Área de hover un poco más grande
            'mac': mac_address,
            'latency': latency_ms
        }
    
    def draw_host_optimized(self, ip, angle, latency_ms, is_recently_detected=False, mac_address=None):
        """
        Versión optimizada de draw_host con menos operaciones gráficas
        """
        radius = self.latency_to_radius(latency_ms)
        
        # Calcular posición
        x = self.center_x + radius * math.cos(math.radians(angle))
        y = self.center_y + radius * math.sin(math.radians(angle))
        
        # Tamaño simplificado (sin pulso para mejor rendimiento)
        pulse_size = 5
        
        # Color basado en latencia
        if latency_ms < 10:
            color = self.GREEN
        elif latency_ms < 50:
            color = self.YELLOW
        else:
            color = self.RED
        
        # Dibujar solo el punto principal (sin borde para mejor rendimiento)
        pygame.draw.circle(self.screen, color, (int(x), int(y)), pulse_size)
        
        # Etiqueta simplificada (solo si está cerca del mouse para mejor rendimiento)
        mouse_distance = math.sqrt((self.mouse_pos[0] - x)**2 + (self.mouse_pos[1] - y)**2)
        if mouse_distance < 50:  # Solo mostrar etiqueta si mouse está cerca
            host_byte = self.get_host_byte(ip)
            text_surface = self.font_small.render(f".{host_byte}", True, self.WHITE)
            text_rect = text_surface.get_rect()
            text_rect.centerx = int(x)
            text_rect.centery = int(y) + 12
            self.screen.blit(text_surface, text_rect)
        
        # Guardar información del host para hover
        self.host_positions[ip] = {
            'x': int(x),
            'y': int(y),
            'radius': pulse_size + 5,
            'mac': mac_address,
            'latency': latency_ms
        }
    
    def draw_info_panel(self, active_hosts_count, scan_status):
        """
        Dibuja panel de información en la esquina
        
        Args:
            active_hosts_count (int): Número de hosts activos
            scan_status (str): Estado del escaneo
        """
        # Panel de información
        panel_width = 250
        panel_height = 120
        panel_x = self.width - panel_width - 10
        panel_y = 10
        
        # Fondo del panel
        panel_surface = pygame.Surface((panel_width, panel_height), pygame.SRCALPHA)
        panel_surface.fill((0, 0, 0, 180))
        self.screen.blit(panel_surface, (panel_x, panel_y))
        
        # Borde del panel
        pygame.draw.rect(self.screen, self.GREEN, 
                        (panel_x, panel_y, panel_width, panel_height), 2)
        
        # Información
        info_lines = [
            "ICMP RADAR",
            f"Hosts Activos: {active_hosts_count}",
            f"Estado: {scan_status}",
            f"Barrido: {self.sweep_angle:.0f}°"
        ]
        
        for i, line in enumerate(info_lines):
            font = self.font_medium if i == 0 else self.font_small
            color = self.BRIGHT_GREEN if i == 0 else self.WHITE
            
            text_surface = font.render(line, True, color)
            self.screen.blit(text_surface, (panel_x + 10, panel_y + 10 + i * 25))
    
    def draw_legend(self):
        """
        Dibuja la leyenda del radar
        """
        legend_x = 10
        legend_y = self.height - 100
        
        # Fondo de la leyenda
        legend_surface = pygame.Surface((200, 90), pygame.SRCALPHA)
        legend_surface.fill((0, 0, 0, 180))
        self.screen.blit(legend_surface, (legend_x, legend_y))
        
        # Borde
        pygame.draw.rect(self.screen, self.GREEN, 
                        (legend_x, legend_y, 200, 90), 2)
        
        # Elementos de la leyenda
        legend_items = [
            ("Latencia:", None),
            ("< 10ms", self.GREEN),
            ("10-50ms", self.YELLOW),
            ("> 50ms", self.RED)
        ]
        
        for i, (text, color) in enumerate(legend_items):
            if color:
                pygame.draw.circle(self.screen, color, 
                                 (legend_x + 20, legend_y + 15 + i * 18), 6)
            
            text_surface = self.font_small.render(text, True, self.WHITE)
            self.screen.blit(text_surface, (legend_x + 35, legend_y + 10 + i * 18))
    
    def check_hover(self, mouse_pos):
        """
        Verifica si el mouse está sobre algún host
        
        Args:
            mouse_pos (tuple): Posición del mouse (x, y)
            
        Returns:
            str: IP del host bajo el mouse, o None
        """
        for ip, pos_info in self.host_positions.items():
            distance = math.sqrt((mouse_pos[0] - pos_info['x'])**2 + 
                               (mouse_pos[1] - pos_info['y'])**2)
            if distance <= pos_info['radius']:
                return ip
        return None
    
    def draw_hover_info(self, ip, learned_macs):
        """
        Dibuja información detallada del host en hover
        
        Args:
            ip (str): IP del host
            learned_macs (dict): Diccionario de MACs aprendidas
        """
        if ip not in self.host_positions:
            return
            
        pos_info = self.host_positions[ip]
        mac_address = learned_macs.get(ip)
        
        # Obtener información del dispositivo
        device_name, device_type = self.get_device_info(ip, mac_address)
        
        # Crear panel de información
        info_lines = [
            f"IP: {ip}",
            f"Host: .{self.get_host_byte(ip)}",
            f"Latencia: {pos_info['latency']:.1f}ms",
            f"Dispositivo: {device_name}",
            f"Tipo: {device_type}"
        ]
        
        if mac_address:
            info_lines.append(f"MAC: {mac_address}")
        
        # Calcular tamaño del panel
        max_width = 0
        line_height = 18
        for line in info_lines:
            text_surface = self.font_small.render(line, True, self.WHITE)
            max_width = max(max_width, text_surface.get_width())
        
        panel_width = max_width + 20
        panel_height = len(info_lines) * line_height + 10
        
        # Posicionar panel cerca del host pero visible
        panel_x = pos_info['x'] + 20
        panel_y = pos_info['y'] - panel_height // 2
        
        # Ajustar si se sale de la pantalla
        if panel_x + panel_width > self.width:
            panel_x = pos_info['x'] - panel_width - 20
        if panel_y < 0:
            panel_y = 10
        if panel_y + panel_height > self.height:
            panel_y = self.height - panel_height - 10
        
        # Dibujar fondo del panel
        panel_surface = pygame.Surface((panel_width, panel_height), pygame.SRCALPHA)
        panel_surface.fill((0, 0, 0, 200))
        self.screen.blit(panel_surface, (panel_x, panel_y))
        
        # Dibujar borde
        pygame.draw.rect(self.screen, self.BRIGHT_GREEN, 
                        (panel_x, panel_y, panel_width, panel_height), 2)
        
        # Dibujar líneas de información
        for i, line in enumerate(info_lines):
            color = self.BRIGHT_GREEN if i == 0 else self.WHITE
            text_surface = self.font_small.render(line, True, color)
            self.screen.blit(text_surface, (panel_x + 10, panel_y + 5 + i * line_height))
    
    def update_display(self, active_hosts, scan_status="Escaneando", learned_macs=None):
        """
        Actualiza toda la pantalla del radar
        
        Args:
            active_hosts (dict): Diccionario de hosts activos
            scan_status (str): Estado del escaneo
            learned_macs (dict): Diccionario de MACs aprendidas
        """
        if learned_macs is None:
            learned_macs = {}
            
        # Actualizar posición del mouse
        self.mouse_pos = pygame.mouse.get_pos()
        
        # Limpiar pantalla
        self.screen.fill(self.BLACK)
        
        # Dibujar elementos del radar
        self.draw_radar_grid()
        self.draw_sweep_line()
        
        # Dibujar hosts detectados (optimizado)
        current_time = time.time()
        for ip, info in active_hosts.items():
            is_recent = (current_time - info['last_seen']) < 5.0  # Reciente si < 5 segundos
            mac_address = learned_macs.get(ip)
            self.draw_host_optimized(ip, info['angle'], info['latency'], is_recent, mac_address)
        
        # Verificar hover y dibujar información detallada
        hovered_ip = self.check_hover(self.mouse_pos)
        if hovered_ip and hovered_ip in active_hosts:
            self.draw_hover_info(hovered_ip, learned_macs)
        
        # Dibujar interfaz
        self.draw_info_panel(len(active_hosts), scan_status)
        self.draw_legend()
        
        # Actualizar pantalla
        pygame.display.flip()
        # No usar clock.tick aquí, se maneja en el bucle principal
    
    def handle_events(self):
        """
        Maneja eventos de Pygame
        
        Returns:
            bool: True si debe continuar, False si debe salir
        """
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return False
        return True
    
    def cleanup(self):
        """
        Limpia recursos de Pygame
        """
        pygame.quit()

if __name__ == "__main__":
    # Ejemplo de uso
    radar = RadarDisplay()
    
    # Hosts de ejemplo
    test_hosts = {
        "192.168.1.1": {"latency": 5.2, "last_seen": time.time(), "angle": 0},
        "192.168.1.100": {"latency": 25.8, "last_seen": time.time(), "angle": 90},
        "192.168.1.50": {"latency": 75.3, "last_seen": time.time(), "angle": 180},
    }
    
    # MACs de ejemplo
    test_macs = {
        "192.168.1.1": "14:82:5b:00:00:20",
        "192.168.1.100": "58:6c:25:f7:56:2f",
        "192.168.1.50": "b4:b0:24:45:3e:b0",
    }
    
    running = True
    while running:
        running = radar.handle_events()
        radar.update_display(test_hosts, "Demo", test_macs)
    
    radar.cleanup()

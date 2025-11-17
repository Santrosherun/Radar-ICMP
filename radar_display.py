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
        self.max_radius = min(width, height) // 3 - 20  # Radar más pequeño
        
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
        
        # UI State para tablas
        self.show_host_tables = True  # Mostrar tablas de hosts
        self.table_scroll_offset = 0  # Para scroll en tablas largas
        
        # Gráfica de latencia promedio
        self.latency_graph_history = []  # Historial de latencia promedio (últimos 60 valores)
        self.max_graph_points = 60

        # Control simple para enviar pings manuales
        self.ping_active = False
        self.ping_button_rect = None
        self.show_icmp_result = False
        self.icmp_result_text = ""
        self.icmp_result_time = 0
        
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
        
        # Color basado en latencia (consistente con estadísticas: <20ms verde, 20-50ms amarillo, >50ms rojo)
        if latency_ms < 20:
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
        
        # Color basado en latencia (consistente con estadísticas: <20ms verde, 20-50ms amarillo, >50ms rojo)
        if latency_ms < 20:
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
    
    def draw_network_health_dashboard(self, active_hosts, statistics, anomalies):
        """
        Dibuja dashboard de salud de red tipo NOC
        """
        panel_width = 350
        panel_height = 210
        panel_x = self.width - panel_width - 10
        panel_y = 230  # Debajo de estadísticas
        
        # Fondo
        panel_surface = pygame.Surface((panel_width, panel_height), pygame.SRCALPHA)
        panel_surface.fill((0, 0, 30, 220))
        self.screen.blit(panel_surface, (panel_x, panel_y))
        
        # Borde
        pygame.draw.rect(self.screen, self.BRIGHT_GREEN, (panel_x, panel_y, panel_width, panel_height), 2)
        
        # Título
        title = self.font_medium.render("SALUD DE LA RED", True, self.BRIGHT_GREEN)
        self.screen.blit(title, (panel_x + 10, panel_y + 8))
        
        # Línea separadora
        pygame.draw.line(self.screen, self.GREEN, (panel_x + 5, panel_y + 35), 
                        (panel_x + panel_width - 5, panel_y + 35), 1)
        
        # Calcular métricas de salud
        total_hosts = len(active_hosts)
        healthy_hosts = 0  # < 20ms
        degraded_hosts = 0  # 20-50ms
        critical_hosts = 0  # > 50ms
        
        for ip, info in active_hosts.items():
            latency = info.get('latency', 0)
            if latency < 20:
                healthy_hosts += 1
            elif latency < 50:
                degraded_hosts += 1
            else:
                critical_hosts += 1
        
        # Anomalías
        high_latency_count = len(anomalies.get('high_latency', []))
        high_jitter_count = len(anomalies.get('high_jitter', []))
        
        # Estado general de la red
        if total_hosts == 0:
            network_quality = 0
            status_text = "SIN HOSTS"
            status_color = self.GRAY
        else:
            network_quality = (healthy_hosts * 100 + degraded_hosts * 60) / total_hosts
            
            if network_quality >= 80:
                status_text = "SALUDABLE"
                status_color = self.GREEN
            elif network_quality >= 50:
                status_text = "DEGRADADO"
                status_color = self.YELLOW
            else:
                status_text = "CRITICO"
                status_color = self.RED
        
        # Dibujar estado
        y = panel_y + 45
        
        # Estado general
        state_text = self.font_medium.render(f"Estado: {status_text}", True, status_color)
        self.screen.blit(state_text, (panel_x + 10, y))
        y += 30
        
        # Hosts por categoría
        categories = [
            (f"Saludables: {healthy_hosts}", self.GREEN),
            (f"Degradados: {degraded_hosts}", self.YELLOW),
            (f"Criticos: {critical_hosts}", self.RED)
        ]
        
        for text, color in categories:
            cat_text = self.font_small.render(text, True, color)
            self.screen.blit(cat_text, (panel_x + 20, y))
            y += 19
        
        # Línea separadora
        pygame.draw.line(self.screen, self.GREEN, (panel_x + 5, y + 5), 
                        (panel_x + panel_width - 5, y + 5), 1)
        y += 15
        
        # Anomalías
        anomaly_text = self.font_small.render("Anomalias:", True, self.WHITE)
        anomaly_text_width = anomaly_text.get_width()
        self.screen.blit(anomaly_text, (panel_x + 15, y))
        y += 20
        
        if high_latency_count > 0:
            text = self.font_small.render(f"  Latencia alta: {high_latency_count}", True, self.RED)
            self.screen.blit(text, (panel_x + 15, y))
            y += 20
        
        if high_jitter_count > 0:
            text = self.font_small.render(f"  Jitter alto: {high_jitter_count}", True, self.YELLOW)
            self.screen.blit(text, (panel_x + 15, y))
            y += 20
        
        if high_latency_count == 0 and high_jitter_count == 0:
            text = self.font_small.render("  Ninguna", True, self.GREEN)
            self.screen.blit(text, (panel_x + 15, y))
            y += 20
        
        # Barra de calidad de red
        bar_width = panel_width - 30
        bar_height = 15
        bar_x = panel_x + 15
        bar_y = panel_y + panel_height - 25
        
        # Texto de calidad (arriba de la barra)
        percent_text = self.font_small.render(f"Calidad: {network_quality:.0f}%", True, self.WHITE)
        percent_text_width = percent_text.get_width()
        self.screen.blit(percent_text, (panel_x + panel_width - percent_text_width - 10, bar_y - 18))
        
        # Fondo de la barra
        pygame.draw.rect(self.screen, (50, 50, 50), (bar_x, bar_y, bar_width, bar_height))
        
        # Barra de progreso
        if total_hosts > 0:
            progress_width = int((network_quality / 100) * bar_width)
            
            if network_quality >= 80:
                bar_color = self.GREEN
            elif network_quality >= 50:
                bar_color = self.YELLOW
            else:
                bar_color = self.RED
            
            pygame.draw.rect(self.screen, bar_color, (bar_x, bar_y, progress_width, bar_height))
        
        # Borde de la barra
        pygame.draw.rect(self.screen, self.WHITE, (bar_x, bar_y, bar_width, bar_height), 1)
    
    def draw_statistics_panel(self, statistics):
        """
        Dibuja panel de estadísticas en tiempo real
        
        Args:
            statistics (dict): Diccionario con estadísticas de red
        """
        # Panel de estadísticas
        panel_width = 280
        panel_height = 200
        panel_x = self.width - panel_width - 10
        panel_y = 10
        
        # Fondo del panel
        panel_surface = pygame.Surface((panel_width, panel_height), pygame.SRCALPHA)
        panel_surface.fill((0, 0, 0, 200))
        self.screen.blit(panel_surface, (panel_x, panel_y))
        
        # Borde del panel
        pygame.draw.rect(self.screen, self.BRIGHT_GREEN, 
                        (panel_x, panel_y, panel_width, panel_height), 2)
        
        # Título
        title = self.font_medium.render("ESTADÍSTICAS DE RED", True, self.BRIGHT_GREEN)
        self.screen.blit(title, (panel_x + 10, panel_y + 8))
        
        # Línea separadora
        pygame.draw.line(self.screen, self.GREEN, 
                        (panel_x + 5, panel_y + 35), 
                        (panel_x + panel_width - 5, panel_y + 35), 1)
        
        # Información estadística
        y_offset = 45
        line_height = 20
        
        stats_lines = [
            f"Paquetes Enviados: {statistics.get('packets_sent', 0)}",
            f"Paquetes Recibidos: {statistics.get('packets_received', 0)}",
            f"Paquetes Perdidos: {statistics.get('packets_lost', 0)}",
            f"Pérdida: {statistics.get('packet_loss_rate', 0):.1f}%",
            f"Latencia Prom: {statistics.get('avg_latency', 0):.1f}ms",
            f"Latencia Min: {statistics.get('min_latency', float('inf')):.1f}ms" if statistics.get('min_latency', float('inf')) != float('inf') else "Latencia Min: N/A",
            f"Latencia Max: {statistics.get('max_latency', 0):.1f}ms",
            f"Throughput: {statistics.get('throughput', 0):.1f} pkt/s"
        ]
        
        for i, line in enumerate(stats_lines):
            # Color basado en el tipo de estadística
            if "Pérdida" in line:
                loss_rate = statistics.get('packet_loss_rate', 0)
                if loss_rate > 10:
                    color = self.RED
                elif loss_rate > 5:
                    color = self.YELLOW
                else:
                    color = self.GREEN
            else:
                color = self.WHITE
            
            text_surface = self.font_small.render(line, True, color)
            self.screen.blit(text_surface, (panel_x + 10, panel_y + y_offset + i * line_height - 10))
    
    def draw_latency_graph(self, statistics):
        """
        Dibuja gráfica de latencia promedio en tiempo real
        """
        graph_width = 350
        graph_height = 130
        graph_x = self.width - graph_width - 10
        graph_y = 450  # Debajo del health dashboard
        
        # Agregar punto actual a historial
        avg_latency = statistics.get('avg_latency', 0)
        self.latency_graph_history.append(avg_latency)
        
        # Mantener solo últimos 60 valores
        if len(self.latency_graph_history) > self.max_graph_points:
            self.latency_graph_history.pop(0)
        
        # Fondo
        graph_surface = pygame.Surface((graph_width, graph_height), pygame.SRCALPHA)
        graph_surface.fill((0, 0, 20, 220))
        self.screen.blit(graph_surface, (graph_x, graph_y))
        
        # Borde
        pygame.draw.rect(self.screen, self.GREEN, (graph_x, graph_y, graph_width, graph_height), 2)
        
        # Título
        title = self.font_small.render("LATENCIA PROMEDIO", True, self.BRIGHT_GREEN)
        self.screen.blit(title, (graph_x + 10, graph_y + 5))
        
        # Área de gráfica
        plot_x = graph_x + 40
        plot_y = graph_y + 30
        plot_width = graph_width - 50
        plot_height = graph_height - 40
        
        if len(self.latency_graph_history) > 1:
            # Calcular escala
            max_latency = max(self.latency_graph_history) if self.latency_graph_history else 100
            min_latency = min(self.latency_graph_history) if self.latency_graph_history else 0
            
            if max_latency == min_latency:
                max_latency = min_latency + 10
            
            latency_range = max_latency - min_latency
            
            # Líneas de referencia horizontales
            for i in range(4):
                ref_y = plot_y + (plot_height // 3) * i
                pygame.draw.line(self.screen, (40, 40, 40), (plot_x, ref_y), 
                               (plot_x + plot_width, ref_y), 1)
            
            # Dibujar puntos y líneas
            points = []
            for i, latency in enumerate(self.latency_graph_history):
                px = plot_x + (i / max(len(self.latency_graph_history) - 1, 1)) * plot_width
                normalized = (latency - min_latency) / latency_range
                py = plot_y + plot_height - (normalized * plot_height)
                points.append((px, py))
            
            # Dibujar líneas
            for i in range(len(points) - 1):
                avg_lat = (self.latency_graph_history[i] + self.latency_graph_history[i + 1]) / 2
                
                if avg_lat < 20:
                    line_color = self.GREEN
                elif avg_lat < 50:
                    line_color = self.YELLOW
                else:
                    line_color = self.RED
                
                pygame.draw.line(self.screen, line_color, points[i], points[i + 1], 2)
            
            # Etiquetas en los ejes
            label_max = self.font_small.render(f"{max_latency:.0f}", True, self.GRAY)
            label_min = self.font_small.render(f"{min_latency:.0f}", True, self.GRAY)
            
            self.screen.blit(label_max, (graph_x + 5, plot_y))
            self.screen.blit(label_min, (graph_x + 5, plot_y + plot_height - 12))
            
            # Valor actual alineado a la derecha
            label_current = self.font_small.render(f"{avg_latency:.1f}ms", True, self.YELLOW)
            label_width = label_current.get_width()
            self.screen.blit(label_current, (graph_x + graph_width - label_width - 10, graph_y + 5))

    def draw_ping_control_panel(self):
        """
        Dibuja un panel sencillo con un botón para enviar pings (Echo) a los hosts.
        1) Haz clic en el botón para activar el modo ping.
        2) Haz clic en un host del radar para enviar el ping.
        """
        panel_width = 340
        panel_height = 90
        panel_x = 10
        panel_y = self.height - panel_height - 10

        # Fondo
        panel_surface = pygame.Surface((panel_width, panel_height), pygame.SRCALPHA)
        panel_surface.fill((10, 10, 30, 220))
        self.screen.blit(panel_surface, (panel_x, panel_y))

        # Borde
        pygame.draw.rect(self.screen, self.GREEN, (panel_x, panel_y, panel_width, panel_height), 2)

        # Título
        title = self.font_small.render("PING MANUAL A HOSTS", True, self.BRIGHT_GREEN)
        title_width = title.get_width()
        title_x = panel_x + (panel_width - title_width) // 2
        self.screen.blit(title, (title_x, panel_y + 6))

        # Botón de ping
        btn_text_preview = self.font_small.render("PING (Echo Request)", True, self.WHITE)
        button_width = btn_text_preview.get_width() + 20  # Ancho basado en el texto + padding
        button_height = 26
        button_x = panel_x + (panel_width - button_width) // 2  # Centrado
        button_y = panel_y + 28

        # Guardar rect para detección de clicks
        self.ping_button_rect = pygame.Rect(button_x, button_y, button_width, button_height)

        # Color según estado (activo/inactivo)
        if self.ping_active:
            btn_border_color = self.BRIGHT_GREEN
            btn_bg_color = (0, 80, 0, 200)
        else:
            btn_border_color = self.WHITE
            btn_bg_color = (30, 30, 30, 200)

        btn_surface = pygame.Surface((button_width, button_height), pygame.SRCALPHA)
        btn_surface.fill(btn_bg_color)
        self.screen.blit(btn_surface, (button_x, button_y))

        pygame.draw.rect(self.screen, btn_border_color, self.ping_button_rect, 2)

        btn_text = self.font_small.render("PING (Echo Request)", True, btn_border_color)
        text_rect = btn_text.get_rect(center=(button_x + button_width // 2, button_y + button_height // 2))
        self.screen.blit(btn_text, text_rect)

        # Breve ayuda (ahora en la línea de abajo)
        help_text = self.font_small.render("Activa y haz clic en un host del radar", True, self.GRAY)
        help_text_width = help_text.get_width()
        help_text_x = panel_x + (panel_width - help_text_width) // 2  # Centrado
        help_text_y = button_y + button_height + 8
        self.screen.blit(help_text, (help_text_x, help_text_y))

        # Mostrar resultado reciente del ping (si existe)
        if self.show_icmp_result and time.time() - self.icmp_result_time < 3:
            result_text = self.font_small.render(self.icmp_result_text, True, self.YELLOW)
            self.screen.blit(result_text, (panel_x + 10, panel_y - 18))
        elif self.show_icmp_result:
            # Expiró el tiempo de mostrar el resultado
            self.show_icmp_result = False
    
    def draw_host_tables(self, active_hosts, offline_hosts, anomalies, scanner=None):
        """
        Dibuja tablas de hosts online y offline con anomalías
        
        Args:
            active_hosts (dict): Hosts activos
            offline_hosts (dict): Hosts offline
            anomalies (dict): Anomalías detectadas
            scanner: Scanner para obtener info de hosts
        """
        table_x = 10
        table_y = 10
        table_width = 380
        row_height = 20
        
        # ═══════════════════════════════════════════════════════
        # TABLA DE HOSTS ONLINE
        # ═══════════════════════════════════════════════════════
        
        online_count = len(active_hosts)
        online_height = min(50 + (online_count * row_height), 240)  # Máximo 240px
        
        # Fondo
        online_surface = pygame.Surface((table_width, online_height), pygame.SRCALPHA)
        online_surface.fill((0, 20, 0, 200))  # Verde oscuro translúcido
        self.screen.blit(online_surface, (table_x, table_y))
        
        # Borde verde
        pygame.draw.rect(self.screen, self.GREEN, 
                        (table_x, table_y, table_width, online_height), 2)
        
        # Título
        title = self.font_medium.render(f"HOSTS ONLINE ({online_count})", True, self.BRIGHT_GREEN)
        self.screen.blit(title, (table_x + 10, table_y + 8))
        
        # Headers
        header_y = table_y + 35
        pygame.draw.line(self.screen, self.GREEN, 
                        (table_x + 5, header_y), 
                        (table_x + table_width - 5, header_y), 1)
        
        # Dibujar hosts (máximo 10 visibles)
        y_offset = header_y + 5
        max_visible = min(10, online_count)
        
        # Crear anomalías lookup para acceso rápido
        anomaly_ips = set()
        for anomaly_list in anomalies.values():
            for item in anomaly_list:
                if 'ip' in item:
                    anomaly_ips.add(item['ip'])
        
        for i, (ip, info) in enumerate(list(active_hosts.items())[:max_visible]):
            latency = info.get('latency', 0)
            
            # Color basado en latencia (consistente: <20ms verde, 20-50ms amarillo, >50ms rojo)
            if latency < 20:
                lat_color = self.GREEN
            elif latency < 50:
                lat_color = self.YELLOW
            else:
                lat_color = self.RED
            
            # Obtener info del dispositivo
            device_type = ""
            if scanner:
                host_info = scanner.get_host_info(ip)
                if host_info:
                    device_type = host_info.get('device_type', '')
            
            # Indicador de anomalía
            anomaly_indicator = "!" if ip in anomaly_ips else " "
            
            # Renderizar línea con tipo de dispositivo
            if device_type:
                line_text = f"{anomaly_indicator} {ip:15} {latency:5.1f}ms {device_type}"
            else:
                line_text = f"{anomaly_indicator} {ip:15} {latency:5.1f}ms"
            
            text_surface = self.font_small.render(line_text, True, lat_color)
            self.screen.blit(text_surface, (table_x + 15, y_offset + i * row_height))
        
        # Indicador si hay más hosts
        if online_count > max_visible:
            more_text = f"... y {online_count - max_visible} mas"
            text_surface = self.font_small.render(more_text, True, self.GRAY)
            self.screen.blit(text_surface, (table_x + 15, y_offset + max_visible * row_height))
        
        # ═══════════════════════════════════════════════════════
        # TABLA DE HOSTS OFFLINE
        # ═══════════════════════════════════════════════════════
        
        offline_count = len(offline_hosts)
        offline_y = table_y + online_height + 10
        offline_height = min(50 + (offline_count * row_height), 160)  # Máximo 160px
        
        if offline_count > 0:
            # Fondo
            offline_surface = pygame.Surface((table_width, offline_height), pygame.SRCALPHA)
            offline_surface.fill((20, 0, 0, 200))  # Rojo oscuro translúcido
            self.screen.blit(offline_surface, (table_x, offline_y))
            
            # Borde rojo
            pygame.draw.rect(self.screen, self.RED, 
                            (table_x, offline_y, table_width, offline_height), 2)
            
            # Título
            title = self.font_medium.render(f"HOSTS OFFLINE ({offline_count})", True, self.RED)
            self.screen.blit(title, (table_x + 10, offline_y + 8))
            
            # Headers
            header_y = offline_y + 35
            pygame.draw.line(self.screen, self.RED, 
                            (table_x + 5, header_y), 
                            (table_x + table_width - 5, header_y), 1)
            
            # Dibujar hosts offline (máximo 7 visibles)
            y_offset = header_y + 5
            max_visible = min(7, offline_count)
            
            for i, (ip, info) in enumerate(list(offline_hosts.items())[:max_visible]):
                # Calcular tiempo offline
                offline_seconds = time.time() - info.get('went_offline', 0)
                
                if offline_seconds < 60:
                    time_str = f"{offline_seconds:.0f}s"
                elif offline_seconds < 3600:
                    time_str = f"{offline_seconds/60:.0f}m"
                else:
                    time_str = f"{offline_seconds/3600:.1f}h"
                
                # Renderizar línea con IP completa
                line_text = f"  {ip:15} offline: {time_str}"
                text_surface = self.font_small.render(line_text, True, self.RED)
                self.screen.blit(text_surface, (table_x + 15, y_offset + i * row_height))
            
            # Indicador si hay más hosts
            if offline_count > max_visible:
                more_text = f"... y {offline_count - max_visible} mas"
                text_surface = self.font_small.render(more_text, True, self.GRAY)
                self.screen.blit(text_surface, (table_x + 15, y_offset + max_visible * row_height))
    
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
    
    def draw_hover_info(self, ip, learned_macs, latency_history, scanner=None):
        """
        Dibuja información detallada del host en hover con gráfico de latencia
        
        Args:
            ip (str): IP del host
            learned_macs (dict): Diccionario de MACs aprendidas
            latency_history (list): Historial de latencias del host
            scanner (ICMPScanner): Referencia al scanner para obtener info del host
        """
        if ip not in self.host_positions:
            return
            
        pos_info = self.host_positions[ip]
        mac_address = learned_macs.get(ip)
        
        # Obtener información del dispositivo desde el scanner
        device_name = None
        device_type = None
        
        if scanner:
            host_info = scanner.get_host_info(ip)
            if host_info:
                device_name = host_info.get('hostname', None)
                device_type = host_info.get('device_type', None)
        
        # Fallback a método antiguo si no hay info del scanner
        if not device_name:
            device_name, device_type = self.get_device_info(ip, mac_address)
        
        # Calcular jitter si hay suficiente historial
        # Usar solo valores recientes (últimos 10) para reflejar jitter actual
        jitter_text = ""
        if len(latency_history) >= 5:
            # Usar solo los últimos 10 valores para calcular jitter (más relevante al estado actual)
            recent_history = latency_history[-10:] if len(latency_history) >= 10 else latency_history
            avg_lat = sum(recent_history) / len(recent_history)
            variance = sum((x - avg_lat) ** 2 for x in recent_history) / len(recent_history)
            jitter = variance ** 0.5
            jitter_text = f"Jitter: {jitter:.1f}ms"
        
        # Crear panel de información
        info_lines = [
            f"IP: {ip}",
            f"Host: .{self.get_host_byte(ip)}",
            f"Latencia: {pos_info['latency']:.1f}ms",
            f"Dispositivo: {device_name}",
            f"Tipo: {device_type}"
        ]
        
        if jitter_text:
            info_lines.append(jitter_text)
        
        if mac_address:
            info_lines.append(f"MAC: {mac_address}")
        
        # Calcular tamaño del panel (incluyendo espacio para gráfico)
        max_width = 0
        line_height = 18
        for line in info_lines:
            text_surface = self.font_small.render(line, True, self.WHITE)
            max_width = max(max_width, text_surface.get_width())
        
        # Tamaño del gráfico
        graph_width = 200
        graph_height = 80
        
        panel_width = max(max_width + 20, graph_width + 20)
        panel_height = len(info_lines) * line_height + 10 + graph_height + 15
        
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
        panel_surface.fill((0, 0, 0, 220))
        self.screen.blit(panel_surface, (panel_x, panel_y))
        
        # Dibujar borde
        pygame.draw.rect(self.screen, self.BRIGHT_GREEN, 
                        (panel_x, panel_y, panel_width, panel_height), 2)
        
        # Dibujar líneas de información
        for i, line in enumerate(info_lines):
            color = self.BRIGHT_GREEN if i == 0 else self.WHITE
            text_surface = self.font_small.render(line, True, color)
            self.screen.blit(text_surface, (panel_x + 10, panel_y + 5 + i * line_height))
    
        # Dibujar gráfico de latencia si hay historial
        if len(latency_history) > 1:
            graph_y = panel_y + len(info_lines) * line_height + 15
            self._draw_latency_graph(panel_x + 10, graph_y, graph_width, graph_height, latency_history)
    
    def _draw_latency_graph(self, x, y, width, height, latency_history):
        """
        Dibuja un mini-gráfico de latencia
        
        Args:
            x, y (int): Posición del gráfico
            width, height (int): Dimensiones del gráfico
            latency_history (list): Lista de latencias
        """
        if not latency_history or len(latency_history) < 2:
            return
        
        # Fondo del gráfico
        graph_surface = pygame.Surface((width, height), pygame.SRCALPHA)
        graph_surface.fill((10, 10, 10, 150))
        self.screen.blit(graph_surface, (x, y))
        
        # Borde
        pygame.draw.rect(self.screen, self.DARK_GREEN, (x, y, width, height), 1)
        
        # Calcular escala
        max_latency = max(latency_history)
        min_latency = min(latency_history)
        latency_range = max_latency - min_latency if max_latency != min_latency else 1
        
        # Líneas de referencia horizontales
        for i in range(3):
            ref_y = y + (height // 3) * i
            pygame.draw.line(self.screen, (50, 50, 50), (x, ref_y), (x + width, ref_y), 1)
        
        # Dibujar puntos y líneas
        points = []
        for i, latency in enumerate(latency_history):
            # Calcular posición
            px = x + (i / (len(latency_history) - 1)) * width
            # Invertir Y (0 en la parte superior = latencia baja)
            normalized = (latency - min_latency) / latency_range
            py = y + height - (normalized * height)
            points.append((px, py))
        
        # Dibujar líneas entre puntos
        if len(points) > 1:
            for i in range(len(points) - 1):
                # Color basado en latencia promedio del segmento (consistente: <20ms verde, 20-50ms amarillo, >50ms rojo)
                avg_lat = (latency_history[i] + latency_history[i + 1]) / 2
                if avg_lat < 20:
                    line_color = self.GREEN
                elif avg_lat < 50:
                    line_color = self.YELLOW
                else:
                    line_color = self.RED
                
                pygame.draw.line(self.screen, line_color, points[i], points[i + 1], 2)
        
        # Dibujar puntos
        for i, (px, py) in enumerate(points):
            latency = latency_history[i]
            # Color basado en latencia (consistente: <20ms verde, 20-50ms amarillo, >50ms rojo)
            if latency < 20:
                point_color = self.GREEN
            elif latency < 50:
                point_color = self.YELLOW
            else:
                point_color = self.RED
            
            pygame.draw.circle(self.screen, point_color, (int(px), int(py)), 3)
        
        # Etiquetas de valores
        label_min = self.font_small.render(f"{min_latency:.0f}ms", True, self.GRAY)
        label_max = self.font_small.render(f"{max_latency:.0f}ms", True, self.GRAY)
        
        self.screen.blit(label_max, (x + 2, y + 2))
        self.screen.blit(label_min, (x + 2, y + height - 18))
        
        # Título del gráfico
        title = self.font_small.render("Historial de Latencia", True, self.WHITE)
        self.screen.blit(title, (x + width // 2 - 60, y - 15))
    
    def update_display(self, active_hosts, statistics, offline_hosts, anomalies, 
                       learned_macs=None, scanner=None):
        """
        Actualiza toda la pantalla del radar con estadísticas y tablas
        
        Args:
            active_hosts (dict): Diccionario de hosts activos
            statistics (dict): Estadísticas de red
            offline_hosts (dict): Hosts offline
            anomalies (dict): Anomalías detectadas
            learned_macs (dict): Diccionario de MACs aprendidas
            scanner (ICMPScanner): Referencia al scanner para obtener historial
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
        
        # Verificar hover y dibujar información detallada con gráfico
        hovered_ip = self.check_hover(self.mouse_pos)
        if hovered_ip and hovered_ip in active_hosts:
            # Obtener historial de latencia
            latency_history = scanner.get_latency_history(hovered_ip) if scanner else []
            self.draw_hover_info(hovered_ip, learned_macs, latency_history, scanner)
        
        # Dibujar nuevas interfaces
        self.draw_network_health_dashboard(active_hosts, statistics, anomalies)
        self.draw_latency_graph(statistics)
        self.draw_statistics_panel(statistics)
        self.draw_host_tables(active_hosts, offline_hosts, anomalies, scanner)
        self.draw_ping_control_panel()
        
        # Actualizar pantalla
        pygame.display.flip()
        # No usar clock.tick aquí, se maneja en el bucle principal
    
    def handle_events(self, scanner=None):
        """
        Maneja eventos de Pygame
        
        Args:
            scanner (ICMPScanner): Referencia al scanner para enviar paquetes
        
        Returns:
            bool: True si debe continuar, False si debe salir
        """
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return False
            elif event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:  # Click izquierdo
                mouse_pos = event.pos

                # Click en botón de ping: activar/desactivar modo ping
                if self.ping_button_rect and self.ping_button_rect.collidepoint(mouse_pos):
                    self.ping_active = not self.ping_active
                # Click sobre un host mientras el modo ping está activo: enviar Echo Request
                elif scanner and self.ping_active:
                    clicked_ip = self.check_hover(mouse_pos)
                    if clicked_ip and clicked_ip in scanner.get_active_hosts():
                        reply, latency = scanner.send_custom_icmp(clicked_ip, 8)

                        if reply:
                            self.icmp_result_text = f"Ping a {clicked_ip}: OK ({latency:.1f}ms)"
                        else:
                            self.icmp_result_text = f"Ping a {clicked_ip}: Sin respuesta"

                        self.show_icmp_result = True
                        self.icmp_result_time = time.time()
        
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

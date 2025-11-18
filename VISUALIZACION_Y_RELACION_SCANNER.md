# VISUALIZACIÓN Y RELACIÓN CON EL SCANNER
## Interfaz Gráfica y Flujo de Datos

---

## 1. INTRODUCCIÓN

La interfaz visual (`RadarDisplay`) presenta de forma gráfica la información recopilada por el motor de escaneo (`ICMPScanner`). La visualización se actualiza en tiempo real a 60 FPS, mostrando hosts activos, estadísticas de red y anomalías detectadas.

**Relación fundamental:**
```
ICMPScanner (Motor de Escaneo)
    ↓
    Recopila datos de red (ICMP/ARP)
    ↓
    Estructuras de datos actualizadas
    ↓
RadarDisplay (Visualización)
    ↓
    Renderiza información gráficamente
```

---

## 2. COMPONENTES VISUALES PRINCIPALES

### 2.1 Radar Circular

**Ubicación:** Centro de la pantalla

**Función:** Visualiza hosts activos en formato tipo radar militar

**Datos del Scanner:**
- `active_hosts`: Diccionario con IPs, latencias y ángulos
- `learned_macs`: Direcciones MAC para identificación de dispositivos

**Representación:**
- **Centro**: Dispositivo local (latencia = 0ms)
- **Distancia radial**: Mapea latencia a distancia del centro
  - Latencia baja (< 10ms) → Cerca del centro
  - Latencia alta (> 50ms) → Lejos del centro
- **Color del punto**: Indica calidad de conexión
  - Verde: < 10ms (excelente)
  - Amarillo: 10-50ms (buena)
  - Rojo: > 50ms (problemas)
- **Etiqueta**: Último octeto de IP (ej: ".157") y latencia

**Código de mapeo:**
```python
# En RadarDisplay
def latency_to_radius(self, latency_ms):
    """Convierte latencia a distancia radial"""
    min_radius = self.max_radius * 0.2
    max_radius = self.max_radius * 0.9
    normalized_latency = min(latency_ms / 100.0, 1.0)
    return int(min_radius + (max_radius - min_radius) * normalized_latency)
```

**Relación con Scanner:**
```python
# Scanner proporciona:
active_hosts = {
    "192.168.1.100": {
        'latency': 15.2,      # ← Usado para calcular radio
        'angle': 45,          # ← Usado para posición angular
        'last_seen': timestamp
    }
}

# Visualización renderiza:
x = center_x + radius * cos(angle)
y = center_y + radius * sin(angle)
```

### 2.2 Panel de Estadísticas

**Ubicación:** Panel superior derecho

**Función:** Muestra métricas globales de la red

**Datos del Scanner:**
- `statistics`: Diccionario con estadísticas calculadas por `get_statistics()`

**Información mostrada:**
- Paquetes enviados/recibidos/perdidos
- Tasa de pérdida de paquetes (%)
- Latencia promedio, mínima y máxima
- Throughput (paquetes por segundo)

**Relación con Scanner:**
```python
# Scanner calcula estadísticas:
statistics = scanner.get_statistics()
# Retorna:
{
    'packets_sent': 1000,
    'packets_received': 950,
    'packets_lost': 50,
    'packet_loss_rate': 5.0,    # ← Calculado
    'avg_latency': 25.5,         # ← Calculado
    'min_latency': 1.2,
    'max_latency': 150.3,
    'throughput': 10.0           # ← Calculado
}

# Visualización muestra estos valores directamente
```

### 2.3 Dashboard de Salud de Red

**Ubicación:** Panel derecho, debajo de estadísticas

**Función:** Clasifica el estado general de la red

**Datos del Scanner:**
- `active_hosts`: Para clasificar hosts por latencia
- `anomalies`: Anomalías detectadas por `detect_anomalies()`

**Clasificación de hosts:**
- **Saludables**: Latencia < 20ms (verde)
- **Degradados**: Latencia 20-50ms (amarillo)
- **Críticos**: Latencia > 50ms (rojo)

**Estado general:**
- **SALUDABLE**: 80%+ de calidad
- **DEGRADADO**: 50-80% de calidad
- **CRÍTICO**: < 50% de calidad

**Cálculo de calidad:**
```python
# En RadarDisplay
network_quality = (healthy_hosts * 100 + degraded_hosts * 60) / total_hosts
```

**Relación con Scanner:**
```python
# Scanner proporciona:
active_hosts = {
    "192.168.1.100": {'latency': 15.2},  # ← Clasificado como saludable
    "192.168.1.101": {'latency': 35.0},  # ← Clasificado como degradado
    "192.168.1.102": {'latency': 80.5}   # ← Clasificado como crítico
}

anomalies = {
    'high_latency': [{'ip': '192.168.1.102', ...}],
    'high_jitter': []
}

# Visualización calcula y muestra:
# - Conteo por categoría
# - Estado general
# - Anomalías detectadas
```

### 2.4 Gráfica de Latencia en Tiempo Real

**Ubicación:** Panel derecho, debajo del dashboard

**Función:** Muestra evolución de la latencia promedio

**Datos del Scanner:**
- `statistics['avg_latency']`: Latencia promedio actual

**Características:**
- Historial de últimos 60 puntos
- Actualización continua
- Codificación por color según latencia
- Escala automática (min/max)

**Relación con Scanner:**
```python
# Scanner actualiza estadísticas continuamente:
statistics = scanner.get_statistics()
avg_latency = statistics['avg_latency']  # ← Usado para gráfica

# Visualización:
# 1. Agrega punto al historial
latency_graph_history.append(avg_latency)

# 2. Mantiene solo últimos 60 valores
if len(latency_graph_history) > 60:
    latency_graph_history.pop(0)

# 3. Renderiza gráfica con puntos históricos
```

### 2.5 Tablas de Hosts

**Ubicación:** Panel izquierdo

**Función:** Lista detallada de hosts online y offline

**Datos del Scanner:**
- `active_hosts`: Hosts activos
- `offline_hosts`: Hosts que estuvieron online
- `anomalies`: Anomalías para marcar hosts problemáticos
- `scanner.get_host_info()`: Información de hostname y tipo

**Información mostrada por host:**
- IP completa
- Latencia actual
- Tipo de dispositivo (si está disponible)
- Indicador de anomalías (si aplica)

**Relación con Scanner:**
```python
# Scanner proporciona:
active_hosts = {
    "192.168.1.100": {
        'latency': 15.2,
        'last_seen': timestamp
    }
}

offline_hosts = {
    "192.168.1.50": {
        'last_seen': timestamp,
        'went_offline': timestamp,
        'last_latency': 12.5
    }
}

# Scanner también proporciona información extendida:
host_info = scanner.get_host_info("192.168.1.100")
# Retorna: {'hostname': 'TP-Link-100', 'device_type': 'Router/AP'}

# Visualización muestra todo en tabla formateada
```

### 2.6 Información de Hover

**Ubicación:** Aparece al pasar el mouse sobre un host

**Función:** Muestra información detallada del host

**Datos del Scanner:**
- `learned_macs`: Dirección MAC del host
- `scanner.get_latency_history()`: Historial de latencia (últimos 30 valores)
- `scanner.get_host_info()`: Hostname y tipo de dispositivo

**Información mostrada:**
- IP completa
- Hostname
- Latencia actual
- Tipo de dispositivo
- Dirección MAC
- Gráfica de historial de latencia (mini-gráfica)

**Relación con Scanner:**
```python
# Usuario pasa mouse sobre host
hovered_ip = "192.168.1.100"

# Visualización solicita datos al scanner:
mac = learned_macs.get(hovered_ip)
latency_history = scanner.get_latency_history(hovered_ip)  # ← Últimos 30 valores
host_info = scanner.get_host_info(hovered_ip)              # ← Hostname y tipo

# Visualización muestra panel con toda la información
```

---

## 3. FLUJO DE DATOS: SCANNER → VISUALIZACIÓN

### 3.1 Actualización Continua

El flujo de datos se actualiza en cada frame (60 veces por segundo):

```python
# En ICMPRadarApp.run() - Bucle principal
while self.running:
    # 1. Scanner recopila datos en segundo plano (threads)
    #    - Escaneo ICMP
    #    - Aprendizaje ARP
    #    - Actualización de estadísticas
    
    # 2. Obtener datos actualizados del scanner
    active_hosts = self.scanner.get_active_hosts()      # ← Thread-safe copy
    learned_macs = self.scanner.get_learned_macs()      # ← Thread-safe copy
    offline_hosts = self.scanner.get_offline_hosts()    # ← Thread-safe copy
    statistics = self.scanner.get_statistics()          # ← Métricas calculadas
    anomalies = self.scanner.detect_anomalies()         # ← Anomalías detectadas
    
    # 3. Pasar datos a visualización
    self.radar.update_display(
        active_hosts=active_hosts,
        statistics=statistics,
        offline_hosts=offline_hosts,
        anomalies=anomalies,
        learned_macs=learned_macs,
        scanner=self.scanner  # ← Referencia para consultas adicionales
    )
    
    # 4. Visualización renderiza todo
    #    - Radar circular
    #    - Paneles de información
    #    - Tablas
    #    - Gráficas
```

### 3.2 Thread Safety

**Problema:** Scanner actualiza datos en threads, visualización lee en thread principal

**Solución:** Scanner retorna copias de datos (thread-safe)

```python
# En ICMPScanner
def get_active_hosts(self):
    return self.active_hosts.copy()  # ← Copia, no referencia

def get_statistics(self):
    stats_copy = self.stats.copy()   # ← Copia
    # Calcular métricas derivadas
    stats_copy['avg_latency'] = ...
    return stats_copy
```

**Ventaja:** Visualización puede leer datos sin bloquear threads de escaneo

---

## 4. MAPEO DE DATOS: EJEMPLOS CONCRETOS

### 4.1 Host Detectado

**En Scanner:**
```python
# Después de ping_host() exitoso:
self.active_hosts["192.168.1.100"] = {
    'latency': 15.2,
    'last_seen': 1234567890.0,
    'angle': 45  # hash(ip) % 360
}

# Después de _learn_mac_via_arp():
self.learned_macs["192.168.1.100"] = "14:82:5B:78:99:63"

# Después de _resolve_hostname_and_type():
self.host_info["192.168.1.100"] = {
    'hostname': 'TP-Link-100',
    'device_type': 'Router/AP'
}
```

**En Visualización:**
```python
# Radar circular:
radius = latency_to_radius(15.2)  # → ~30% del radio máximo
x = center_x + radius * cos(45°)
y = center_y + radius * sin(45°)
color = GREEN  # Porque 15.2ms < 10ms... espera, debería ser YELLOW
# (Nota: el código usa < 10 para verde, 10-50 para amarillo)

# Tabla de hosts:
# Muestra: "192.168.1.100 | 15.2ms | Router/AP"

# Hover:
# Muestra: IP, hostname, MAC, latencia, historial
```

### 4.2 Estadísticas Actualizadas

**En Scanner:**
```python
# Después de múltiples pings:
self.stats = {
    'packets_sent': 1000,
    'packets_received': 950,
    'packets_lost': 50,
    'total_latency': 25000.0,
    'min_latency': 1.2,
    'max_latency': 150.3
}

# get_statistics() calcula:
statistics = {
    'packet_loss_rate': 5.0,      # 50/1000 * 100
    'avg_latency': 26.3,           # 25000/950
    'throughput': 10.0             # 1000 / elapsed_time
}
```

**En Visualización:**
```python
# Panel de estadísticas muestra:
# "Paquetes Enviados: 1000"
# "Paquetes Recibidos: 950"
# "Paquetes Perdidos: 50"
# "Pérdida: 5.0%"  ← Color amarillo (5-10%)
# "Latencia Prom: 26.3ms"
# "Latencia Min: 1.2ms"
# "Latencia Max: 150.3ms"
# "Throughput: 10.0 pkt/s"

# Gráfica de latencia:
# Agrega punto en y=26.3ms
# Color: YELLOW (20-50ms)
```

### 4.3 Anomalía Detectada

**En Scanner:**
```python
# detect_anomalies() identifica:
anomalies = {
    'high_latency': [
        {
            'ip': '192.168.1.102',
            'latency': 120.5,
            'threshold': 100
        }
    ],
    'high_jitter': [],
    'recently_offline': []
}
```

**En Visualización:**
```python
# Dashboard de salud:
# Muestra: "Anomalias: Latencia alta: 1"

# Tabla de hosts:
# Marca host 192.168.1.102 con indicador de anomalía
# Color: ROJO (latencia > 50ms)

# Radar circular:
# Host aparece en posición lejana (alta latencia)
# Color: ROJO
```

---

## 5. INTERACCIÓN USUARIO → SCANNER

### 5.1 Ping Manual

**Flujo:**
```
Usuario hace click en host del radar
    ↓
RadarDisplay detecta click
    ↓
Solicita ping al scanner
    ↓
Scanner envía paquete ICMP personalizado
    ↓
Muestra resultado en pantalla
```

**Código:**
```python
# En RadarDisplay.handle_events()
if click_en_host:
    # Usar scanner para enviar ping
    result = scanner.send_custom_icmp(ip, icmp_type=8)
    
    if result[0]:  # Si hay respuesta
        latency = result[1]
        mostrar_resultado(f"OK ({latency}ms)")
    else:
        mostrar_resultado("Sin respuesta")
```

---

## 6. RESUMEN: RELACIÓN SCANNER-VISUALIZACIÓN

### 6.1 Datos que Scanner Proporciona

| Dato | Estructura | Uso en Visualización |
|------|------------|---------------------|
| `active_hosts` | `{ip: {latency, angle, last_seen}}` | Radar circular, tablas |
| `learned_macs` | `{ip: mac_address}` | Identificación de dispositivos, hover |
| `offline_hosts` | `{ip: {last_seen, went_offline, last_latency}}` | Tabla de hosts offline |
| `statistics` | `{packets_sent, avg_latency, ...}` | Panel de estadísticas, gráfica |
| `anomalies` | `{high_latency: [...], ...}` | Dashboard de salud, marcadores |
| `host_info` | `{ip: {hostname, device_type}}` | Tablas, hover |
| `latency_history` | `{ip: [lat1, lat2, ...]}` | Gráfica de historial en hover |

### 6.2 Transformaciones Visuales

**Latencia → Posición Radial:**
```
latency_ms → normalized (0-1) → radius (20%-90% del máximo)
```

**Latencia → Color:**
```
< 10ms → Verde
10-50ms → Amarillo
> 50ms → Rojo
```

**Estadísticas → Texto:**
```
Valores numéricos → Strings formateados → Renderizado en pantalla
```

**Hosts → Tabla:**
```
Diccionario → Lista ordenada → Filas formateadas → Renderizado
```

---

## 7. OPTIMIZACIONES DE RENDIMIENTO

### 7.1 Actualización Selectiva

- **Estadísticas**: Se calculan bajo demanda (no cada frame)
- **Anomalías**: Se detectan cada 2 segundos (cache)
- **Hosts**: Solo se renderizan hosts visibles

### 7.2 Thread Safety

- Scanner retorna copias de datos (no referencias)
- Visualización no modifica datos del scanner
- Sin locks necesarios (lectura pura)

---

## REFERENCIAS

1. Pygame Community. (2024). *Pygame Documentation*. https://www.pygame.org/docs/

2. Python Software Foundation. (2024). *threading — Thread-based parallelism*. Python 3.12 Documentation.

---

**Nota para el informe:**
Este documento explica brevemente la visualización y su relación con el scanner, enfocándose en:
- Qué muestra cada componente visual
- De dónde vienen los datos (scanner)
- Cómo se transforman los datos para visualización
- Flujo de actualización en tiempo real

Cada sección puede copiarse directamente al informe, ajustando el formato según sea necesario.


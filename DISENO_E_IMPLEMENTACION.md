# DISEÑO, ARQUITECTURA E IMPLEMENTACIÓN
## Sistema de Escaneo de Red con ICMP y ARP

---

## 1. ARQUITECTURA DEL SISTEMA

### 1.1 Visión General

El sistema está diseñado con una arquitectura modular que separa las responsabilidades en tres componentes principales:

```
┌─────────────────────────────────────────────────────────┐
│                  ICMPRadarApp                           │
│  (Coordinador Principal - icmp_radar.py)                │
│  - Gestión del ciclo de vida                            │
│  - Coordinación de threads                               │
│  - Interfaz con el usuario                               │
└──────────────┬──────────────────────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────────┐
│ ICMPScanner │  │  RadarDisplay   │
│ (Motor de   │  │  (Visualización) │
│  Escaneo)   │  │                  │
│             │  │                  │
│ - ICMP      │  │ - Pygame         │
│ - ARP       │  │ - Renderizado     │
│ - Stats     │  │ - Interfaz       │
└─────────────┘  └──────────────────┘
```

**Componentes principales:**

1. **ICMPScanner** (`icmp_scanner.py`): Motor de escaneo que implementa toda la lógica de red
2. **ICMPRadarApp** (`icmp_radar.py`): Aplicación principal que coordina los componentes
3. **RadarDisplay** (`radar_display.py`): Módulo de visualización (no cubierto en detalle aquí)

### 1.2 Flujo de Datos

```
Inicialización
    ↓
Detección de Red Local (psutil)
    ↓
Configuración de Rango de Red
    ↓
┌─────────────────────────────────────┐
│  Thread de Escaneo Continuo         │
│  - Escanea red completa cada N seg  │
│  - Descubre nuevos hosts             │
└───────────┬─────────────────────────┘
            │
            ├─> ping_host() [ICMP]
            │   └─> _learn_mac_via_arp() [ARP]
            │
            └─> Actualiza active_hosts
                └─> Actualiza estadísticas
                    ↓
┌─────────────────────────────────────┐
│  Thread de Ping Continuo            │
│  - Monitorea hosts conocidos         │
│  - Actualiza latencia en tiempo real │
└───────────┬─────────────────────────┘
            │
            └─> Actualiza active_hosts
                ↓
┌─────────────────────────────────────┐
│  Thread de Limpieza                 │
│  - Elimina hosts expirados           │
│  - Mueve a offline_hosts             │
└─────────────────────────────────────┘
```

---

## 2. IMPLEMENTACIÓN CON SCAPY

### 2.1 Configuración Inicial de Scapy

El sistema configura Scapy para operar de forma silenciosa y eficiente:

```python
from scapy.all import IP, ICMP, sr1, conf

# Configurar Scapy para ser menos verboso
conf.verb = 0  # Desactivar salida verbosa
```

**Importaciones clave:**
- `IP`: Construcción de encabezados IP
- `ICMP`: Construcción de mensajes ICMP
- `sr1`: Función send-and-receive (envía 1 paquete y espera respuesta)
- `ARP, Ether, srp`: Para solicitudes ARP (importadas cuando se necesitan)

### 2.2 Construcción de Paquetes ICMP con Scapy

El sistema utiliza Scapy para construir paquetes ICMP personalizados siguiendo el estándar RFC 792 (Postel, 1981).

**Paquete ICMP Echo Request básico:**

```python
# Construcción del paquete
packet = IP(dst="192.168.1.100") / ICMP()

# Desglose:
# IP(dst="...")  → Encabezado IP con dirección destino
# /              → Operador de composición de capas en Scapy
# ICMP()         → Encabezado ICMP (por defecto: Type=8, Code=0)
```

**Estructura del paquete resultante:**

```
┌─────────────────────────────────────────┐
│  IP Header (20 bytes)                   │
│  - Versión: 4                           │
│  - Protocolo: 1 (ICMP)                 │
│  - IP Origen: [IP local]               │
│  - IP Destino: 192.168.1.100           │
├─────────────────────────────────────────┤
│  ICMP Header (8 bytes)                  │
│  - Tipo: 8 (Echo Request)              │
│  - Código: 0                            │
│  - Checksum: [calculado automáticamente]│
│  - Identificador: [auto]               │
│  - Secuencia: [auto]                     │
└─────────────────────────────────────────┘
```

**Envío y recepción:**

```python
# Enviar paquete y esperar respuesta
start_time = time.time()
reply = sr1(packet, timeout=0.5, verbose=0)
end_time = time.time()

# sr1() retorna:
# - Objeto de respuesta si hay respuesta
# - None si timeout o no hay respuesta
```

### 2.3 Construcción de Paquetes ARP con Scapy

El sistema utiliza Scapy para construir y enviar solicitudes ARP siguiendo el estándar RFC 826 (Plummer, 1982).

**Solicitud ARP:**

```python
from scapy.all import ARP, Ether, srp

# Crear solicitud ARP
arp_request = ARP(pdst="192.168.1.100")

# Crear encabezado Ethernet para broadcast
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

# Componer paquete completo (Ethernet + ARP)
arp_packet = broadcast / arp_request

# Enviar y recibir respuestas
answered_list, _ = srp(arp_packet, timeout=1, verbose=0)
```

**Estructura del paquete ARP:**

```
┌─────────────────────────────────────────┐
│  Ethernet Header (14 bytes)             │
│  - MAC Destino: ff:ff:ff:ff:ff:ff       │
│  - MAC Origen: [MAC local]              │
│  - Tipo: 0x0806 (ARP)                   │
├─────────────────────────────────────────┤
│  ARP Header (28 bytes)                  │
│  - Tipo Hardware: 1 (Ethernet)         │
│  - Tipo Protocolo: 0x0800 (IPv4)        │
│  - Operación: 1 (Request)               │
│  - IP Origen: [IP local]                │
│  - MAC Origen: [MAC local]              │
│  - IP Destino: 192.168.1.100            │
│  - MAC Destino: 00:00:00:00:00:00       │
└─────────────────────────────────────────┘
```

**Procesamiento de respuesta:**

```python
if answered_list:
    for element in answered_list:
        mac_address = element[1].hwsrc  # MAC del host que respondió
        self.learned_macs[ip] = mac_address
```

---

## 3. IMPLEMENTACIÓN DEL ESCANEO ICMP

### 3.1 Función `ping_host()`

Esta función implementa el ping ICMP utilizando Scapy:

```python
def ping_host(self, ip, retries=1):
    """
    Envía un ping ICMP a una IP específica
    
    Proceso:
    1. Construye paquete ICMP con Scapy
    2. Envía y espera respuesta (sr1)
    3. Mide latencia (RTT)
    4. Actualiza estadísticas
    5. Aprende MAC si es necesario
    """
    # Construir paquete ICMP
    packet = IP(dst=ip) / ICMP()
    
    # Medir tiempo de ida y vuelta
    start_time = time.time()
    reply = sr1(packet, timeout=self.timeout, verbose=0)
    end_time = time.time()
    
    if reply:
        # Calcular latencia en milisegundos
        latency = (end_time - start_time) * 1000
        
        # Actualizar estadísticas globales
        self.stats['packets_received'] += 1
        self.stats['total_latency'] += latency
        
        # Aprender MAC si no la conocemos
        if ip not in self.learned_macs:
            self._learn_mac_via_arp(ip)
        
        return (ip, latency)
    
    return (ip, None)  # Host no responde
```

**Características clave:**
- **Timeout configurable**: Por defecto 0.5 segundos
- **Reintentos opcionales**: Permite múltiples intentos si falla
- **Medición precisa de latencia**: Calcula RTT en milisegundos
- **Integración con ARP**: Aprende MAC automáticamente

### 3.2 Función `scan_network()`

Implementa el escaneo paralelo de toda la red:

```python
def scan_network(self):
    """
    Escanea toda la red en busca de hosts activos
    
    Estrategia:
    - Escaneo paralelo con threading
    - Máximo 20 threads concurrentes
    - Cada thread ejecuta ping_host()
    """
    network = ipaddress.IPv4Network(self.network_range, strict=False)
    threads = []
    results = []
    
    def ping_worker(ip_str):
        result = self.ping_host(ip_str)
        if result[1] is not None:  # Si responde
            results.append(result)
    
    # Crear threads para ping paralelo
    for ip in network.hosts():
        if len(threads) >= 20:  # Límite de threads
            for t in threads:
                t.join()  # Esperar a que terminen
            threads.clear()
        
        thread = threading.Thread(target=ping_worker, args=(str(ip),))
        thread.start()
        threads.append(thread)
    
    # Esperar a que terminen todos
    for thread in threads:
        thread.join()
    
    # Actualizar hosts activos con resultados
    for ip, latency in results:
        self.active_hosts[ip] = {
            'latency': latency,
            'last_seen': time.time()
        }
```

**Optimizaciones implementadas:**
- **Límite de threads**: Máximo 20 concurrentes para evitar saturación
- **Gestión de memoria**: Limpia threads completados
- **Thread-safe**: Resultados se agregan de forma segura

### 3.3 Detección Automática de Red

El sistema detecta automáticamente la red local utilizando `psutil`:

```python
def get_local_network(self):
    """
    Detecta automáticamente la red local
    
    Proceso:
    1. Obtiene interfaces de red con psutil
    2. Busca interfaz IPv4 activa
    3. Calcula rango de red con ipaddress
    """
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                ip = addr.address
                netmask = addr.netmask
                
                # Filtrar localhost y link-local
                if ip != "127.0.0.1" and not ip.startswith("169.254"):
                    # Calcular red completa
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return str(network)  # Ej: "192.168.1.0/24"
    
    return "192.168.1.0/24"  # Fallback
```

---

## 4. IMPLEMENTACIÓN DEL APRENDIZAJE ARP

### 4.1 Función `_learn_mac_via_arp()`

Implementa la resolución de direcciones MAC mediante ARP:

```python
def _learn_mac_via_arp(self, ip):
    """
    Aprende la dirección MAC de una IP usando ARP
    
    Proceso:
    1. Construye solicitud ARP con Scapy
    2. Envía en broadcast (Ethernet)
    3. Espera respuesta ARP
    4. Extrae MAC y almacena en tabla
    """
    from scapy.all import ARP, Ether, srp
    
    # Crear solicitud ARP
    arp_request = ARP(pdst=ip)
    
    # Encapsular en Ethernet broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    
    # Enviar y recibir (srp = send/receive packet en capa 2)
    answered_list, _ = srp(arp_packet, timeout=1, verbose=0)
    
    if answered_list:
        # Extraer MAC de la respuesta
        mac_address = answered_list[0][1].hwsrc
        self.learned_macs[ip] = mac_address
```

**Integración con ICMP:**

El aprendizaje ARP se integra automáticamente después de descubrir un host con ICMP:

```python
# En ping_host(), después de recibir respuesta ICMP:
if reply:
    # ... actualizar estadísticas ...
    
    # Solo aprender MAC si no la conocemos
    if ip not in self.learned_macs:
        self._learn_mac_via_arp(ip)
```

**Ventajas de esta integración:**
- **Eficiencia**: Solo aprende MAC de hosts que responden ICMP
- **Reducción de tráfico**: Evita broadcasts ARP innecesarios
- **Información completa**: Obtiene tanto IP como MAC

### 4.2 Tabla ARP del Sistema

El sistema mantiene su propia tabla ARP durante la ejecución:

```python
# Estructura de datos
self.learned_macs = {}  # {ip: mac_address}

# Ejemplo de contenido:
# {
#     "192.168.1.1": "aa:bb:cc:dd:ee:ff",
#     "192.168.1.100": "11:22:33:44:55:66"
# }
```

**Uso de la tabla:**
- Identificación de dispositivos mediante OUI
- Evitar broadcasts ARP redundantes
- Información para visualización

---

## 5. SISTEMA DE MONITOREO CONTINUO

### 5.1 Thread de Escaneo Continuo

El sistema mantiene un thread que escanea la red periódicamente:

```python
def start_scanning(self):
    """
    Inicia escaneo continuo en segundo plano
    """
    def scan_worker():
        while self.running:
            # Realizar escaneo completo
            self.scanner.scan_network()
            
            # Esperar antes del próximo escaneo
            time.sleep(self.scan_interval)  # Por defecto: 3 segundos
    
    self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
    self.scan_thread.start()
```

### 5.2 Thread de Ping Continuo

Monitorea hosts conocidos más frecuentemente:

```python
def start_continuous_ping(self):
    """
    Ping continuo a hosts conocidos
    """
    def continuous_ping_worker():
        while self.continuous_ping_running:
            for ip in list(self.known_hosts):
                # Ping sin reintentos para velocidad
                result = self.ping_host(ip, retries=0)
                
                if result[1] is not None:
                    # Actualizar información del host
                    self.active_hosts[ip] = {
                        'latency': result[1],
                        'last_seen': time.time()
                    }
            
            time.sleep(5)  # Ciclo cada 5 segundos
    
    self.continuous_ping_thread = threading.Thread(
        target=continuous_ping_worker, 
        daemon=True
    )
    self.continuous_ping_thread.start()
```

**Diferencia entre threads:**
- **Escaneo continuo**: Descubre nuevos hosts (más lento, completo)
- **Ping continuo**: Monitorea hosts conocidos (más rápido, selectivo)

### 5.3 Thread de Limpieza

Elimina hosts que han dejado de responder:

```python
def start_cleanup_thread(self):
    """
    Limpia hosts expirados periódicamente
    """
    def cleanup_worker():
        while self.cleanup_running:
            current_time = time.time()
            expired_hosts = []
            
            # Identificar hosts expirados
            for ip, info in list(self.active_hosts.items()):
                if current_time - info['last_seen'] > self.host_persistence:
                    expired_hosts.append(ip)
            
            # Mover a offline_hosts
            for ip in expired_hosts:
                self.offline_hosts[ip] = {
                    'last_seen': self.active_hosts[ip]['last_seen'],
                    'went_offline': current_time,
                    'last_latency': self.active_hosts[ip].get('latency', 0)
                }
                del self.active_hosts[ip]
            
            time.sleep(5)  # Ejecutar cada 5 segundos
```

---

## 6. SISTEMA DE ESTADÍSTICAS

### 6.1 Estructura de Estadísticas

El sistema mantiene estadísticas globales de todas las operaciones de red:

```python
self.stats = {
    'packets_sent': 0,           # Total de paquetes ICMP enviados
    'packets_received': 0,       # Total de respuestas recibidas
    'packets_lost': 0,          # Total de paquetes perdidos
    'total_latency': 0.0,       # Suma acumulada de latencias
    'min_latency': float('inf'), # Latencia mínima registrada
    'max_latency': 0.0,         # Latencia máxima registrada
    'start_time': time.time()   # Timestamp de inicio
}
```

### 6.2 Actualización de Estadísticas

Las estadísticas se actualizan en cada operación de ping:

```python
# En ping_host(), después de recibir respuesta:
if reply:
    latency = (end_time - start_time) * 1000
    
    # Actualizar contadores
    self.stats['packets_sent'] += packets_sent_this_call
    self.stats['packets_received'] += 1
    self.stats['packets_lost'] += (packets_sent_this_call - 1)
    
    # Actualizar métricas de latencia
    self.stats['total_latency'] += latency
    self.stats['min_latency'] = min(self.stats['min_latency'], latency)
    self.stats['max_latency'] = max(self.stats['max_latency'], latency)
```

### 6.3 Cálculo de Métricas Derivadas

El sistema calcula métricas adicionales bajo demanda:

```python
def get_statistics(self):
    """
    Retorna estadísticas con métricas derivadas
    """
    stats_copy = self.stats.copy()
    
    # Tasa de pérdida de paquetes
    if stats_copy['packets_sent'] > 0:
        stats_copy['packet_loss_rate'] = (
            stats_copy['packets_lost'] / stats_copy['packets_sent']
        ) * 100
    
    # Latencia promedio
    if stats_copy['packets_received'] > 0:
        stats_copy['avg_latency'] = (
            stats_copy['total_latency'] / stats_copy['packets_received']
        )
    
    # Throughput (paquetes por segundo)
    elapsed_time = time.time() - stats_copy['start_time']
    if elapsed_time > 0:
        stats_copy['throughput'] = (
            stats_copy['packets_sent'] / elapsed_time
        )
    
    return stats_copy
```

---

## 7. PAQUETES ICMP PERSONALIZADOS

### 7.1 Función `send_custom_icmp()`

El sistema permite enviar diferentes tipos de mensajes ICMP:

```python
def send_custom_icmp(self, ip, icmp_type=8, icmp_code=0, payload_size=32):
    """
    Envía un paquete ICMP personalizado
    
    Tipos soportados:
    - 8: Echo Request (ping normal)
    - 13: Timestamp Request
    - 15: Information Request
    - 17: Address Mask Request
    """
    # Crear payload personalizado
    payload = b'X' * payload_size
    
    # Construir paquete según tipo
    if icmp_type == 8:  # Echo Request
        packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code) / payload
    elif icmp_type == 13:  # Timestamp Request
        packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
    # ... otros tipos ...
    
    # Enviar y medir
    start_time = time.time()
    reply = sr1(packet, timeout=self.timeout, verbose=0)
    end_time = time.time()
    
    if reply:
        latency = (end_time - start_time) * 1000
        return (reply, latency)
    
    return (None, None)
```

**Uso de diferentes tipos ICMP:**
- **Tipo 8**: Verificación básica de conectividad
- **Tipo 13**: Sincronización de tiempo
- **Tipo 17**: Descubrimiento de máscara de red

---

## 8. CONSIDERACIONES DE IMPLEMENTACIÓN

### 8.1 Thread Safety

El sistema utiliza estructuras de datos compartidas entre múltiples threads. Para garantizar thread safety:

```python
# Estructuras protegidas implícitamente:
# - active_hosts: Actualizado en threads específicos
# - learned_macs: Actualizado solo en ping_host()
# - stats: Actualizado de forma atómica

# Nota: En una implementación más robusta, se usarían locks explícitos
```

### 8.2 Manejo de Errores

El sistema maneja errores de forma robusta:

```python
try:
    # Operación de red con Scapy
    reply = sr1(packet, timeout=self.timeout, verbose=0)
except Exception as e:
    # Si falla, no es crítico - continuar con siguiente host
    pass
```

### 8.3 Optimizaciones de Rendimiento

**Optimizaciones implementadas:**
- **Límite de threads**: Máximo 20 concurrentes
- **Timeout corto**: 0.5 segundos por defecto
- **Reintentos mínimos**: 1 reintento por defecto
- **Cache de MACs**: Evita broadcasts ARP redundantes
- **Intervalos configurables**: Permite ajustar frecuencia de escaneo

---

## 9. FLUJO COMPLETO DE OPERACIÓN

### 9.1 Inicialización

```
1. Crear instancia de ICMPScanner
2. Detectar red local automáticamente
3. Configurar rango de red
4. Inicializar estructuras de datos
5. Verificar permisos ICMP
```

### 9.2 Escaneo Inicial

```
1. Thread de escaneo inicia
2. Para cada IP en rango:
   a. Crear thread de ping
   b. Construir paquete ICMP con Scapy
   c. Enviar y esperar respuesta
   d. Si responde: aprender MAC vía ARP
   e. Actualizar active_hosts y estadísticas
3. Esperar a que terminen todos los threads
```

### 9.3 Monitoreo Continuo

```
1. Thread de ping continuo monitorea hosts conocidos
2. Thread de limpieza elimina hosts expirados
3. Thread de escaneo descubre nuevos hosts periódicamente
4. Estadísticas se actualizan en tiempo real
5. Visualización se actualiza a 60 FPS
```

---

## REFERENCIAS TÉCNICAS

1. Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force.

2. Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol*. RFC 826. Internet Engineering Task Force.

3. Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/

4. Python Software Foundation. (2024). *threading — Thread-based parallelism*. Python 3.12 Documentation.

---

**Nota para el informe:**
Este documento explica el funcionamiento técnico del sistema de forma clara y concisa, enfocándose en:
- Uso de Scapy para construcción de paquetes
- Implementación de protocolos ICMP y ARP
- Arquitectura y diseño del sistema
- Flujos de operación

Cada sección puede copiarse directamente al informe, ajustando el formato según sea necesario.


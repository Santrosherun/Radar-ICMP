# Análisis Técnico Actualizado: Implementación de Escaneo de Red con ICMP y ARP

## Tabla de Contenidos

1. [Introducción](#introducción)
2. [Fundamentos Teóricos](#fundamentos-teóricos)
3. [Arquitectura del Sistema](#arquitectura-del-sistema)
4. [Análisis Detallado del Código](#análisis-detallado-del-código)
5. [Nuevas Características](#nuevas-características)
6. [Estructura de Paquetes de Red](#estructura-de-paquetes-de-red)
7. [Flujos de Comunicación](#flujos-de-comunicación)
8. [Sistema de Estadísticas y Monitoreo](#sistema-de-estadísticas-y-monitoreo)
9. [Detección de Anomalías](#detección-de-anomalías)
10. [Consideraciones Técnicas](#consideraciones-técnicas)
11. [Conclusiones](#conclusiones)

---

## Introducción

Este documento presenta un análisis técnico detallado y actualizado de la implementación de un escáner de red avanzado que utiliza los protocolos **ICMP (Internet Control Message Protocol)** y **ARP (Address Resolution Protocol)** para descubrir, monitorear y analizar hosts activos en una red local. La implementación utiliza la biblioteca **Scapy** de Python y ahora incluye características avanzadas como estadísticas en tiempo real, detección de tipos de dispositivos, historial de latencia y detección de anomalías.

### Objetivos del Sistema

- **Descubrimiento de hosts**: Identificar dispositivos activos en una red local mediante pings ICMP
- **Resolución de direcciones**: Aprender y mantener una tabla de correspondencia IP-MAC mediante ARP
- **Monitoreo continuo**: Mantener actualizada la información de latencia y estado de los hosts descubiertos
- **Detección automática**: Identificar automáticamente la configuración de red local
- **Análisis avanzado**: Estadísticas de red, detección de anomalías y clasificación de dispositivos
- **Gestión de estado**: Rastrear hosts online y offline con historial completo

---

## Fundamentos Teóricos

### 2.1 Protocolo ICMP (Internet Control Message Protocol)

**ICMP** es un protocolo de la capa de red (Capa 3 del modelo OSI) utilizado para el intercambio de mensajes de control y diagnóstico entre dispositivos de red.

#### Tipos de Mensajes ICMP Relevantes:

- **Tipo 8, Código 0**: Echo Request (ping request)
- **Tipo 0, Código 0**: Echo Reply (ping reply)
- **Tipo 13, Código 0**: Timestamp Request
- **Tipo 15, Código 0**: Information Request
- **Tipo 17, Código 0**: Address Mask Request

#### Estructura del mensaje ICMP:

```
┌─────────────────────────────────────────┐
│  Tipo (8 bits)      │  Código (8 bits)  │
├─────────────────────────────────────────┤
│  Checksum (16 bits)                     │
├─────────────────────────────────────────┤
│  Identificador (16 bits)                │
├─────────────────────────────────────────┤
│  Número de secuencia (16 bits)          │
├─────────────────────────────────────────┤
│  Datos (variable)                       │
└─────────────────────────────────────────┘
```

### 2.2 Protocolo ARP (Address Resolution Protocol)

**ARP** resuelve direcciones IP (Capa 3) a direcciones MAC (Capa 2) dentro de una red local.

#### Estructura del paquete ARP:

```
┌─────────────────────────────────────────┐
│  Tipo de hardware (2 bytes)             │  ← Ethernet = 1
├─────────────────────────────────────────┤
│  Tipo de protocolo (2 bytes)            │  ← IPv4 = 0x0800
├─────────────────────────────────────────┤
│  Longitud de hardware (1 byte)          │  ← MAC = 6 bytes
├─────────────────────────────────────────┤
│  Longitud de protocolo (1 byte)         │  ← IP = 4 bytes
├─────────────────────────────────────────┤
│  Operación (2 bytes)                    │  ← 1=Request, 2=Reply
├─────────────────────────────────────────┤
│  MAC origen (6 bytes)                   │
├─────────────────────────────────────────┤
│  IP origen (4 bytes)                    │
├─────────────────────────────────────────┤
│  MAC destino (6 bytes)                   │
├─────────────────────────────────────────┤
│  IP destino (4 bytes)                   │
└─────────────────────────────────────────┘
```

### 2.3 Hostnames Sintéticos y Detección por MAC

El sistema genera hostnames simples basados en la IP (por ejemplo, `Host-23` para `192.168.1.23`) y **no depende de DNS**.
Además, utiliza la **dirección MAC aprendida vía ARP** para inferir el tipo de dispositivo a partir del OUI (primeros bytes de la MAC).

---

## Arquitectura del Sistema

### 3.1 Componentes Principales

El sistema está estructurado en una clase principal `ICMPScanner` con las siguientes estructuras de datos:

```python
class ICMPScanner:
    # Configuración básica
    - network_range: Rango de red a escanear
    - timeout: Tiempo de espera para respuestas
    - host_persistence: Tiempo antes de considerar host inactivo
    
    # Estado de hosts
    - active_hosts: Diccionario de hosts activos
    - offline_hosts: Diccionario de hosts que estuvieron online
    - learned_macs: Tabla ARP aprendida (IP -> MAC)
    - known_hosts: Conjunto de IPs conocidas
    
    # Información extendida
    - host_info: Información de hostname y tipo de dispositivo
    - latency_history: Historial de latencia por host (últimos 30 valores)
    
    # Estadísticas globales
    - stats: Estadísticas de paquetes y latencia
```

### 3.2 Flujo General del Sistema Actualizado

```
┌─────────────────┐
│  Inicialización │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│  Detección de Red Local │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Escaneo de Red (ICMP)  │
└────────┬────────────────┘
         │
         ├─> Aprender MAC (ARP)
         ├─> Inferir tipo de dispositivo por MAC/IP
         └─> Actualizar estadísticas
         │
         ▼
┌─────────────────────────┐
│  Monitoreo Continuo     │
│  - Ping periódico       │
│  - Actualizar latencia │
│  - Detectar offline     │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Análisis y Detección   │
│  - Calcular métricas    │
│  - Detectar anomalías   │
│  - Generar estadísticas │
└─────────────────────────┘
```

---

## Análisis Detallado del Código

### 4.1 Configuración Inicial y Nuevas Dependencias

```python
# (Se eliminó la dependencia de socket/DNS para simplificar)
```

```python
# Estadísticas globales
self.stats = {
    'packets_sent': 0,
    'packets_received': 0,
    'packets_lost': 0,
    'total_latency': 0.0,
    'min_latency': float('inf'),
    'max_latency': 0.0,
    'start_time': time.time()
}

# Historial de latencia por host
self.latency_history = defaultdict(lambda: [])

# Información de hosts
self.host_info = {}  # {ip: {'hostname': str, 'device_type': str}}

# Hosts offline
self.offline_hosts = {}  # Hosts que estuvieron online pero ahora están offline
```

### 4.2 Resolución de Hostname y Detección de Tipo de Dispositivo

#### Función: `_resolve_hostname_and_type(ip)`

```python
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
    
    # Múltiples categorías de detección...
```

#### Análisis Detallado:

##### 4.2.1 Resolución DNS Inversa

**Línea 1: Resolver hostname**
```python
hostname = socket.gethostbyaddr(ip)[0]
```

- **`socket.gethostbyaddr(ip)`**: Realiza una búsqueda DNS inversa (PTR record)
- Retorna una tupla: `(hostname, alias_list, ip_address_list)`
- `[0]`: Extrae solo el hostname principal
- **Si falla**: Se genera un hostname basado en el último octeto de la IP

**Ejemplo:**
- IP: `192.168.1.100`
- DNS inverso exitoso: `"MiPC.local"` o `"android-abc123"`
- DNS inverso fallido: `"Host-100"`

##### 4.2.2 Detección Heurística de Tipo de Dispositivo

El código utiliza **heurísticas basadas en palabras clave** en el hostname para identificar tipos de dispositivos:

**Categorías detectadas:**

1. **📱 Android**: Detecta dispositivos móviles Android
   - Palabras clave: `android`, `samsung`, `galaxy`, `xiaomi`, `huawei`, etc.

2. **🍎 Apple**: Detecta dispositivos Apple
   - Palabras clave: `iphone`, `ipad`, `apple`, `macbook`, `airpods`, etc.

3. **🌐 Router**: Detecta routers y gateways
   - Palabras clave: `router`, `gateway`, `modem`, `tp-link`, `asus`, etc.

4. **💻 Windows PC**: Detecta computadoras Windows
   - Palabras clave: `desktop`, `pc-`, `windows`, `laptop`, etc.

5. **📺 Smart TV**: Detecta televisores inteligentes
   - Palabras clave: `tv`, `smarttv`, `chromecast`, `roku`, etc.

6. **🖨️ Printer**: Detecta impresoras
   - Palabras clave: `printer`, `hp-`, `canon`, `epson`, etc.

7. **🎮 Console**: Detecta consolas de videojuegos
   - Palabras clave: `playstation`, `xbox`, `nintendo`, etc.

8. **🏠 IoT**: Detecta dispositivos IoT y Smart Home
   - Palabras clave: `alexa`, `echo`, `nest`, `ring`, `camera`, etc.

**Lógica de detección:**
```python
if any(x in hostname_lower for x in ['android', 'samsung', ...]):
    device_type = "📱 Android"
```

Esta heurística busca cualquier palabra clave en el hostname (case-insensitive) y asigna el tipo correspondiente.

**Limitaciones:**
- Depende de que el hostname contenga información identificable
- Algunos dispositivos pueden tener hostnames genéricos
- Requiere que DNS inverso funcione o que el dispositivo publique su hostname

### 4.3 Sistema de Estadísticas Globales

#### Estructura de Estadísticas

```python
self.stats = {
    'packets_sent': 0,           # Total de paquetes ICMP enviados
    'packets_received': 0,       # Total de respuestas recibidas
    'packets_lost': 0,          # Total de paquetes perdidos
    'total_latency': 0.0,       # Suma acumulada de todas las latencias
    'min_latency': float('inf'), # Latencia mínima registrada
    'max_latency': 0.0,         # Latencia máxima registrada
    'start_time': time.time()   # Timestamp de inicio
}
```

#### Actualización de Estadísticas en `ping_host()`

```python
# Contar paquete enviado
packets_sent_this_call += 1

# ... después de recibir respuesta ...

if reply:
    latency = (end_time - start_time) * 1000
    packets_received_this_call = 1
    
    # Actualizar estadísticas en un solo lock
    with self.stats_lock:
        self.stats['packets_sent'] += packets_sent_this_call
        self.stats['packets_received'] += 1
        self.stats['packets_lost'] += (packets_sent_this_call - 1)
        self.stats['total_latency'] += latency
        self.stats['min_latency'] = min(self.stats['min_latency'], latency)
        self.stats['max_latency'] = max(self.stats['max_latency'], latency)
```

**Análisis:**

1. **`packets_sent_this_call`**: Cuenta todos los intentos de ping (incluyendo reintentos)
2. **`packets_lost`**: Calcula como `packets_sent - packets_received`
   - Si se enviaron 3 intentos y solo el último respondió: `packets_lost = 2`
3. **Latencia acumulada**: Suma todas las latencias para calcular promedio después
4. **Min/Max**: Mantiene registro de latencias extremas

**Si no hay respuesta:**
```python
# Si llegamos aquí, ningún intento tuvo éxito
with self.stats_lock:
    self.stats['packets_sent'] += packets_sent_this_call
    self.stats['packets_lost'] += packets_sent_this_call
```

Todos los paquetes enviados se cuentan como perdidos.

### 4.4 Historial de Latencia

#### Implementación

```python
# Historial de latencia por host (últimos 30 valores)
self.latency_history = defaultdict(lambda: [])

# En ping_host(), después de recibir respuesta:
with self.hosts_lock:
    self.latency_history[ip].append(latency)
    if len(self.latency_history[ip]) > 30:
        self.latency_history[ip].pop(0)
```

**Características:**

- **`defaultdict(lambda: [])`**: Crea automáticamente una lista vacía para nuevas IPs
- **Límite de 30 valores**: Mantiene solo las últimas 30 mediciones por host
- **FIFO (First In, First Out)**: `pop(0)` elimina el valor más antiguo
- **Uso**: Permite calcular tendencias, jitter y variabilidad de latencia

**Aplicaciones:**

1. **Cálculo de jitter**: Variación de latencia entre mediciones consecutivas
2. **Detección de tendencias**: Latencia aumentando o disminuyendo
3. **Análisis de estabilidad**: Qué tan consistente es la latencia de un host

### 4.5 Gestión de Hosts Offline

#### Estructura de Datos

```python
self.offline_hosts = {}  # {ip: {
    'last_seen': timestamp,
    'went_offline': timestamp,
    'last_latency': float
}}
```

#### Proceso de Marcado como Offline

**En `start_cleanup_thread()`:**

```python
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
```

**Cuando un host vuelve a estar online:**

```python
# En scan_network() y start_continuous_ping():
if ip in self.offline_hosts:
    del self.offline_hosts[ip]
```

**Características:**

- **Preserva historial**: No se pierde información cuando un host se desconecta
- **Timestamp de desconexión**: Permite saber cuándo se desconectó
- **Última latencia conocida**: Útil para análisis comparativo
- **Recuperación automática**: Se elimina de `offline_hosts` cuando vuelve a responder

### 4.6 Envío de Paquetes ICMP Personalizados

#### Función: `send_custom_icmp()`

```python
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
    """
```

#### Análisis de Tipos ICMP

**Tipo 8 - Echo Request (Ping Normal):**
```python
packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code) / payload
```
- Incluye payload personalizable
- Usado para verificar conectividad básica

**Tipo 13 - Timestamp Request:**
```python
packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
```
- Solicita timestamp del host remoto
- Útil para sincronización de tiempo
- No requiere payload

**Tipo 15 - Information Request:**
```python
packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
```
- Solicita información de red
- Obsoleto en IPv4, pero algunos sistemas aún lo soportan

**Tipo 17 - Address Mask Request:**
```python
packet = IP(dst=ip) / ICMP(type=icmp_type, code=icmp_code)
```
- Solicita la máscara de subred
- Útil para descubrimiento de red

**Construcción del Payload:**

```python
payload = b'X' * payload_size
```

- Crea un payload de bytes repetidos
- Permite probar con diferentes tamaños de paquete
- Útil para detectar MTU (Maximum Transmission Unit)

### 4.7 Escaneo de Red Mejorado

#### Actualización en `scan_network()`

```python
# Resolver hostname y tipo si es nuevo
if ip not in self.host_info:
    hostname, device_type = self._resolve_hostname_and_type(ip)
    with self.hosts_lock:
        self.host_info[ip] = {
            'hostname': hostname,
            'device_type': device_type
        }
```

**Mejoras:**

1. **Resolución única**: Solo resuelve hostname una vez por IP (cache)
2. **Información extendida**: Almacena hostname y tipo de dispositivo
3. **Thread-safe**: Usa locks para acceso seguro

**Estructura de `host_info`:**

```python
self.host_info[ip] = {
    'hostname': "MiPC.local",
    'device_type': "💻 Windows PC"
}
```

---

## Nuevas Características

### 5.1 Sistema de Métricas Derivadas

#### Función: `get_statistics()`

```python
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
```

#### Métricas Calculadas:

1. **`packet_loss_rate`**: Porcentaje de paquetes perdidos
   ```
   packet_loss_rate = (packets_lost / packets_sent) × 100
   ```

2. **`avg_latency`**: Latencia promedio
   ```
   avg_latency = total_latency / packets_received
   ```

3. **`throughput`**: Paquetes enviados por segundo
   ```
   throughput = packets_sent / elapsed_time
   ```

**Ejemplo de salida:**
```python
{
    'packets_sent': 1000,
    'packets_received': 950,
    'packets_lost': 50,
    'packet_loss_rate': 5.0,  # 5% de pérdida
    'avg_latency': 25.5,      # 25.5ms promedio
    'min_latency': 1.2,
    'max_latency': 150.3,
    'throughput': 10.0,       # 10 paquetes/segundo
    'start_time': 1234567890.0
}
```

### 5.2 Funciones de Consulta de Información

#### `get_latency_history(ip)`

```python
def get_latency_history(self, ip):
    """
    Retorna el historial de latencia de un host específico
    
    Returns:
        list: Lista de latencias (últimas 30)
    """
    with self.hosts_lock:
        return self.latency_history.get(ip, []).copy()
```

**Uso:** Permite analizar la variabilidad de latencia de un host específico.

#### `get_host_info(ip)`

```python
def get_host_info(self, ip):
    """
    Retorna información del host (hostname y tipo de dispositivo)
    
    Returns:
        dict: {'hostname': str, 'device_type': str} o None
    """
    with self.hosts_lock:
        return self.host_info.get(ip, None)
```

**Uso:** Obtiene información identificativa del dispositivo.

#### `get_offline_hosts()`

```python
def get_offline_hosts(self):
    """
    Retorna la lista de hosts offline
    
    Returns:
        dict: {ip: {last_seen, went_offline, last_latency}}
    """
    with self.hosts_lock:
        return self.offline_hosts.copy()
```

**Uso:** Identifica dispositivos que estuvieron conectados pero ahora están desconectados.

---

## Estructura de Paquetes de Red

### 6.1 Paquete ICMP Echo Request con Payload Personalizado

```
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET HEADER (14 bytes)                │
├─────────────────────────────────────────────────────────────┤
│  Destino MAC:    [Resuelto por ARP]                         │
│  Origen MAC:     aa:bb:cc:dd:ee:ff                          │
│  Tipo:           0x0800 (IPv4)                              │
├─────────────────────────────────────────────────────────────┤
│                    IP HEADER (20 bytes)                      │
├─────────────────────────────────────────────────────────────┤
│  Versión:        4                                           │
│  Protocolo:      1 (ICMP)                                    │
│  IP Origen:      192.168.1.50                               │
│  IP Destino:     192.168.1.100                              │
├─────────────────────────────────────────────────────────────┤
│                   ICMP HEADER (8 bytes)                        │
├─────────────────────────────────────────────────────────────┤
│  Tipo:           8 (Echo Request)                           │
│  Código:         0                                           │
│  Identificador: 0x0001                                      │
│  Secuencia:      0x0000                                      │
├─────────────────────────────────────────────────────────────┤
│                    ICMP PAYLOAD (variable)                   │
├─────────────────────────────────────────────────────────────┤
│  Datos:          [payload_size bytes]                       │
│                 (ej: 32 bytes de 'X' repetidos)            │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Paquete ICMP Timestamp Request

```
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET HEADER                           │
├─────────────────────────────────────────────────────────────┤
│                    IP HEADER                                 │
├─────────────────────────────────────────────────────────────┤
│                   ICMP HEADER                                │
├─────────────────────────────────────────────────────────────┤
│  Tipo:           13 (Timestamp Request)                     │
│  Código:         0                                           │
│  Checksum:       [calculado]                                │
│  Identificador:  [auto]                                     │
│  Secuencia:      [auto]                                      │
├─────────────────────────────────────────────────────────────┤
│  Timestamp Origin:    [timestamp del origen]               │
│  Timestamp Receive:   0 (vacío en request)                 │
│  Timestamp Transmit:   0 (vacío en request)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Flujos de Comunicación

### 7.1 Flujo Completo: Escaneo con Resolución de Hostname

```
┌──────────┐                    ┌──────────┐              ┌──────────┐
│  Cliente │                    │  Servidor│              │   DNS    │
└────┬─────┘                    └────┬─────┘              └────┬─────┘
     │                               │                         │
     │  1. ICMP Echo Request         │                         │
     ├───────────────────────────────>│                         │
     │                               │                         │
     │  2. ICMP Echo Reply           │                         │
     │<───────────────────────────────┤                         │
     │                               │                         │
     │  3. Resolver hostname (DNS)   │                         │
     │─────────────────────────────────────────────────────────>│
     │                               │                         │
     │  4. DNS Response               │                         │
     │<─────────────────────────────────────────────────────────┤
     │                               │                         │
     │  5. Detectar tipo dispositivo │                         │
     │     (heurística en hostname)  │                         │
     │                               │                         │
     │  6. Guardar información:      │                         │
     │     - IP, latencia            │                         │
     │     - Hostname                │                         │
     │     - Tipo dispositivo        │                         │
     │     - Actualizar estadísticas│                         │
     │                               │                         │
```

### 7.2 Flujo: Detección de Host Offline

```
Tiempo T0: Host responde normalmente
  │
  ├─> active_hosts[ip] = {latency: 10ms, last_seen: T0}
  │
Tiempo T1: Host deja de responder (T1 - T0 > host_persistence)
  │
  ├─> cleanup_thread detecta expiración
  │
  ├─> offline_hosts[ip] = {
  │       last_seen: T0,
  │       went_offline: T1,
  │       last_latency: 10ms
  │     }
  │
  ├─> del active_hosts[ip]
  │
Tiempo T2: Host vuelve a responder
  │
  ├─> ping_host() recibe respuesta
  │
  ├─> del offline_hosts[ip]
  │
  └─> active_hosts[ip] = {latency: 12ms, last_seen: T2}
```

---

## Sistema de Estadísticas y Monitoreo

### 8.1 Contadores de Paquetes

El sistema mantiene contadores precisos de:

- **Paquetes enviados**: Cada llamada a `ping_host()` incrementa este contador
- **Paquetes recibidos**: Solo se incrementa cuando hay respuesta exitosa
- **Paquetes perdidos**: Diferencia entre enviados y recibidos

**Cálculo de pérdida:**
```
packet_loss = packets_sent - packets_received
packet_loss_rate = (packet_loss / packets_sent) × 100%
```

### 8.2 Métricas de Latencia

#### Latencia Individual
Cada ping mide el tiempo de ida y vuelta (RTT):
```python
start_time = time.time()
reply = sr1(packet, timeout=self.timeout, verbose=0)
end_time = time.time()
latency = (end_time - start_time) * 1000  # ms
```

#### Latencia Agregada
- **Total**: Suma acumulada de todas las latencias
- **Mínima**: Valor más bajo registrado
- **Máxima**: Valor más alto registrado
- **Promedio**: Calculado como `total_latency / packets_received`

### 8.3 Throughput

**Definición:** Número de paquetes enviados por unidad de tiempo

```python
elapsed_time = time.time() - stats['start_time']
throughput = packets_sent / elapsed_time  # paquetes/segundo
```

**Interpretación:**
- Alto throughput: Escaneo activo y frecuente
- Bajo throughput: Escaneo lento o pausado

---

## Detección de Anomalías

### 9.1 Función: `detect_anomalies()`

```python
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
```

### 9.2 Detección de Latencia Alta

```python
# Latencia alta: más del doble del promedio global o > 100ms
if current_latency > global_avg * 2 or current_latency > 100:
    anomalies['high_latency'].append({
        'ip': ip,
        'latency': current_latency,
        'threshold': max(global_avg * 2, 100)
    })
```

**Criterios:**
1. **Relativo**: Más del doble del promedio global
2. **Absoluto**: Mayor a 100ms
3. **Se aplica el más restrictivo**: El umbral es el máximo de ambos

**Ejemplo:**
- Promedio global: 20ms
- Umbral relativo: 40ms
- Umbral absoluto: 100ms
- **Umbral final**: 100ms (más restrictivo)

### 9.3 Detección de Jitter Alto

```python
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
```

#### Cálculo de Jitter

**Paso 1: Promedio**
```
avg_lat = Σ(latency_i) / n
```

**Paso 2: Varianza**
```
variance = Σ(latency_i - avg_lat)² / n
```

**Paso 3: Desviación Estándar (Jitter)**
```
std_dev = √variance
```

**Interpretación:**
- **Jitter bajo (< 10ms)**: Latencia muy estable
- **Jitter medio (10-30ms)**: Variación normal
- **Jitter alto (> 30ms)**: Latencia inestable, posible problema de red

**Ejemplo:**
```
Historial: [10, 12, 15, 8, 50, 9, 11]
Promedio: 16.4ms
Varianza: 202.2
Desviación estándar: 14.2ms
Resultado: Jitter normal (< 30ms)
```

### 9.4 Detección de Hosts Recientemente Offline

```python
# Hosts recientemente offline (últimos 60 segundos)
current_time = time.time()
for ip, info in self.offline_hosts.items():
    if current_time - info['went_offline'] < 60:
        anomalies['recently_offline'].append({
            'ip': ip,
            'offline_since': info['went_offline'],
            'last_latency': info['last_latency']
        })
```

**Características:**
- Solo reporta hosts desconectados en los últimos 60 segundos
- Incluye timestamp de desconexión
- Incluye última latencia conocida (útil para análisis)

**Uso:** Identificar desconexiones recientes que pueden indicar problemas de red o dispositivos inestables.

---

## Consideraciones Técnicas

### 10.1 Thread Safety

El código utiliza múltiples locks para garantizar acceso seguro a estructuras compartidas:

```python
self.hosts_lock = Lock()      # Para active_hosts, offline_hosts, latency_history
self.macs_lock = Lock()       # Para learned_macs
self.known_hosts_lock = Lock() # Para known_hosts
self.stats_lock = Lock()      # Para stats
```

**Lock (Thread Lock):**
- Garantiza acceso exclusivo a recursos compartidos entre threads
- Previene condiciones de carrera (race conditions)

**Patrón de uso:**
```python
with self.stats_lock:
    # Operaciones atómicas
    self.stats['packets_sent'] += 1
    self.stats['packets_received'] += 1
```

### 10.2 Optimización de Reintentos

**Cambio importante:** El valor por defecto de `retries` cambió de 2 a 1:

```python
def ping_host(self, ip, retries=1):  # Antes era retries=2
```

**Razón:** Reducir tráfico de red y acelerar el escaneo, especialmente en ping continuo.

**En ping continuo:**
```python
result = self.ping_host(ip, retries=0)  # Sin reintentos
```

Sin reintentos para máxima velocidad en monitoreo continuo.

### 10.3 Intervalo de Ping Continuo

**Cambio:** El intervalo aumentó de 2 a 5 segundos:

```python
time.sleep(5)  # Antes era 2 segundos
```

**Razón:** Reducir carga en la red y en el sistema, especialmente con muchos hosts.

### 10.4 Gestión de Memoria

#### Historial de Latencia Limitado

```python
if len(self.latency_history[ip]) > 30:
    self.latency_history[ip].pop(0)
```

**Limitación:** Solo 30 valores por host previene crecimiento ilimitado de memoria.

**Cálculo de memoria:**
- 30 valores × 8 bytes (float) = 240 bytes por host
- 100 hosts = ~24 KB (muy eficiente)

#### Limpieza de Hosts Offline

Los hosts offline se mantienen indefinidamente, pero esto es aceptable porque:
- Solo almacena metadatos (timestamps y latencia)
- El número de hosts offline es típicamente pequeño
- Permite análisis histórico

---

## Conclusiones

### Resumen de Mejoras

El código actualizado incluye las siguientes mejoras significativas:

1. **Sistema de Estadísticas Completo**
   - Contadores de paquetes enviados/recibidos/perdidos
   - Métricas de latencia (min, max, promedio)
   - Cálculo de throughput y tasa de pérdida

2. **Resolución de Hostnames y Clasificación**
   - DNS inverso para identificar dispositivos por nombre
   - Detección heurística de tipos de dispositivos
   - Información extendida por host

3. **Historial de Latencia**
   - Últimas 30 mediciones por host
   - Permite análisis de tendencias y jitter

4. **Gestión de Estado Avanzada**
   - Rastreo de hosts offline con timestamps
   - Recuperación automática cuando hosts vuelven online

5. **Detección de Anomalías**
   - Identificación de latencia alta
   - Detección de jitter (variabilidad)
   - Alertas de hosts recientemente desconectados

6. **Paquetes ICMP Personalizados**
   - Soporte para múltiples tipos de ICMP
   - Payload configurable
   - Útil para pruebas avanzadas

### Aplicaciones Prácticas

- **Administración de Red**: Monitoreo completo con estadísticas y alertas
- **Diagnóstico**: Identificación automática de problemas (latencia alta, jitter)
- **Inventario**: Clasificación automática de dispositivos en la red
- **Análisis de Rendimiento**: Métricas históricas y tendencias
- **Seguridad**: Detección de dispositivos desconectados (posibles intrusiones)

### Mejoras Futuras Potenciales

1. **Persistencia de Datos**: Guardar estadísticas e historial en base de datos
2. **Alertas Configurables**: Sistema de notificaciones para anomalías
3. **Gráficos en Tiempo Real**: Visualización de tendencias de latencia
4. **Fingerprinting Avanzado**: Detección de OS y servicios mediante técnicas avanzadas
5. **IPv6**: Soporte completo para escaneo IPv6
6. **API REST**: Exponer estadísticas y controles mediante API web

---

## Referencias Técnicas

### Protocolos

- **RFC 792**: Internet Control Message Protocol (ICMP)
- **RFC 826**: Ethernet Address Resolution Protocol (ARP)
- **RFC 791**: Internet Protocol (IP)
- **RFC 1122**: Requirements for Internet Hosts

### Bibliotecas

- **Scapy**: https://scapy.net/
- **psutil**: https://psutil.readthedocs.io/
- **ipaddress**: Módulo estándar de Python 3.3+
- **socket**: Módulo estándar de Python para DNS

### Conceptos de Red

- **RTT (Round Trip Time)**: Tiempo de ida y vuelta de un paquete
- **Jitter**: Variación en la latencia entre paquetes consecutivos
- **Packet Loss Rate**: Porcentaje de paquetes perdidos
- **Throughput**: Tasa de transferencia de datos

---

**Documento generado para análisis académico**
**Fecha**: 2024
**Versión**: 2.0 (Actualizado con nuevas características)
**Autor**: Análisis técnico de código ICMP Scanner


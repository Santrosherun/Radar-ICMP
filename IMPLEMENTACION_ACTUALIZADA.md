# IMPLEMENTACIÓN Y FLUJO DE FUNCIONAMIENTO ACTUALIZADO
## Sistema de Escaneo de Red con ICMP y ARP

---

## 1. ARQUITECTURA Y FLUJO GENERAL

### 1.1 Visión General del Sistema

El sistema implementa un escáner de red que opera en tres fases principales:

```
┌─────────────────────────────────────────────────────────┐
│  FASE 1: DETECCIÓN DE RED (psutil)                      │
│  - Obtener IP y máscara de interfaz activa              │
│  - Calcular rango de red manualmente                    │
│  - Generar lista de IPs a escanear                     │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  FASE 2: ESCANEO ICMP (Scapy)                          │
│  - Construir paquetes ICMP Echo Request                │
│  - Enviar pings en paralelo (threading)                │
│  - Medir latencia (RTT)                                 │
│  - Identificar hosts activos                            │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│  FASE 3: APRENDIZAJE ARP (Scapy)                       │
│  - Solicitar MAC de hosts descubiertos                 │
│  - Construir tabla ARP local                           │
│  - Identificar dispositivos por OUI                    │
└─────────────────────────────────────────────────────────┘
```

### 1.2 Componentes Principales

**ICMPScanner** (`icmp_scanner.py`):
- Motor de escaneo y monitoreo
- Manejo de paquetes ICMP y ARP
- Gestión de estadísticas y estado

**ICMPRadarApp** (`icmp_radar.py`):
- Coordinador principal
- Gestión de threads
- Interfaz con visualización

---

## 2. DETECCIÓN AUTOMÁTICA DE RED

### 2.1 Funciones de Manipulación de IP 

El sistema implementa funciones propias para manipular direcciones IP sin depender completamente de bibliotecas externas:

**Conversión IP ↔ Entero:**
```python
def _ip_to_int(self, ip):
    """Convierte IP string a entero de 32 bits"""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def _int_to_ip(self, ip_int):
    """Convierte entero de 32 bits a IP string"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))
```

**Ejemplo:**
- `_ip_to_int("192.168.1.50")` → `3232235826`
- `_int_to_ip(3232235826)` → `"192.168.1.50"`

**Conversión de Máscara a CIDR:**
```python
def _netmask_to_cidr(self, netmask):
    """Convierte netmask a notación CIDR (/24, etc)"""
    netmask_int = self._ip_to_int(netmask)
    # Contar bits en 1
    cidr = bin(netmask_int).count('1')
    return cidr
```

**Ejemplo:**
- `_netmask_to_cidr("255.255.255.0")` → `24`
- `_netmask_to_cidr("255.255.0.0")` → `16`

**Cálculo de Dirección de Red:**
```python
def _calculate_network(self, ip, netmask):
    """Calcula la IP de red a partir de IP y netmask"""
    ip_int = self._ip_to_int(ip)
    netmask_int = self._ip_to_int(netmask)
    network_int = ip_int & netmask_int  # Operación AND bit a bit
    return self._int_to_ip(network_int)
```

**Ejemplo:**
- IP: `192.168.1.50`
- Máscara: `255.255.255.0`
- Red calculada: `192.168.1.0`

### 2.2 Función `get_local_network()`

Detecta automáticamente la red local utilizando psutil y las funciones de manipulación de IP:

```python
def get_local_network(self):
    """
    Detecta automáticamente la red local
    
    Proceso:
    1. Obtiene interfaces con psutil.net_if_addrs()
    2. Filtra interfaz IPv4 activa
    3. Calcula red usando funciones propias
    4. Retorna formato CIDR
    """
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                ip = addr.address
                netmask = addr.netmask
                
                # Filtrar localhost y link-local
                if ip != "127.0.0.1" and not ip.startswith("169.254"):
                    # Calcular red usando funciones propias
                    network_ip = self._calculate_network(ip, netmask)
                    cidr = self._netmask_to_cidr(netmask)
                    return f"{network_ip}/{cidr}"  # "192.168.1.0/24"
    
    return "192.168.1.0/24"  # Fallback
```

**Ventajas de este enfoque:**
- Control total sobre el cálculo
- No depende de bibliotecas externas para cálculos básicos
- Más eficiente para operaciones repetitivas

### 2.3 Generación de IPs de Hosts

El sistema genera las IPs a escanear manualmente:

```python
def _parse_network_range(self, network_str):
    """Parsea rango de red (ej: "192.168.1.0/24")"""
    if '/' in network_str:
        network_ip, cidr = network_str.split('/')
        return network_ip, int(cidr)
    else:
        return network_str, 24  # Default /24

def _generate_host_ips(self, network_str):
    """
    Genera todas las IPs de hosts en un rango
    
    Ejemplo: "192.168.1.0/24" → 
    ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]
    """
    network_ip, cidr = self._parse_network_range(network_str)
    network_int = self._ip_to_int(network_ip)
    
    # Calcular número de hosts
    host_bits = 32 - cidr
    num_hosts = (2 ** host_bits) - 2  # Excluir red y broadcast
    
    # Generar IPs
    start_ip = network_int + 1  # Primera IP útil
    end_ip = network_int + num_hosts  # Última IP útil
    
    for ip_int in range(start_ip, end_ip + 1):
        yield self._int_to_ip(ip_int)  # Generador (eficiente en memoria)
```

**Ejemplo para /24:**
- Red: `192.168.1.0/24`
- `host_bits = 32 - 24 = 8`
- `num_hosts = 2^8 - 2 = 254`
- IPs generadas: `192.168.1.1` a `192.168.1.254`

**Ventajas del generador:**
- Eficiente en memoria (no almacena todas las IPs)
- Permite iteración lazy
- Útil para redes grandes

---

## 3. CONSTRUCCIÓN Y ENVÍO DE PAQUETES ICMP CON SCAPY

### 3.1 Construcción del Paquete ICMP

El sistema utiliza Scapy para construir paquetes ICMP siguiendo el estándar RFC 792:

```python
def ping_host(self, ip, retries=1):
    """
    Envía ping ICMP a una IP específica
    
    Proceso:
    1. Construye paquete IP/ICMP con Scapy
    2. Envía y espera respuesta (sr1)
    3. Mide latencia (RTT)
    4. Actualiza estadísticas
    """
    # Construir paquete ICMP Echo Request
    packet = IP(dst=ip) / ICMP()
    
    # Enviar y medir tiempo
    start_time = time.time()
    reply = sr1(packet, timeout=self.timeout, verbose=0)
    end_time = time.time()
```

**Estructura del paquete construido:**

```
┌─────────────────────────────────────────┐
│  IP Header (20 bytes)                   │
│  - Versión: 4                           │
│  - Protocolo: 1 (ICMP)                  │
│  - IP Destino: [ip proporcionada]       │
│  - IP Origen: [auto - IP local]         │
├─────────────────────────────────────────┤
│  ICMP Header (8 bytes)                  │
│  - Tipo: 8 (Echo Request)               │
│  - Código: 0                             │
│  - Checksum: [calculado por Scapy]      │
│  - Identificador: [auto]                 │
│  - Secuencia: [auto]                     │
└─────────────────────────────────────────┘
```

**Operador `/` en Scapy:**
- `IP(dst=ip) / ICMP()` compone capas de protocolo
- Equivalente a encapsular ICMP dentro de IP
- Scapy maneja automáticamente checksums y campos calculados

### 3.2 Envío y Recepción con `sr1()`

```python
reply = sr1(packet, timeout=self.timeout, verbose=0)
```

**`sr1()` (send and receive 1):**
- Envía el paquete a la red
- Espera una respuesta dentro del timeout
- Retorna el paquete de respuesta o `None`
- `verbose=0` suprime salida de Scapy

**Proceso interno de Scapy:**
1. Construye el paquete completo (IP + ICMP)
2. Calcula checksums automáticamente
3. Resuelve MAC destino (puede usar ARP si es necesario)
4. Envía por la interfaz de red
5. Espera respuesta ICMP Echo Reply (Tipo 0)
6. Retorna paquete recibido

### 3.3 Medición de Latencia

```python
if reply:
    latency = (end_time - start_time) * 1000  # Convertir a ms
```

**Cálculo de RTT (Round Trip Time):**
- `start_time`: Momento antes de enviar
- `end_time`: Momento después de recibir respuesta
- `latency`: Diferencia en milisegundos

**Interpretación:**
- `< 10ms`: Excelente (red local cableada)
- `10-50ms`: Bueno (WiFi normal)
- `> 50ms`: Lento (posibles problemas)

---

## 4. ESCANEO PARALELO DE RED

### 4.1 Función `scan_network()`

Implementa escaneo paralelo utilizando threading:

```python
def scan_network(self):
    """
    Escanea toda la red en busca de hosts activos
    
    Estrategia:
    - Genera IPs usando _generate_host_ips()
    - Crea threads para ping paralelo
    - Máximo 20 threads concurrentes
    - Recolecta resultados
    """
    threads = []
    results = []
    
    def ping_worker(ip_str):
        result = self.ping_host(ip_str)
        if result[1] is not None:  # Si responde
            results.append(result)
    
    # Generar IPs y crear threads
    for ip in self._generate_host_ips(self.network_range):
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
```

**Flujo de ejecución:**

```
Generar IP: 192.168.1.1
  └─> Crear Thread 1 → ping_host("192.168.1.1")
Generar IP: 192.168.1.2
  └─> Crear Thread 2 → ping_host("192.168.1.2")
...
Generar IP: 192.168.1.20
  └─> Crear Thread 20 → ping_host("192.168.1.20")
Generar IP: 192.168.1.21
  └─> Esperar que terminen Threads 1-20
  └─> Crear Thread 21 → ping_host("192.168.1.21")
...
```

**Optimizaciones:**
- **Límite de 20 threads**: Evita saturación del sistema
- **Gestión de memoria**: Limpia threads completados
- **Resultados thread-safe**: Se agregan de forma segura

### 4.2 Actualización de Hosts Activos

Después del escaneo, se actualizan las estructuras de datos:

```python
current_time = time.time()
for ip, latency in results:
    # Resolver hostname y tipo si es nuevo
    if ip not in self.host_info:
        hostname, device_type = self._resolve_hostname_and_type(ip)
        self.host_info[ip] = {
            'hostname': hostname,
            'device_type': device_type
        }
    
    # Actualizar información del host
    self.active_hosts[ip] = {
        'latency': latency,
        'last_seen': current_time,
        'angle': hash(ip) % 360  # Para visualización
    }
    
    # Si vuelve a estar online, quitarlo de offline
    if ip in self.offline_hosts:
        del self.offline_hosts[ip]
    
    self.known_hosts.add(ip)
```

---

## 5. APRENDIZAJE DE DIRECCIONES MAC (ARP)

### 5.1 Función `_learn_mac_via_arp()`

Aprende direcciones MAC mediante solicitudes ARP:

```python
def _learn_mac_via_arp(self, ip):
    """
    Aprende la dirección MAC de una IP usando ARP
    
    Proceso:
    1. Construye solicitud ARP con Scapy
    2. Encapsula en Ethernet broadcast
    3. Envía y espera respuesta
    4. Extrae MAC y almacena
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
        mac_address = answered_list[0][1].hwsrc
        self.learned_macs[ip] = mac_address
```

**Estructura del paquete ARP:**

```
┌─────────────────────────────────────────┐
│  Ethernet Header (14 bytes)              │
│  - MAC Destino: ff:ff:ff:ff:ff:ff        │
│  - MAC Origen: [MAC local]                │
│  - Tipo: 0x0806 (ARP)                     │
├─────────────────────────────────────────┤
│  ARP Header (28 bytes)                   │
│  - Tipo Hardware: 1 (Ethernet)            │
│  - Tipo Protocolo: 0x0800 (IPv4)          │
│  - Operación: 1 (Request)                 │
│  - IP Origen: [IP local]                  │
│  - MAC Origen: [MAC local]                │
│  - IP Destino: [ip a resolver]           │
│  - MAC Destino: 00:00:00:00:00:00         │
└─────────────────────────────────────────┘
```

**Diferencias clave:**
- **`sr1()`**: Para paquetes en capa 3 (IP/ICMP)
- **`srp()`**: Para paquetes en capa 2 (Ethernet/ARP)

### 5.2 Integración con Escaneo ICMP

El aprendizaje ARP se integra automáticamente:

```python
# En ping_host(), después de recibir respuesta ICMP:
if reply:
    # ... actualizar estadísticas ...
    
    # Solo aprender MAC si no la conocemos
    if ip not in self.learned_macs:
        self._learn_mac_via_arp(ip)
```

**Ventajas:**
- Solo aprende MAC de hosts que responden ICMP
- Evita broadcasts ARP innecesarios
- Construye tabla ARP completa

### 5.3 Identificación de Dispositivos por OUI

El sistema utiliza OUI (Organizationally Unique Identifier) para identificar tipos de dispositivos:

```python
def _resolve_hostname_and_type(self, ip):
    """
    Identifica tipo de dispositivo por OUI de MAC
    """
    mac = self.learned_macs.get(ip)
    if mac:
        mac_norm = mac.upper().replace('-', ':')
        oui = ':'.join(mac_norm.split(':')[0:3])  # Primeros 3 bytes
        
        # Mapa de OUI a fabricante/tipo
        oui_vendor_type_map = {
            "14:82:5B": ("TP-Link", "Router/AP"),
            "58:6C:25": ("Intel", "PC/Laptop"),
            "B4:B0:24": ("Samsung", "Phone/Tablet"),
            "C0:95:6D": ("Apple", "iPhone/iPad/Mac"),
            # ... más de 50 fabricantes mapeados
        }
        
        vendor_type = oui_vendor_type_map.get(oui)
        if vendor_type:
            vendor_name, inferred_type = vendor_type
            hostname = f"{vendor_name}-{last_octet}"
            device_type = inferred_type
```

**Ejemplo:**
- MAC: `14:82:5B:78:99:63`
- OUI: `14:82:5B`
- Identificado como: `TP-Link Router/AP`

---

## 6. SISTEMA DE MONITOREO CONTINUO

### 6.1 Thread de Escaneo Continuo

Escanea la red completa periódicamente:

```python
def start_scanning(self):
    """Inicia escaneo continuo en segundo plano"""
    def scan_worker():
        while self.running:
            self.scanner.scan_network()  # Escaneo completo
            time.sleep(self.scan_interval)  # Por defecto: 3 segundos
    
    self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
    self.scan_thread.start()
```

### 6.2 Thread de Ping Continuo

Monitorea hosts conocidos más frecuentemente:

```python
def start_continuous_ping(self):
    """Ping continuo a hosts conocidos"""
    def continuous_ping_worker():
        while self.continuous_ping_running:
            for ip in list(self.known_hosts):
                result = self.ping_host(ip, retries=0)  # Sin reintentos
                
                if result[1] is not None:
                    # Actualizar información
                    self.active_hosts[ip] = {
                        'latency': result[1],
                        'last_seen': time.time()
                    }
            
            time.sleep(5)  # Ciclo cada 5 segundos
```

**Diferencia entre threads:**
- **Escaneo continuo**: Descubre nuevos hosts (más lento, completo)
- **Ping continuo**: Monitorea hosts conocidos (más rápido, selectivo)

### 6.3 Thread de Limpieza

Elimina hosts que han dejado de responder:

```python
def start_cleanup_thread(self):
    """Limpia hosts expirados"""
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

## 7. SISTEMA DE ESTADÍSTICAS

### 7.1 Estructura de Estadísticas

```python
self.stats = {
    'packets_sent': 0,           # Total enviados
    'packets_received': 0,        # Total recibidos
    'packets_lost': 0,           # Total perdidos
    'total_latency': 0.0,        # Suma acumulada
    'min_latency': float('inf'), # Mínimo
    'max_latency': 0.0,         # Máximo
    'start_time': time.time()    # Inicio
}
```

### 7.2 Actualización en Tiempo Real

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

### 7.3 Cálculo de Métricas Derivadas

```python
def get_statistics(self):
    """Retorna estadísticas con métricas derivadas"""
    stats_copy = self.stats.copy()
    
    # Tasa de pérdida
    if stats_copy['packets_sent'] > 0:
        stats_copy['packet_loss_rate'] = (
            stats_copy['packets_lost'] / stats_copy['packets_sent']
        ) * 100
    
    # Latencia promedio
    if stats_copy['packets_received'] > 0:
        stats_copy['avg_latency'] = (
            stats_copy['total_latency'] / stats_copy['packets_received']
        )
    
    # Throughput
    elapsed_time = time.time() - stats_copy['start_time']
    if elapsed_time > 0:
        stats_copy['throughput'] = (
            stats_copy['packets_sent'] / elapsed_time
        )
    
    return stats_copy
```

---

## 8. FLUJO COMPLETO DE OPERACIÓN

### 8.1 Inicialización

```
1. Crear ICMPScanner
   └─> Inicializar estructuras de datos
   └─> Configurar estadísticas

2. Detectar red local (get_local_network)
   └─> psutil.net_if_addrs()
   └─> Filtrar interfaz IPv4 activa
   └─> Calcular red con funciones propias
   └─> Retornar "192.168.1.0/24"

3. Configurar network_range
   └─> scanner.network_range = "192.168.1.0/24"

4. Verificar permisos ICMP
   └─> ping_host("127.0.0.1")
```

### 8.2 Escaneo Inicial

```
1. Generar IPs a escanear (_generate_host_ips)
   └─> "192.168.1.0/24" → [192.168.1.1, ..., 192.168.1.254]

2. Para cada IP (hasta 20 en paralelo):
   a. Crear thread
   b. ping_host(ip)
      ├─> Construir paquete: IP(dst=ip) / ICMP()
      ├─> Enviar con sr1()
      ├─> Medir latencia
      ├─> Actualizar estadísticas
      └─> Si responde y no conocemos MAC:
          └─> _learn_mac_via_arp(ip)
              ├─> Construir: Ether() / ARP(pdst=ip)
              ├─> Enviar con srp()
              └─> Extraer MAC y almacenar

3. Recolectar resultados
   └─> Actualizar active_hosts
   └─> Identificar dispositivos por OUI
   └─> Agregar a known_hosts
```

### 8.3 Monitoreo Continuo

```
Thread 1: Escaneo Continuo
  └─> Cada 3 segundos:
      └─> scan_network() (escaneo completo)

Thread 2: Ping Continuo
  └─> Cada 5 segundos:
      └─> Para cada known_host:
          └─> ping_host(ip, retries=0)
          └─> Actualizar latencia

Thread 3: Limpieza
  └─> Cada 5 segundos:
      └─> Identificar hosts expirados
      └─> Mover a offline_hosts
```

---

## 9. CONSTRUCCIÓN DE PAQUETES: DETALLES TÉCNICOS

### 9.1 Paquete ICMP Echo Request

**Construcción con Scapy:**
```python
packet = IP(dst="192.168.1.100") / ICMP()
```

**Campos automáticos de Scapy:**
- **IP.src**: IP de la interfaz de salida (automático)
- **IP.ttl**: 64 (por defecto)
- **ICMP.id**: Identificador único (automático)
- **ICMP.seq**: Número de secuencia (automático)
- **Checksums**: Calculados automáticamente

**Proceso de envío:**
1. Scapy construye el paquete completo
2. Calcula checksum IP
3. Calcula checksum ICMP
4. Resuelve MAC destino (puede usar ARP)
5. Envía por interfaz de red
6. Espera respuesta ICMP Echo Reply (Tipo 0)

### 9.2 Paquete ARP Request

**Construcción con Scapy:**
```python
arp_request = ARP(pdst="192.168.1.100")
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_packet = broadcast / arp_request
```

**Campos automáticos:**
- **ARP.op**: 1 (Request) - automático
- **ARP.hwsrc**: MAC local (automático)
- **ARP.psrc**: IP local (automático)
- **ARP.hwdst**: 00:00:00:00:00:00 (automático)

**Proceso de envío:**
1. Scapy construye paquete Ethernet + ARP
2. Envía en broadcast (MAC destino: ff:ff:ff:ff:ff:ff)
3. Todos los hosts en la red reciben el paquete
4. Solo el host con la IP solicitada responde
5. Respuesta ARP Reply (op=2) con MAC destino

---

## 10. OPTIMIZACIONES Y CONSIDERACIONES

### 10.1 Gestión de Memoria

**Generador de IPs:**
- `_generate_host_ips()` usa `yield` (generador)
- No almacena todas las IPs en memoria
- Eficiente para redes grandes (/16, /8)

**Historial de latencia:**
- Limitado a 30 valores por host
- FIFO: elimina valores antiguos
- Prevención de crecimiento ilimitado

### 10.2 Thread Safety

**Estructuras compartidas:**
- `active_hosts`: actualizado en threads específicos
- `learned_macs`: actualizado solo en ping_host()
- `stats`: actualizado de forma atómica

**Nota**: En una implementación más robusta, se usarían locks explícitos para mayor seguridad.

### 10.3 Manejo de Errores

```python
try:
    # Operación de red
    reply = sr1(packet, timeout=self.timeout, verbose=0)
except Exception as e:
    # Si falla, no es crítico - continuar con siguiente host
    pass
```

**Filosofía:**
- Errores de red no detienen el escaneo
- Cada host se maneja independientemente
- El sistema continúa funcionando aunque algunos hosts fallen

---

## REFERENCIAS TÉCNICAS

1. Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force.

2. Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol*. RFC 826. Internet Engineering Task Force.

3. Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/

4. Giampaolo, S. (2024). *psutil: Cross-platform lib for process and system monitoring*. https://psutil.readthedocs.io/

5. Python Software Foundation. (2024). *socket — Low-level networking interface*. Python 3.12 Documentation.

6. Python Software Foundation. (2024). *struct — Interpret bytes as packed binary data*. Python 3.12 Documentation.

---

**Nota para el informe:**
Este documento explica el funcionamiento actualizado del sistema, enfocándose en:
- Manipulación manual de IPs (sin dependencia completa de ipaddress)
- Construcción de paquetes con Scapy
- Flujo completo de escaneo ICMP y aprendizaje ARP
- Sistema de monitoreo continuo
- Detalles técnicos de implementación

Cada sección puede copiarse directamente al informe, ajustando el formato según sea necesario.


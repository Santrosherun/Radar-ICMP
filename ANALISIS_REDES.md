# Análisis Técnico: Implementación de Escaneo de Red con ICMP y ARP

## Tabla de Contenidos

1. [Introducción](#introducción)
2. [Fundamentos Teóricos](#fundamentos-teóricos)
3. [Arquitectura del Sistema](#arquitectura-del-sistema)
4. [Análisis Detallado del Código](#análisis-detallado-del-código)
5. [Estructura de Paquetes de Red](#estructura-de-paquetes-de-red)
6. [Flujos de Comunicación](#flujos-de-comunicación)
7. [Consideraciones Técnicas](#consideraciones-técnicas)
8. [Conclusiones](#conclusiones)

---

## Introducción

Este documento presenta un análisis técnico detallado de la implementación de un escáner de red que utiliza los protocolos **ICMP (Internet Control Message Protocol)** y **ARP (Address Resolution Protocol)** para descubrir y monitorear hosts activos en una red local. La implementación utiliza la biblioteca **Scapy** de Python, que permite la construcción, manipulación y envío de paquetes de red a nivel de protocolo.

### Objetivos del Sistema

- **Descubrimiento de hosts**: Identificar dispositivos activos en una red local mediante pings ICMP
- **Resolución de direcciones**: Aprender y mantener una tabla de correspondencia IP-MAC mediante ARP
- **Monitoreo continuo**: Mantener actualizada la información de latencia y estado de los hosts descubiertos
- **Detección automática**: Identificar automáticamente la configuración de red local

---

## Fundamentos Teóricos

### 2.1 Protocolo ICMP (Internet Control Message Protocol)

**ICMP** es un protocolo de la capa de red (Capa 3 del modelo OSI) utilizado para el intercambio de mensajes de control y diagnóstico entre dispositivos de red. Aunque técnicamente ICMP está en la capa de red, funciona como un protocolo auxiliar de IP.

#### Características principales:

- **Tipo de mensaje**: ICMP Echo Request (tipo 8) y Echo Reply (tipo 0)
- **Propósito**: Verificar conectividad y medir latencia entre hosts
- **Encapsulación**: Los mensajes ICMP se encapsulan directamente en paquetes IP (protocolo número 1)

#### Estructura del mensaje ICMP:

```
┌─────────────────────────────────────────┐
│  Tipo (8 bits)      │  Código (8 bits) │
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

**Campos importantes:**
- **Tipo 8**: Echo Request (ping request)
- **Tipo 0**: Echo Reply (ping reply)
- **Checksum**: Verificación de integridad del mensaje
- **Identificador y Número de secuencia**: Permiten asociar requests con replies

### 2.2 Protocolo ARP (Address Resolution Protocol)

**ARP** es un protocolo de la capa de enlace de datos (Capa 2 del modelo OSI) que resuelve direcciones IP (Capa 3) a direcciones MAC (Capa 2) dentro de una red local.

#### Funcionamiento de ARP:

1. **ARP Request**: Un host pregunta "¿Quién tiene la IP X.X.X.X?" mediante broadcast
2. **ARP Reply**: El host con esa IP responde con su dirección MAC

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
│  MAC destino (6 bytes)                   │  ← 00:00:00:00:00:00 en Request
├─────────────────────────────────────────┤
│  IP destino (4 bytes)                   │
└─────────────────────────────────────────┘
```

### 2.3 Modelo de Capas OSI/TCP-IP

El código trabaja con múltiples capas del modelo de red:

```
┌─────────────────────────────────────────┐
│  Capa 7: Aplicación                     │  ← Python/Scapy
├─────────────────────────────────────────┤
│  Capa 3: Red (IP)                       │  ← IP(dst=ip)
├─────────────────────────────────────────┤
│  Capa 2: Enlace de Datos (Ethernet)     │  ← Ether(dst="ff:ff:ff:ff:ff:ff")
├─────────────────────────────────────────┤
│  Capa 1: Física                         │  ← Tarjeta de red
└─────────────────────────────────────────┘
```

---

## Arquitectura del Sistema

### 3.1 Componentes Principales

El sistema está estructurado en una clase principal `ICMPScanner` que encapsula toda la funcionalidad de red:

```python
class ICMPScanner:
    - network_range: Rango de red a escanear
    - timeout: Tiempo de espera para respuestas
    - active_hosts: Diccionario de hosts activos
    - learned_macs: Tabla ARP aprendida (IP -> MAC)
    - known_hosts: Conjunto de IPs conocidas
```

### 3.2 Flujo General del Sistema

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
         ▼
┌─────────────────────────┐
│  Aprendizaje ARP        │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Monitoreo Continuo     │
└─────────────────────────┘
```

---

## Análisis Detallado del Código

### 4.1 Configuración Inicial y Dependencias

```python
from scapy.all import IP, ICMP, sr1, conf
import psutil
import ipaddress
```

#### Explicación de importaciones:

- **`IP`**: Clase de Scapy para construir encabezados IP (Capa 3)
- **`ICMP`**: Clase de Scapy para construir mensajes ICMP
- **`sr1`**: Función "send and receive 1" - envía un paquete y espera una respuesta
- **`conf`**: Objeto de configuración global de Scapy
- **`psutil`**: Biblioteca para obtener información del sistema, incluyendo interfaces de red
- **`ipaddress`**: Módulo estándar de Python para manipular direcciones IP y redes

#### Configuración de Scapy:

```python
conf.verb = 0
```

Esta línea desactiva la salida verbosa de Scapy. Los valores posibles son:
- `0`: Sin salida
- `1`: Solo errores
- `2`: Información básica
- `3`: Detallado

### 4.2 Detección Automática de Red Local

#### Función: `get_local_network()`

```python
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
```

#### Análisis línea por línea:

1. **`psutil.net_if_addrs()`**: 
   - Retorna un diccionario donde las claves son nombres de interfaces de red
   - Los valores son listas de objetos `snicaddr` con información de direcciones

2. **`addr.family == 2`**:
   - `family` indica el tipo de familia de direcciones
   - `2` corresponde a `socket.AF_INET` (IPv4)
   - `10` sería IPv6 (`socket.AF_INET6`)

3. **Filtrado de direcciones**:
   - `ip != "127.0.0.1"`: Excluye la interfaz loopback (localhost)
   - `not ip.startswith("169.254")`: Excluye direcciones APIPA (Auto-Configuration IP)
     - APIPA se asigna automáticamente cuando no hay servidor DHCP disponible

4. **Cálculo de red**:
   - `ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)`:
     - Combina la IP y la máscara de subred para calcular el rango de red
     - `strict=False` permite que la IP no sea exactamente la dirección de red
     - Ejemplo: `192.168.1.50/255.255.255.0` → `192.168.1.0/24`

#### Ejemplo práctico:

Si el sistema tiene:
- IP: `192.168.1.50`
- Máscara: `255.255.255.0`

El resultado será: `192.168.1.0/24`, que representa:
- Dirección de red: `192.168.1.0`
- Máscara: `/24` (24 bits = 255.255.255.0)
- Rango de hosts: `192.168.1.1` a `192.168.1.254`

### 4.3 Aprendizaje de Direcciones MAC mediante ARP

#### Función: `_learn_mac_via_arp(ip)`

```python
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
```

#### Análisis detallado:

##### 4.3.1 Construcción del paquete ARP

**Línea 1: Crear solicitud ARP**
```python
arp_request = ARP(pdst=ip)
```

- **`ARP(pdst=ip)`**: Crea un paquete ARP Request
  - `pdst`: Protocol destination (IP destino a resolver)
  - Por defecto, `op=1` (ARP Request)
  - `psrc`: IP origen (se completa automáticamente con la IP de la interfaz)

**Estructura interna del objeto ARP:**
```
ARP(
    hwtype=1,           # Ethernet
    ptype=0x800,        # IPv4
    hwlen=6,            # Longitud MAC (6 bytes)
    plen=4,             # Longitud IP (4 bytes)
    op=1,               # 1=Request, 2=Reply
    hwsrc=<tu MAC>,     # MAC origen (auto)
    psrc=<tu IP>,       # IP origen (auto)
    hwdst="00:00:00:00:00:00",  # MAC destino (desconocida)
    pdst=ip             # IP destino a resolver
)
```

##### 4.3.2 Encapsulación en Ethernet

**Línea 2-3: Frame Ethernet con broadcast**
```python
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_broadcast = broadcast / arp_request
```

- **`Ether(dst="ff:ff:ff:ff:ff:ff")`**: Crea un frame Ethernet
  - `dst="ff:ff:ff:ff:ff:ff"`: Dirección MAC de broadcast
  - Todos los dispositivos en la red local reciben este frame
  - `src`: Se completa automáticamente con la MAC de la interfaz

- **`broadcast / arp_request`**: Operador de composición de Scapy
  - Encapsula el paquete ARP dentro del frame Ethernet
  - Equivale a: Frame Ethernet → Paquete ARP

**Estructura completa del paquete:**

```
┌─────────────────────────────────────────┐
│  Ethernet Header                        │
│  - MAC destino: ff:ff:ff:ff:ff:ff       │  ← Broadcast
│  - MAC origen: aa:bb:cc:dd:ee:ff        │  ← Tu MAC
│  - Tipo: 0x0806 (ARP)                   │
├─────────────────────────────────────────┤
│  ARP Header                             │
│  - Operación: 1 (Request)               │
│  - IP origen: 192.168.1.50             │
│  - MAC origen: aa:bb:cc:dd:ee:ff       │
│  - IP destino: 192.168.1.100            │
│  - MAC destino: 00:00:00:00:00:00       │  ← Desconocida
└─────────────────────────────────────────┘
```

##### 4.3.3 Envío y Recepción

**Línea 4: Enviar y recibir respuesta**
```python
answered_list, _ = srp(arp_request_broadcast, timeout=1, verbose=0)
```

- **`srp()`**: "Send and Receive Packet" a nivel de capa 2 (Ethernet)
  - Diferencia con `sr1()`: `sr1()` trabaja a nivel IP, `srp()` a nivel Ethernet
  - Retorna una tupla: `(answered_list, unanswered_list)`
  - `timeout=1`: Espera máximo 1 segundo por respuesta
  - `verbose=0`: Sin salida

**Retorno de `srp()`:**
```python
answered_list = [
    (paquete_enviado, paquete_recibido),
    ...
]
```

##### 4.3.4 Extracción de la Dirección MAC

**Línea 5-6: Procesar respuesta**
```python
if answered_list:
    for element in answered_list:
        mac_address = element[1].hwsrc
```

- **`element[1]`**: El segundo elemento es el paquete recibido (ARP Reply)
- **`element[1].hwsrc`**: `hwsrc` = hardware source (dirección MAC del remitente)
- Esta es la MAC del host que respondió al ARP Request

**Estructura del ARP Reply recibido:**
```
ARP(
    op=2,                    # 2 = Reply
    hwsrc=aa:bb:cc:dd:ee:ff, # MAC del host que responde
    psrc=192.168.1.100,      # IP del host que responde
    hwdst=<tu MAC>,          # Tu MAC (destino)
    pdst=<tu IP>             # Tu IP (destino)
)
```

##### 4.3.5 Almacenamiento de la Información

**Línea 7: Guardar en tabla ARP**
```python
with self.macs_lock:
    self.learned_macs[ip] = mac_address
```

- Se almacena la correspondencia `IP → MAC` en un diccionario
- El uso de `lock` garantiza acceso thread-safe (evita condiciones de carrera)

### 4.4 Envío de Paquetes ICMP (Ping)

#### Función: `ping_host(ip, retries=2)`

```python
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
```

#### Análisis detallado:

##### 4.4.1 Construcción del Paquete ICMP

**Línea 1: Crear paquete IP con ICMP**
```python
packet = IP(dst=ip) / ICMP()
```

- **`IP(dst=ip)`**: Crea encabezado IP
  - `dst`: Dirección IP destino
  - `src`: Se completa automáticamente con la IP de la interfaz de salida
  - `ttl`: Time To Live (por defecto 64)
  - `proto`: Protocolo (se establece automáticamente a 1 para ICMP)

- **`ICMP()`**: Crea mensaje ICMP
  - Por defecto, `type=8` (Echo Request)
  - `code=0` (Echo Request)
  - `id` y `seq`: Se generan automáticamente

- **`IP() / ICMP()`**: Operador de composición
  - Encapsula ICMP dentro de IP
  - Scapy maneja automáticamente la encapsulación en Ethernet

**Estructura completa del paquete ICMP:**

```
┌─────────────────────────────────────────┐
│  Ethernet Header (L2)                   │
│  - MAC destino: [resuelto por ARP]      │
│  - MAC origen: [tu MAC]                 │
│  - Tipo: 0x0800 (IPv4)                  │
├─────────────────────────────────────────┤
│  IP Header (L3)                          │
│  - Versión: 4                           │
│  - IHL: 5                               │
│  - TTL: 64                              │
│  - Protocolo: 1 (ICMP)                 │
│  - IP origen: 192.168.1.50             │
│  - IP destino: 192.168.1.100           │
├─────────────────────────────────────────┤
│  ICMP Header (L3.5)                     │
│  - Tipo: 8 (Echo Request)               │
│  - Código: 0                            │
│  - Checksum: [calculado]                │
│  - Identificador: [auto]                │
│  - Número secuencia: [auto]             │
│  - Datos: [timestamp, etc.]             │
└─────────────────────────────────────────┘
```

##### 4.4.2 Envío y Medición de Latencia

**Línea 2-4: Enviar y medir tiempo**
```python
start_time = time.time()
reply = sr1(packet, timeout=self.timeout, verbose=0)
end_time = time.time()
```

- **`sr1()`**: "Send and Receive 1 packet"
  - Envía el paquete y espera exactamente una respuesta
  - Retorna `None` si no hay respuesta dentro del timeout
  - Trabaja a nivel IP (maneja automáticamente ARP si es necesario)

- **Medición de latencia**:
  - `time.time()` retorna segundos desde epoch (Unix timestamp)
  - La diferencia da el tiempo de ida y vuelta (RTT - Round Trip Time)

**Proceso interno de `sr1()`:**

```
1. Scapy verifica si conoce la MAC destino
   ├─ Si la conoce → Usa esa MAC
   └─ Si NO la conoce → Envía ARP Request primero
                        └─ Espera ARP Reply
                           └─ Usa la MAC aprendida

2. Construye frame Ethernet completo
   └─ Envía por la interfaz de red

3. Espera respuesta ICMP Echo Reply
   └─ Timeout si no hay respuesta
```

##### 4.4.3 Procesamiento de la Respuesta

**Línea 5-6: Calcular latencia**
```python
if reply:
    latency = (end_time - start_time) * 1000  # Convertir a ms
```

- Si `reply` no es `None`, el host respondió
- La latencia se convierte de segundos a milisegundos (×1000)

**Estructura del ICMP Echo Reply recibido:**

```
ICMP(
    type=0,              # 0 = Echo Reply
    code=0,
    id=<mismo del request>,
    seq=<mismo del request>,
    data=<mismo del request>
)
```

##### 4.4.4 Aprendizaje Condicional de MAC

**Línea 7-12: Verificar y aprender MAC**
```python
with self.macs_lock:
    mac_known = ip in self.learned_macs

if not mac_known:
    self._learn_mac_via_arp(ip)
else:
    print(f"[MAC-SKIP] Ya conocemos MAC de {ip}, omitiendo ARP")
```

**Optimización importante:**
- Solo se envía ARP Request si no se conoce la MAC
- Esto evita tráfico de red innecesario
- Scapy internamente puede hacer ARP, pero este código mantiene su propia tabla

**Nota sobre Scapy y ARP:**
- Scapy tiene su propia tabla ARP interna
- Esta tabla es independiente de la tabla ARP del sistema operativo
- Por eso el código mantiene `self.learned_macs` para evitar ARP redundantes

### 4.5 Escaneo Completo de Red

#### Función: `scan_network()`

```python
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
```

#### Análisis detallado:

##### 4.5.1 Parseo del Rango de Red

**Línea 1: Convertir string a objeto de red**
```python
network = ipaddress.IPv4Network(self.network_range, strict=False)
```

- **`IPv4Network`**: Clase del módulo `ipaddress` de Python
- **`strict=False`**: Permite que la IP no sea exactamente la dirección de red
  - Ejemplo: `192.168.1.50/24` se normaliza a `192.168.1.0/24`

**Ejemplo:**
```python
network = ipaddress.IPv4Network("192.168.1.0/24")
# network.hosts() genera: 192.168.1.1, 192.168.1.2, ..., 192.168.1.254
```

##### 4.5.2 Generación de Direcciones IP

**Línea 2: Iterar sobre hosts**
```python
for ip in network.hosts():
```

- **`network.hosts()`**: Generador que produce todas las direcciones IP válidas de la red
- Excluye:
  - Dirección de red (ej: `192.168.1.0`)
  - Dirección de broadcast (ej: `192.168.1.255`)

**Para una red /24:**
- Total de direcciones: 256
- Direcciones de red y broadcast: 2
- Hosts escaneables: 254

##### 4.5.3 Paralelización del Escaneo

**Línea 3-4: Control de concurrencia**
```python
if len(threads) >= 20:
    for t in threads:
        t.join()
    threads.clear()
```

- **Límite de 20 threads**: Evita saturar el sistema
- **`thread.join()`**: Espera a que el thread termine antes de crear más
- Esto crea un "pool" de threads con límite máximo

**Ventajas:**
- Escaneo más rápido que secuencial
- No satura recursos del sistema
- Control de ancho de banda de red

##### 4.5.4 Almacenamiento de Resultados

**Línea 5-8: Guardar información del host**
```python
host_info = {
    'latency': latency,
    'last_seen': current_time,
    'angle': hash(ip) % 360
}
```

- **`latency`**: Tiempo de respuesta en milisegundos
- **`last_seen`**: Timestamp de última vez que se vio activo
- **`angle`**: Ángulo calculado para visualización en radar (0-359°)

**Cálculo del ángulo:**
- `hash(ip)`: Genera un hash determinístico de la IP
- `% 360`: Módulo para obtener un ángulo entre 0-359°
- Mismo IP siempre genera el mismo ángulo

---

## Estructura de Paquetes de Red

### 5.1 Paquete ICMP Echo Request Completo

```
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET HEADER (14 bytes)                │
├─────────────────────────────────────────────────────────────┤
│  Destino MAC:    [Resuelto por ARP o tabla]                 │
│  Origen MAC:     aa:bb:cc:dd:ee:ff                          │
│  Tipo:           0x0800 (IPv4)                              │
├─────────────────────────────────────────────────────────────┤
│                    IP HEADER (20 bytes)                      │
├─────────────────────────────────────────────────────────────┤
│  Versión:        4                                           │
│  IHL:            5 (20 bytes)                               │
│  TOS:            0                                           │
│  Longitud total: 84 bytes                                    │
│  ID:             0x1234                                      │
│  Flags:          0 (Don't Fragment)                         │
│  Offset:         0                                           │
│  TTL:            64                                          │
│  Protocolo:      1 (ICMP)                                    │
│  Checksum:       0xABCD                                      │
│  IP Origen:      192.168.1.50                               │
│  IP Destino:     192.168.1.100                              │
├─────────────────────────────────────────────────────────────┤
│                   ICMP HEADER (8 bytes)                        │
├─────────────────────────────────────────────────────────────┤
│  Tipo:           8 (Echo Request)                           │
│  Código:         0                                           │
│  Checksum:       0xEF12                                      │
│  Identificador:  0x0001                                      │
│  Secuencia:      0x0000                                      │
├─────────────────────────────────────────────────────────────┤
│                    ICMP DATA (variable)                      │
├─────────────────────────────────────────────────────────────┤
│  Timestamp:      [tiempo actual]                            │
│  Datos:          [datos adicionales]                        │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Paquete ARP Request Completo

```
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET HEADER (14 bytes)                │
├─────────────────────────────────────────────────────────────┤
│  Destino MAC:    ff:ff:ff:ff:ff:ff (Broadcast)              │
│  Origen MAC:     aa:bb:cc:dd:ee:ff                          │
│  Tipo:           0x0806 (ARP)                                │
├─────────────────────────────────────────────────────────────┤
│                    ARP HEADER (28 bytes)                     │
├─────────────────────────────────────────────────────────────┤
│  Tipo Hardware:  1 (Ethernet)                               │
│  Tipo Protocolo: 0x0800 (IPv4)                              │
│  Long. Hardware: 6 (bytes)                                  │
│  Long. Protocolo: 4 (bytes)                                 │
│  Operación:      1 (ARP Request)                             │
│  MAC Origen:     aa:bb:cc:dd:ee:ff                          │
│  IP Origen:      192.168.1.50                               │
│  MAC Destino:    00:00:00:00:00:00 (desconocida)            │
│  IP Destino:     192.168.1.100                              │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 Paquete ARP Reply

```
┌─────────────────────────────────────────────────────────────┐
│                    ETHERNET HEADER (14 bytes)                │
├─────────────────────────────────────────────────────────────┤
│  Destino MAC:    aa:bb:cc:dd:ee:ff (tu MAC)                 │
│  Origen MAC:     11:22:33:44:55:66 (MAC del host)           │
│  Tipo:           0x0806 (ARP)                                │
├─────────────────────────────────────────────────────────────┤
│                    ARP HEADER (28 bytes)                     │
├─────────────────────────────────────────────────────────────┤
│  Tipo Hardware:  1 (Ethernet)                               │
│  Tipo Protocolo: 0x0800 (IPv4)                              │
│  Long. Hardware: 6 (bytes)                                   │
│  Long. Protocolo: 4 (bytes)                                 │
│  Operación:      2 (ARP Reply)                               │
│  MAC Origen:     11:22:33:44:55:66 (MAC del host)          │
│  IP Origen:      192.168.1.100                              │
│  MAC Destino:    aa:bb:cc:dd:ee:ff (tu MAC)                 │
│  IP Destino:     192.168.1.50                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Flujos de Comunicación

### 6.1 Flujo Completo: Primer Ping a un Host

```
┌──────────┐                    ┌──────────┐
│  Cliente │                    │  Servidor│
└────┬─────┘                    └────┬─────┘
     │                               │
     │  1. ICMP Echo Request         │
     │  IP: 192.168.1.100            │
     │  MAC: ? (desconocida)         │
     ├───────────────────────────────>│
     │                               │
     │  2. Scapy necesita MAC        │
     │  → Envía ARP Request          │
     │                               │
     │  3. ARP Request (Broadcast)   │
     │  "¿Quién tiene 192.168.1.100?"│
     ├───────────────────────────────>│
     │                               │
     │  4. ARP Reply                 │
     │  "192.168.1.100 = 11:22:33..."│
     │<───────────────────────────────┤
     │                               │
     │  5. Guarda MAC en tabla      │
     │  learned_macs[IP] = MAC       │
     │                               │
     │  6. ICMP Echo Request         │
     │  (con MAC conocida)           │
     ├───────────────────────────────>│
     │                               │
     │  7. ICMP Echo Reply           │
     │<───────────────────────────────┤
     │                               │
     │  8. Calcula latencia          │
     │  Guarda host activo           │
     │                               │
```

### 6.2 Flujo: Ping Subsecuente (MAC Conocida)

```
┌──────────┐                    ┌──────────┐
│  Cliente │                    │  Servidor│
└────┬─────┘                    └────┬─────┘
     │                               │
     │  1. Verifica tabla ARP        │
     │  MAC conocida? ✓              │
     │                               │
     │  2. ICMP Echo Request         │
     │  (usa MAC de tabla)           │
     ├───────────────────────────────>│
     │                               │
     │  3. ICMP Echo Reply           │
     │<───────────────────────────────┤
     │                               │
     │  4. Actualiza latencia        │
     │                               │
```

**Optimización:** No se envía ARP Request, se usa la MAC ya conocida.

### 6.3 Flujo: Escaneo Completo de Red

```
Inicio
  │
  ├─> Parsear rango de red (ej: 192.168.1.0/24)
  │
  ├─> Generar lista de IPs (192.168.1.1 a 192.168.1.254)
  │
  ├─> Para cada IP (en paralelo, max 20 threads):
  │     │
  │     ├─> ping_host(ip)
  │     │     │
  │     │     ├─> Construir paquete: IP(dst=ip) / ICMP()
  │     │     │
  │     │     ├─> Enviar con sr1()
  │     │     │     │
  │     │     │     └─> Scapy verifica MAC
  │     │     │           │
  │     │     │           ├─> Si MAC conocida → Usar
  │     │     │           │
  │     │     │           └─> Si MAC desconocida → ARP Request
  │     │     │
  │     │     ├─> Si respuesta recibida:
  │     │     │     │
  │     │     │     ├─> Calcular latencia
  │     │     │     │
  │     │     │     ├─> Si MAC no conocida:
  │     │     │     │     └─> _learn_mac_via_arp(ip)
  │     │     │     │
  │     │     │     └─> Retornar (ip, latency)
  │     │     │
  │     │     └─> Si no hay respuesta:
  │     │           └─> Retornar (ip, None)
  │     │
  │     └─> Si respuesta exitosa:
  │           └─> Agregar a results[]
  │
  ├─> Procesar todos los resultados
  │
  ├─> Para cada host activo:
  │     │
  │     ├─> Crear host_info {
  │     │     latency: X ms,
  │     │     last_seen: timestamp,
  │     │     angle: hash(ip) % 360
  │     │   }
  │     │
  │     └─> Guardar en active_hosts[ip]
  │
  └─> Fin
```

---

## Consideraciones Técnicas

### 7.1 Resolución de Direcciones MAC

#### Problema: Scapy vs Sistema Operativo

Scapy mantiene su **propia tabla ARP interna**, separada de la tabla ARP del sistema operativo. Esto significa:

- **Tabla ARP del SO**: Windows/Linux mantiene su propia tabla
- **Tabla ARP de Scapy**: Scapy tiene una tabla independiente
- **Sincronización**: No hay sincronización automática entre ambas

**Solución implementada:**
```python
self.learned_macs = {}  # Tabla ARP propia del código
```

El código mantiene su propia tabla para:
1. Evitar ARP Requests redundantes
2. Tener control sobre qué MACs se conocen
3. Optimizar el rendimiento

#### Proceso de Resolución

```
1. Cliente quiere hacer ping a 192.168.1.100
   │
   ├─> ¿MAC conocida en self.learned_macs?
   │     │
   │     ├─> SÍ → Usar MAC conocida
   │     │
   │     └─> NO → Enviar ARP Request
   │               │
   │               ├─> Esperar ARP Reply
   │               │
   │               └─> Guardar en self.learned_macs
   │
   └─> Construir paquete ICMP con MAC conocida
```

### 7.2 Timeouts y Reintentos

#### Timeout de ICMP
```python
timeout=self.timeout  # Por defecto 0.5 segundos
```

- **Timeout corto (0.5s)**: Escaneo más rápido
- **Desventaja**: Puede perder hosts con latencia alta
- **Balance**: Entre velocidad y completitud

#### Reintentos
```python
retries=2  # 3 intentos totales (1 inicial + 2 reintentos)
```

- **Primer intento**: Ping inicial
- **Reintentos**: Si falla, espera 0.1s y reintenta
- **Total**: Hasta 3 intentos por host

**Justificación:**
- Algunos hosts pueden tardar en responder
- Redes con alta latencia requieren más tiempo
- Balance entre exhaustividad y velocidad

### 7.3 Paralelización y Control de Concurrencia

#### Límite de Threads
```python
if len(threads) >= 20:
    # Esperar a que terminen antes de crear más
```

**Razones del límite:**
1. **Recursos del sistema**: Demasiados threads consumen memoria
2. **Ancho de banda**: Evita saturar la red
3. **Rendimiento**: Demasiada concurrencia puede degradar el rendimiento

**Cálculo:**
- Red /24: 254 hosts
- 20 threads concurrentes
- Tiempo estimado: ~13 ciclos (254/20 ≈ 12.7)

### 7.4 Manejo de Errores

#### Errores Silenciados
```python
except Exception as e:
    # Si falla ARP, no es crítico
    pass
```

**Filosofía:**
- ARP puede fallar por múltiples razones (firewall, host apagado, etc.)
- No es crítico para el funcionamiento del ping
- El ping puede funcionar aunque ARP falle (Scapy lo maneja internamente)

#### Errores en Escaneo
```python
except Exception as e:
    print(f"Error durante el escaneo: {e}")
```

- Errores de red se registran pero no detienen el escaneo
- Permite continuar con otros hosts aunque algunos fallen

---

## Conceptos Avanzados

### 8.1 Diferencias entre `sr1()` y `srp()`

#### `sr1()` - Send and Receive 1 (Nivel IP)
```python
reply = sr1(IP(dst=ip) / ICMP(), timeout=1)
```

- **Nivel**: Trabaja a nivel IP (Capa 3)
- **ARP automático**: Scapy maneja ARP internamente si es necesario
- **Uso**: Para protocolos de capa 3 (ICMP, TCP, UDP)

#### `srp()` - Send and Receive Packet (Nivel Ethernet)
```python
answered, _ = srp(Ether() / ARP(), timeout=1)
```

- **Nivel**: Trabaja a nivel Ethernet (Capa 2)
- **Control total**: Tú controlas la construcción completa del frame
- **Uso**: Para protocolos de capa 2 (ARP, protocolos personalizados)

**En este código:**
- `sr1()` se usa para ICMP (ping)
- `srp()` se usa para ARP (aprendizaje de MAC)

### 8.2 Composición de Paquetes en Scapy

#### Operador `/` (División)
```python
packet = IP(dst=ip) / ICMP()
```

El operador `/` en Scapy significa "encapsular" o "componer":

```
IP(dst=ip) / ICMP()
    ↓
┌─────────┐
│   IP    │ ← Capa externa
├─────────┤
│  ICMP   │ ← Capa interna
└─────────┘
```

**Múltiples capas:**
```python
Ether() / IP() / ICMP()
    ↓
┌──────────┐
│  Ether   │ ← Capa más externa
├──────────┤
│   IP     │
├──────────┤
│  ICMP    │ ← Capa más interna
└──────────┘
```

### 8.3 Campos Automáticos en Scapy

Scapy completa automáticamente muchos campos:

```python
packet = IP(dst="192.168.1.100") / ICMP()
```

**Campos completados automáticamente:**
- `src`: IP de la interfaz de salida
- `ttl`: 64 (por defecto)
- `id`: Número de identificación único
- `checksum`: Calculado automáticamente
- `len`: Longitud total calculada

**Campos de ICMP completados:**
- `type`: 8 (Echo Request) por defecto
- `id`: Identificador del proceso
- `seq`: Número de secuencia

### 8.4 Tabla ARP del Sistema vs Scapy

#### Tabla ARP del Sistema Operativo

**Windows:**
```cmd
arp -a
```

**Linux:**
```bash
arp -a
# o
ip neigh show
```

Esta tabla es **independiente** de la tabla de Scapy.

#### Tabla ARP de Scapy

Scapy mantiene su propia tabla en memoria:
```python
from scapy.all import getmacbyip
mac = getmacbyip("192.168.1.100")
```

**Problema:** Esta tabla puede estar vacía aunque el SO tenga la entrada.

**Solución del código:** Mantener `self.learned_macs` para control propio.

---

## Conclusiones

### Resumen Técnico

Este sistema implementa un escáner de red completo que:

1. **Detecta automáticamente** la configuración de red local
2. **Escanea hosts activos** mediante protocolo ICMP (ping)
3. **Aprende direcciones MAC** mediante protocolo ARP
4. **Mantiene estado** de hosts activos con latencia y timestamps
5. **Optimiza el rendimiento** evitando ARP redundantes

### Aspectos Destacables

- **Uso correcto de protocolos**: ICMP para descubrimiento, ARP para resolución
- **Optimización de red**: Cacheo de direcciones MAC para evitar tráfico innecesario
- **Paralelización eficiente**: Control de concurrencia para balancear velocidad y recursos
- **Manejo robusto**: Timeouts, reintentos y manejo de errores apropiado

### Aplicaciones Prácticas

- **Administración de red**: Descubrimiento de dispositivos en red local
- **Monitoreo**: Seguimiento de disponibilidad y latencia de hosts
- **Seguridad**: Identificación de dispositivos no autorizados
- **Diagnóstico**: Detección de problemas de conectividad

### Mejoras Potenciales

1. **Integración con tabla ARP del SO**: Consultar tabla del sistema antes de enviar ARP
2. **Escaneo de puertos**: Extender para detectar servicios activos
3. **Detección de OS**: Fingerprinting de sistemas operativos
4. **Persistencia**: Guardar tabla ARP aprendida en disco
5. **IPv6**: Soporte para escaneo IPv6

---

## Referencias Técnicas

### Protocolos

- **RFC 792**: Internet Control Message Protocol (ICMP)
- **RFC 826**: Ethernet Address Resolution Protocol (ARP)
- **RFC 791**: Internet Protocol (IP)

### Bibliotecas

- **Scapy**: https://scapy.net/
- **psutil**: https://psutil.readthedocs.io/
- **ipaddress**: Módulo estándar de Python 3.3+

### Modelos de Red

- **Modelo OSI**: 7 capas
- **Modelo TCP/IP**: 4 capas
- **Encapsulación**: Ethernet → IP → ICMP/ARP

---

**Documento generado para análisis académico**
**Fecha**: 2024
**Autor**: Análisis técnico de código ICMP Scanner


# DETECCIÓN AUTOMÁTICA DE RED CON PSUTIL
## Paso Previo al Escaneo ICMP y ARP

---

## 1. INTRODUCCIÓN: ¿POR QUÉ DETECTAR LA RED PRIMERO?

Antes de poder escanear una red con ICMP o ARP, el sistema necesita conocer información fundamental:

1. **¿En qué red estamos?** - Necesitamos saber el rango de direcciones IP a escanear
2. **¿Cuál es nuestra IP?** - Para saber desde dónde escaneamos
3. **¿Cuál es la máscara de subred?** - Para calcular el rango completo de la red

**Problema sin detección automática:**
- El usuario tendría que especificar manualmente: `192.168.1.0/24`
- No funcionaría en diferentes redes (casa, oficina, etc.)
- Requeriría conocimiento técnico del usuario

**Solución: Detección automática con psutil**
- El sistema detecta automáticamente la red local
- Funciona en cualquier red sin configuración
- Transparente para el usuario

---

## 2. ¿QUÉ ES PSUTIL?

### 2.1 Definición

**psutil** (process and system utilities) es una biblioteca multiplataforma de Python que proporciona una interfaz para obtener información del sistema y procesos en ejecución. Fue desarrollada por Stefano Giampaolo y es ampliamente utilizada para monitoreo de sistemas (Giampaolo, 2024).

**Características principales:**
- **Multiplataforma**: Funciona en Windows, Linux, macOS, BSD
- **Información del sistema**: CPU, memoria, discos, red
- **Información de procesos**: Procesos en ejecución, uso de recursos
- **Información de red**: Interfaces de red, direcciones IP, estadísticas

**Referencia:**
- Giampaolo, S. (2024). *psutil: Cross-platform lib for process and system monitoring in Python*. https://psutil.readthedocs.io/

### 2.2 Funciones de Red en psutil

psutil proporciona varias funciones relacionadas con redes:

**1. `psutil.net_if_addrs()`**
- Retorna un diccionario con todas las interfaces de red
- Para cada interfaz, proporciona direcciones IP, MAC, máscaras de subred
- **Uso en el proyecto**: Obtener la IP y máscara de la interfaz activa

**2. `psutil.net_if_stats()`**
- Proporciona estadísticas de interfaces de red
- Estado (up/down), velocidad, tipo de conexión
- **Uso en el proyecto**: Identificar interfaces activas

**3. `psutil.net_io_counters()`**
- Contadores de tráfico de red (bytes enviados/recibidos)
- **Uso en el proyecto**: No utilizado directamente, pero disponible

---

## 3. DETECCIÓN AUTOMÁTICA DE RED: IMPLEMENTACIÓN

### 3.1 Función `get_local_network()`

Esta función es el **primer paso** en el proceso de escaneo. Se ejecuta antes de cualquier operación con Scapy o ICMP:

```python
def get_local_network(self):
    """
    Detecta automáticamente la red local
    
    Proceso:
    1. Obtiene todas las interfaces de red con psutil
    2. Busca una interfaz IPv4 activa
    3. Extrae IP y máscara de subred
    4. Calcula el rango completo de la red
    5. Retorna el rango en formato CIDR (ej: "192.168.1.0/24")
    """
    try:
        # Obtener todas las interfaces de red
        for interface, addrs in psutil.net_if_addrs().items():
            # Iterar sobre todas las direcciones de cada interfaz
            for addr in addrs:
                # Filtrar solo direcciones IPv4
                if addr.family == 2:  # 2 = IPv4 (socket.AF_INET)
                    ip = addr.address
                    netmask = addr.netmask
                    
                    # Filtrar direcciones no válidas:
                    # - 127.0.0.1 (localhost)
                    # - 169.254.x.x (link-local, sin DHCP)
                    if ip != "127.0.0.1" and not ip.startswith("169.254"):
                        # Calcular la red completa usando ipaddress
                        network = ipaddress.IPv4Network(
                            f"{ip}/{netmask}", 
                            strict=False
                        )
                        return str(network)  # Retorna "192.168.1.0/24"
    except:
        pass
    
    # Fallback si no se encuentra ninguna red
    return "192.168.1.0/24"
```

### 3.2 Explicación Paso a Paso

**Paso 1: Obtener interfaces de red**
```python
for interface, addrs in psutil.net_if_addrs().items():
```
- `psutil.net_if_addrs()` retorna un diccionario
- Clave: nombre de la interfaz (ej: "Ethernet", "Wi-Fi", "eth0")
- Valor: lista de direcciones asociadas a esa interfaz

**Ejemplo de salida:**
```python
{
    'Ethernet': [
        snicaddr(family=2, address='192.168.1.50', netmask='255.255.255.0', ...),
        snicaddr(family=23, address='fe80::...', ...)  # IPv6
    ],
    'Wi-Fi': [
        snicaddr(family=2, address='192.168.1.100', netmask='255.255.255.0', ...)
    ],
    'Loopback': [
        snicaddr(family=2, address='127.0.0.1', netmask='255.0.0.0', ...)
    ]
}
```

**Paso 2: Filtrar direcciones IPv4**
```python
if addr.family == 2:  # socket.AF_INET = 2
```
- `family` indica el tipo de dirección:
  - `2` = IPv4 (AF_INET)
  - `23` = IPv6 (AF_INET6)
  - `17` = MAC address (AF_LINK)

**Paso 3: Filtrar direcciones válidas**
```python
if ip != "127.0.0.1" and not ip.startswith("169.254"):
```
- **127.0.0.1**: Loopback (localhost), no es una red real
- **169.254.x.x**: Link-local (APIPA), asignada cuando no hay DHCP
- Solo queremos direcciones IP reales de la red local

**Paso 4: Calcular rango de red**
```python
network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
```
- Usa el módulo `ipaddress` de Python (estándar)
- Combina IP y máscara para calcular la red completa
- `strict=False` permite cálculos flexibles

**Ejemplo:**
- IP: `192.168.1.50`
- Máscara: `255.255.255.0`
- Red calculada: `192.168.1.0/24`
- Rango de IPs: `192.168.1.1` a `192.168.1.254`

### 3.3 Estructura de Datos Retornada

La función retorna un string en formato CIDR (Classless Inter-Domain Routing):

```
"192.168.1.0/24"
```

**Desglose:**
- `192.168.1.0`: Dirección de red (primera IP del rango)
- `/24`: Prefijo de red (24 bits = 255.255.255.0)
- Indica que hay 256 direcciones posibles (2^8)
- Rango útil: 192.168.1.1 a 192.168.1.254 (254 hosts)

---

## 4. INTEGRACIÓN EN EL FLUJO DEL SISTEMA

### 4.1 Orden de Ejecución

La detección de red es el **primer paso** antes de cualquier operación de red:

```
┌─────────────────────────────────────────┐
│  1. INICIALIZACIÓN                      │
│     - Crear ICMPScanner                 │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  2. DETECCIÓN DE RED (psutil)           │
│     - get_local_network()               │
│     - Obtener IP y máscara              │
│     - Calcular rango CIDR               │
│     - Retorna: "192.168.1.0/24"         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  3. CONFIGURACIÓN                       │
│     - Asignar rango a network_range      │
│     - Preparar estructuras de datos     │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  4. ESCANEO ICMP (Scapy)                │
│     - Usa network_range para escanear   │
│     - Envía pings a todas las IPs       │
└─────────────────────────────────────────┘
```

### 4.2 Código de Integración

**En `icmp_radar.py` (aplicación principal):**

```python
def _setup_network(self):
    """
    Configura el rango de red a escanear
    """
    if self.network_range:
        # Usuario especificó red manualmente
        self.scanner.network_range = self.network_range
    else:
        # DETECCIÓN AUTOMÁTICA (primer paso)
        detected_network = self.scanner.get_local_network()
        self.scanner.network_range = detected_network
        print(f"[NETWORK] Red detectada: {detected_network}")
```

**Flujo completo:**

```python
# 1. Crear scanner
scanner = ICMPScanner()

# 2. DETECCIÓN AUTOMÁTICA (antes de Scapy/ICMP)
local_network = scanner.get_local_network()
# Retorna: "192.168.1.0/24"

# 3. Configurar rango
scanner.network_range = local_network

# 4. AHORA SÍ: Escanear con ICMP (Scapy)
scanner.scan_network()
```

---

## 5. VENTAJAS DE LA DETECCIÓN AUTOMÁTICA

### 5.1 Para el Usuario

- **Sin configuración**: No necesita saber su IP o máscara
- **Funciona en cualquier red**: Casa, oficina, laboratorio
- **Transparente**: El sistema lo hace automáticamente

### 5.2 Para el Sistema

- **Precisión**: Obtiene la configuración real del sistema
- **Flexibilidad**: Funciona en diferentes sistemas operativos
- **Robustez**: Tiene fallback si falla la detección

### 5.3 Ejemplos de Uso

**Escenario 1: Red doméstica**
- Usuario en casa con router 192.168.1.1
- Sistema detecta: `192.168.1.0/24`
- Escanea: 192.168.1.1 a 192.168.1.254

**Escenario 2: Red corporativa**
- Usuario en oficina con red 10.0.0.0/16
- Sistema detecta: `10.0.0.0/16`
- Escanea: 10.0.0.1 a 10.0.255.254

**Escenario 3: Red universitaria**
- Usuario en campus con red 172.16.0.0/12
- Sistema detecta: `172.16.0.0/12`
- Escanea el rango correspondiente

---

## 6. MÓDULO IPADDRESS DE PYTHON

### 6.1 ¿Qué es?

El módulo `ipaddress` es parte de la biblioteca estándar de Python (desde Python 3.3). Proporciona clases para trabajar con direcciones IP y redes.

**Uso en el proyecto:**
```python
import ipaddress

# Crear objeto de red desde IP y máscara
network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

# Convertir a string CIDR
network_str = str(network)  # "192.168.1.0/24"

# Obtener todas las IPs del rango
for ip in network.hosts():
    print(ip)  # 192.168.1.1, 192.168.1.2, ...
```

### 6.2 Funcionalidades Utilizadas

**1. Cálculo de red desde IP y máscara:**
```python
ipaddress.IPv4Network("192.168.1.50/255.255.255.0", strict=False)
# Retorna: IPv4Network('192.168.1.0/24')
```

**2. Iteración sobre hosts:**
```python
network = ipaddress.IPv4Network("192.168.1.0/24")
for host in network.hosts():
    # host es un objeto IPv4Address
    # Útil para escanear todas las IPs
```

---

## 7. COMPARACIÓN: CON Y SIN DETECCIÓN AUTOMÁTICA

### 7.1 Sin Detección Automática (Manual)

```python
# Usuario debe especificar manualmente
scanner = ICMPScanner(network_range="192.168.1.0/24")

# Problemas:
# - No funciona si cambia de red
# - Requiere conocimiento técnico
# - Propenso a errores
```

### 7.2 Con Detección Automática

```python
# Sistema detecta automáticamente
scanner = ICMPScanner()
network = scanner.get_local_network()  # "192.168.1.0/24"
scanner.network_range = network

# Ventajas:
# - Funciona en cualquier red
# - Transparente para el usuario
# - Sin errores de configuración
```

---

## 8. CASOS ESPECIALES Y MANEJO DE ERRORES

### 8.1 Múltiples Interfaces

Si el sistema tiene múltiples interfaces (Ethernet + Wi-Fi):

```python
# psutil retorna todas las interfaces
# El código toma la PRIMERA interfaz válida encontrada
# Normalmente es la interfaz activa principal
```

### 8.2 Sin Red Conectada

Si no hay red conectada:

```python
# El código retorna fallback
return "192.168.1.0/24"  # Red por defecto

# El escaneo intentará esta red
# Si no hay hosts, simplemente no encontrará nada
```

### 8.3 Redes Link-Local (169.254.x.x)

Las direcciones 169.254.x.x se filtran porque:
- Son asignadas automáticamente cuando no hay DHCP
- No representan una red real configurada
- Generalmente indican problemas de conectividad

---

## 9. RESUMEN: FLUJO COMPLETO

```
INICIO
  │
  ├─> [1] psutil.net_if_addrs()
  │     └─> Obtiene todas las interfaces de red
  │
  ├─> [2] Filtrar interfaz IPv4 activa
  │     └─> Excluir: localhost, link-local
  │
  ├─> [3] Extraer IP y máscara
  │     └─> Ejemplo: IP=192.168.1.50, Mask=255.255.255.0
  │
  ├─> [4] Calcular red con ipaddress
  │     └─> Resultado: "192.168.1.0/24"
  │
  ├─> [5] Configurar network_range
  │     └─> scanner.network_range = "192.168.1.0/24"
  │
  └─> [6] AHORA SÍ: Usar Scapy para ICMP/ARP
        └─> Escanear todas las IPs del rango
```

---

## REFERENCIAS

1. Giampaolo, S. (2024). *psutil: Cross-platform lib for process and system monitoring in Python*. https://psutil.readthedocs.io/

2. Python Software Foundation. (2024). *ipaddress — IPv4/IPv6 manipulation library*. Python 3.12 Documentation. https://docs.python.org/3/library/ipaddress.html

3. Postel, J., & Reynolds, J. (1985). *File Transfer Protocol (FTP)*. RFC 959. Internet Engineering Task Force. (Para contexto de direccionamiento IP)

---

**Nota para el informe:**
Esta sección debe ir **ANTES** de la sección de Scapy e ICMP, ya que es el paso previo necesario. Explica:
- Por qué es necesario detectar la red primero
- Cómo funciona psutil
- Cómo se implementa la detección automática
- Cómo se integra en el flujo del sistema

El orden lógico en el informe sería:
1. Detección automática de red (psutil) ← ESTA SECCIÓN
2. Construcción de paquetes con Scapy
3. Escaneo ICMP
4. Aprendizaje ARP


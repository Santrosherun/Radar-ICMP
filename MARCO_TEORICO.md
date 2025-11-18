# MARCO TEÓRICO E INVESTIGATIVO
## Fundamentos de Redes y Protocolos Utilizados

---

## 1. SCAPY: BIBLIOTECA DE MANIPULACIÓN DE PAQUETES DE RED

### 1.1 Definición y Características

Scapy es una biblioteca de manipulación de paquetes de red escrita en Python, desarrollada por Philippe Biondi. Permite la creación, envío, recepción y análisis de paquetes de red a nivel de protocolo, proporcionando control granular sobre todos los campos de los protocolos de red (Postel, 1981; Biondi & Desclaux, 2024).

**Características principales:**
- **Construcción de paquetes**: Permite crear paquetes personalizados especificando cada campo del protocolo
- **Inyección de paquetes**: Capacidad de enviar paquetes directamente a la red, bypassing las capas superiores del sistema operativo
- **Captura y análisis**: Puede capturar y analizar tráfico de red en tiempo real
- **Decodificación automática**: Interpreta automáticamente los protocolos de los paquetes capturados
- **Flexibilidad**: Soporta más de 200 protocolos de red diferentes

**Referencias:**
- Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/
- Wikipedia Contributors. (2024). *Scapy*. Wikipedia. https://en.wikipedia.org/wiki/Scapy

### 1.2 Uso de Scapy en el Proyecto

En este proyecto, Scapy se utiliza como herramienta fundamental para:

**1. Construcción de paquetes ICMP:**
```python
from scapy.all import IP, ICMP, sr1

# Crear paquete ICMP Echo Request
packet = IP(dst="192.168.1.100") / ICMP()
reply = sr1(packet, timeout=0.5, verbose=0)
```

**2. Construcción de paquetes ARP:**
```python
from scapy.all import ARP, Ether, srp

# Crear solicitud ARP
arp_request = ARP(pdst="192.168.1.100")
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_packet = broadcast / arp_request
answered_list, _ = srp(arp_packet, timeout=1, verbose=0)
```

**3. Funciones principales utilizadas:**
- `IP()`: Construye encabezado IP con dirección destino
- `ICMP()`: Construye encabezado ICMP (por defecto tipo 8, Echo Request)
- `ARP()`: Construye paquete ARP para solicitar dirección MAC
- `Ether()`: Construye encabezado Ethernet para broadcast
- `sr1()`: Envía paquete y espera una respuesta (send and receive 1)
- `srp()`: Envía paquete en capa 2 y espera respuestas (send and receive packet)

**Ventajas de usar Scapy:**
- Control total sobre los campos de los protocolos
- No requiere herramientas externas (ping, arp) del sistema operativo
- Permite implementar funcionalidades personalizadas
- Facilita el desarrollo de herramientas de diagnóstico de red

---

## 2. PROTOCOLO ICMP (INTERNET CONTROL MESSAGE PROTOCOL)

### 2.1 Definición y Propósito

El Protocolo de Mensajes de Control de Internet (ICMP) es un protocolo de la capa de red (Capa 3 del modelo OSI) que forma parte del conjunto de protocolos TCP/IP. Fue definido en el RFC 792 por Jon Postel en 1981 y está diseñado para el intercambio de mensajes de control y diagnóstico entre dispositivos de red (Postel, 1981).

**Propósito principal:**
- Reportar errores en la entrega de paquetes IP
- Proporcionar información sobre problemas de red
- Facilitar herramientas de diagnóstico como ping y traceroute
- Permitir la comunicación de control entre routers y hosts

**Referencias:**
- Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force. https://tools.ietf.org/html/rfc792
- Braden, R. (Ed.). (1989). *Requirements for Internet Hosts -- Communication Layers*. RFC 1122. Internet Engineering Task Force. https://tools.ietf.org/html/rfc1122

### 2.2 Estructura del Mensaje ICMP

Un mensaje ICMP está encapsulado dentro de un datagrama IP y tiene la siguiente estructura:

```
┌─────────────────────────────────────────┐
│  Tipo (8 bits)      │  Código (8 bits)  │
├─────────────────────────────────────────┤
│  Checksum (16 bits)                     │
├─────────────────────────────────────────┤
│  Identificador (16 bits)                 │
├─────────────────────────────────────────┤
│  Número de secuencia (16 bits)          │
├─────────────────────────────────────────┤
│  Datos (variable)                       │
└─────────────────────────────────────────┘
```

**Campos principales:**
- **Tipo (Type)**: Identifica el tipo de mensaje ICMP
- **Código (Code)**: Proporciona información adicional sobre el tipo de mensaje
- **Checksum**: Verificación de integridad del mensaje
- **Identificador y Secuencia**: Usados en mensajes Echo Request/Reply para emparejar solicitudes con respuestas
- **Datos**: Información adicional específica del tipo de mensaje

### 2.3 Tipos de Mensajes ICMP Relevantes

**Tipo 0 - Echo Reply:**
- Respuesta a un Echo Request
- Utilizado por la herramienta ping para confirmar conectividad
- Código: 0

**Tipo 8 - Echo Request:**
- Solicitud de eco, comúnmente conocido como "ping"
- Utilizado para verificar si un host está activo y accesible
- Código: 0
- **Uso en el proyecto**: Este es el tipo principal utilizado para descubrir hosts activos

**Tipo 13 - Timestamp Request:**
- Solicita el timestamp del sistema remoto
- Útil para sincronización de tiempo y diagnóstico
- Código: 0
- **Uso en el proyecto**: Implementado como funcionalidad avanzada para pruebas

**Tipo 15 - Information Request:**
- Solicita información de red (obsoleto en IPv4)
- Código: 0
- **Uso en el proyecto**: Implementado para compatibilidad y pruebas

**Tipo 17 - Address Mask Request:**
- Solicita la máscara de subred del host remoto
- Útil para descubrimiento de red
- Código: 0
- **Uso en el proyecto**: Implementado como funcionalidad avanzada

### 2.4 Funcionamiento del Ping (ICMP Echo Request/Reply)

El proceso de ping utiliza ICMP de la siguiente manera:

1. **Host origen** crea un paquete ICMP Echo Request (Tipo 8)
2. El paquete se encapsula en un datagrama IP y se envía al host destino
3. **Host destino** recibe el paquete y responde con un ICMP Echo Reply (Tipo 0)
4. El host origen mide el tiempo de ida y vuelta (RTT - Round Trip Time)
5. Si no hay respuesta dentro del timeout, se considera que el host no está disponible

**Fórmula de latencia:**
```
RTT = Tiempo_Respuesta - Tiempo_Envío
```

**Uso en el proyecto:**
El sistema implementa ping mediante Scapy para:
- Descubrir hosts activos en la red
- Medir latencia (tiempo de respuesta)
- Monitorear el estado de conectividad de hosts conocidos
- Detectar hosts que han dejado de responder

---

## 3. PROTOCOLO ARP (ADDRESS RESOLUTION PROTOCOL)

### 3.1 Definición y Propósito

El Protocolo de Resolución de Direcciones (ARP) es un protocolo de la capa de enlace de datos (Capa 2 del modelo OSI) definido en el RFC 826 por David C. Plummer en 1982. Su función principal es resolver direcciones IP (Capa 3) a direcciones MAC (Capa 2) dentro de una red local (Plummer, 1982).

**Problema que resuelve:**
Cuando un dispositivo necesita enviar un paquete a otro dispositivo en la misma red local, necesita conocer la dirección MAC del destino. Sin embargo, las aplicaciones solo conocen la dirección IP. ARP resuelve esta discrepancia.

**Referencias:**
- Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol: Or Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware*. RFC 826. Internet Engineering Task Force. https://tools.ietf.org/html/rfc826
- Wikipedia Contributors. (2024). *Address Resolution Protocol*. Wikipedia. https://es.wikipedia.org/wiki/Protocolo_de_resoluci%C3%B3n_de_direcciones

### 3.2 Estructura del Paquete ARP

Un paquete ARP tiene la siguiente estructura:

```
┌─────────────────────────────────────────┐
│  Tipo de hardware (2 bytes)             │  ← Ethernet = 1
├─────────────────────────────────────────┤
│  Tipo de protocolo (2 bytes)            │  ← IPv4 = 0x0800
├─────────────────────────────────────────┤
│  Longitud de hardware (1 byte)          │  ← MAC = 6 bytes
├─────────────────────────────────────────┤
│  Longitud de protocolo (1 byte)          │  ← IP = 4 bytes
├─────────────────────────────────────────┤
│  Operación (2 bytes)                     │  ← 1=Request, 2=Reply
├─────────────────────────────────────────┤
│  MAC origen (6 bytes)                    │
├─────────────────────────────────────────┤
│  IP origen (4 bytes)                     │
├─────────────────────────────────────────┤
│  MAC destino (6 bytes)                   │  ← 00:00:00:00:00:00 en Request
├─────────────────────────────────────────┤
│  IP destino (4 bytes)                   │
└─────────────────────────────────────────┘
```

**Campos principales:**
- **Tipo de hardware**: Identifica el tipo de hardware (1 = Ethernet)
- **Tipo de protocolo**: Identifica el protocolo de red (0x0800 = IPv4)
- **Operación**: 1 para ARP Request, 2 para ARP Reply
- **Direcciones**: MAC e IP de origen y destino

### 3.3 Funcionamiento del Protocolo ARP

El proceso de resolución ARP sigue estos pasos:

**1. ARP Request (Solicitud):**
```
Host A necesita comunicarse con Host B (IP: 192.168.1.100)
Host A no conoce la MAC de Host B
Host A envía un ARP Request en BROADCAST:
  "¿Quién tiene la IP 192.168.1.100? Por favor, dime tu MAC"
```

**2. ARP Reply (Respuesta):**
```
Host B recibe el ARP Request
Host B reconoce que la IP solicitada es la suya
Host B responde directamente a Host A (UNICAST):
  "Yo tengo la IP 192.168.1.100, mi MAC es aa:bb:cc:dd:ee:ff"
```

**3. Almacenamiento en Tabla ARP:**
```
Host A almacena la asociación IP-MAC en su tabla ARP
Futuras comunicaciones usan esta información sin necesidad de nuevo ARP Request
```

**Uso en el proyecto:**
El sistema implementa solicitudes ARP mediante Scapy para:
- Aprender direcciones MAC de hosts descubiertos
- Construir una tabla ARP local del sistema
- Identificar tipos de dispositivos mediante OUI (Organizationally Unique Identifier)

### 3.4 Tabla ARP

**Definición:**
La tabla ARP es una caché que almacena temporalmente las asociaciones entre direcciones IP y direcciones MAC conocidas. Esta tabla permite evitar solicitudes ARP repetidas para las mismas direcciones IP.

**Características:**
- **Tiempo de vida (TTL)**: Las entradas tienen un tiempo de expiración (típicamente 2-4 minutos)
- **Actualización dinámica**: Se actualiza automáticamente cuando se reciben nuevas respuestas ARP
- **Eficiencia**: Reduce el tráfico de broadcast en la red

**Estructura típica:**
```
IP Address          MAC Address           Type
192.168.1.1        aa:bb:cc:dd:ee:ff    dynamic
192.168.1.100      11:22:33:44:55:66    dynamic
```

**Uso en el proyecto:**
El sistema mantiene su propia tabla ARP (`learned_macs`) que:
- Almacena asociaciones IP-MAC aprendidas durante el escaneo
- Persiste durante la ejecución del programa
- Se utiliza para evitar broadcasts ARP redundantes
- Permite identificar dispositivos por su dirección MAC

---

## 4. DESCUBRIMIENTO DE HOSTS

### 4.1 Concepto y Metodologías

El descubrimiento de hosts es el proceso de identificar dispositivos activos en una red. Existen múltiples metodologías para realizar este descubrimiento, cada una con sus ventajas y limitaciones.

**Metodologías principales:**

**1. Escaneo ICMP (Ping Sweep):**
- Envío de paquetes ICMP Echo Request a un rango de direcciones IP
- Los hosts que responden con Echo Reply se consideran activos
- **Ventajas**: Simple, rápido, bajo overhead
- **Desventajas**: Algunos hosts bloquean ICMP por seguridad

**2. Escaneo ARP:**
- Envío de solicitudes ARP a todas las direcciones IP posibles
- Los hosts que responden con ARP Reply se consideran activos
- **Ventajas**: Muy efectivo en redes locales, no puede ser bloqueado fácilmente
- **Desventajas**: Solo funciona en la misma subred

**3. Escaneo de Puertos:**
- Envío de paquetes TCP/UDP a puertos específicos
- Análisis de respuestas para determinar servicios activos
- **Ventajas**: Proporciona información sobre servicios
- **Desventajas**: Más lento, puede ser detectado por sistemas de seguridad

### 4.2 Escaneo ICMP en el Proyecto

El sistema implementa escaneo ICMP de la siguiente manera:

**Proceso:**
1. **Detección de rango de red**: Identifica automáticamente la red local
2. **Generación de direcciones**: Calcula todas las direcciones IP posibles en el rango
3. **Escaneo paralelo**: Envía pings ICMP a múltiples hosts simultáneamente (hasta 20 threads)
4. **Análisis de respuestas**: Identifica hosts que responden con Echo Reply
5. **Medición de latencia**: Calcula el tiempo de respuesta (RTT)

**Implementación técnica:**
```python
# Pseudocódigo del proceso
for cada IP en rango_de_red:
    thread = crear_thread(ping_host, IP)
    threads.append(thread)
    
    if len(threads) >= 20:
        esperar_completar_threads()
        limpiar_threads()
```

**Optimizaciones:**
- Escaneo paralelo con límite de threads concurrentes
- Timeout configurable para evitar esperas prolongadas
- Reintentos opcionales para mejorar tasa de descubrimiento
- Cacheo de resultados para evitar escaneos redundantes

### 4.3 Integración ICMP-ARP

El proyecto combina ambos protocolos para un descubrimiento más completo:

**Flujo integrado:**
1. **Fase 1 - Descubrimiento ICMP**: Escanea la red con pings para identificar hosts activos
2. **Fase 2 - Aprendizaje ARP**: Para cada host descubierto, envía solicitud ARP para aprender su MAC
3. **Fase 3 - Monitoreo continuo**: Usa la información aprendida para monitoreo eficiente

**Ventajas de la integración:**
- Descubrimiento rápido mediante ICMP
- Información completa (IP + MAC) mediante ARP
- Identificación de dispositivos mediante OUI de MAC
- Reducción de tráfico de broadcast en monitoreo continuo

---

## 5. CONCEPTOS ADICIONALES RELEVANTES

### 5.1 Modelo OSI y Capas de Red

**Modelo OSI (Open Systems Interconnection):**
El modelo OSI divide la comunicación de red en 7 capas. Los protocolos utilizados en este proyecto operan en diferentes capas:

- **Capa 2 (Enlace de Datos)**: ARP opera aquí, resolviendo direcciones físicas
- **Capa 3 (Red)**: ICMP e IP operan aquí, proporcionando comunicación entre hosts
- **Capa 4 (Transporte)**: TCP/UDP (no utilizados directamente en este proyecto)

**Interacción entre capas:**
```
Aplicación (Capa 7)
    ↓
Red (Capa 3) - ICMP, IP
    ↓
Enlace (Capa 2) - ARP, Ethernet
    ↓
Físico (Capa 1) - Cable, WiFi
```

### 5.2 Direcciones MAC y OUI (Organizationally Unique Identifier)

**Dirección MAC:**
Una dirección MAC (Media Access Control) es un identificador único de 48 bits asignado a una interfaz de red. Se expresa en formato hexadecimal: `aa:bb:cc:dd:ee:ff`

**OUI (Organizationally Unique Identifier):**
Los primeros 24 bits (3 bytes) de una dirección MAC identifican al fabricante del dispositivo. Esto permite:
- Identificar el fabricante del dispositivo
- Clasificar tipos de dispositivos (routers, smartphones, PCs)
- Detectar dispositivos virtuales o aleatorios

**Ejemplos de OUI:**
- `14:82:5B` → TP-Link (routers, access points)
- `58:6C:25` → Intel (PCs, laptops)
- `B4:B0:24` → Samsung (smartphones, tablets)
- `C0:95:6D` → Apple (iPhones, iPads)

**Uso en el proyecto:**
El sistema utiliza OUI para:
- Identificar tipos de dispositivos automáticamente
- Generar hostnames más descriptivos
- Clasificar dispositivos en categorías (Router, PC, Phone, IoT)

### 5.3 Latencia y Métricas de Red

**Latencia (RTT - Round Trip Time):**
Tiempo que tarda un paquete en viajar desde el origen hasta el destino y regresar. Se mide típicamente en milisegundos (ms).

**Factores que afectan la latencia:**
- Distancia física entre dispositivos
- Número de saltos (hops) en la ruta
- Carga de la red
- Tipo de conexión (cableada vs inalámbrica)

**Métricas calculadas en el proyecto:**
- **Latencia mínima**: Valor más bajo registrado
- **Latencia máxima**: Valor más alto registrado
- **Latencia promedio**: Media aritmética de todas las mediciones
- **Jitter**: Variabilidad de latencia (desviación estándar)

**Fórmulas:**
```
Latencia_Promedio = Σ(Latencia_i) / N
Jitter = √(Σ(Latencia_i - Promedio)² / N)
```

### 5.4 Tasa de Pérdida de Paquetes

**Definición:**
Porcentaje de paquetes enviados que no reciben respuesta dentro del timeout especificado.

**Cálculo:**
```
Tasa_Pérdida = (Paquetes_Perdidos / Paquetes_Enviados) × 100%
```

**Interpretación:**
- **0-1%**: Excelente calidad de red
- **1-5%**: Buena calidad, aceptable
- **5-10%**: Calidad degradada, puede afectar aplicaciones
- **>10%**: Calidad pobre, problemas de red significativos

**Uso en el proyecto:**
El sistema calcula y monitorea la tasa de pérdida de paquetes para:
- Evaluar la calidad general de la red
- Identificar problemas de conectividad
- Detectar hosts con problemas de comunicación

### 5.5 Throughput de Red

**Definición:**
Número de paquetes enviados por unidad de tiempo (típicamente paquetes por segundo).

**Cálculo:**
```
Throughput = Paquetes_Enviados / Tiempo_Transcurrido
```

**Uso en el proyecto:**
El sistema calcula el throughput para:
- Medir la actividad del escaneo
- Evaluar la eficiencia del sistema
- Comparar diferentes configuraciones de escaneo

---

## 6. PROGRAMACIÓN CONCURRENTE Y THREADING

### 6.1 Necesidad de Concurrencia

En el contexto de escaneo de red, la programación concurrente es esencial porque:
- **Escaneo secuencial es lento**: Escanear 254 direcciones IP una por una tomaría varios minutos
- **Timeouts independientes**: Cada ping tiene su propio timeout, no necesita esperar a otros
- **No bloqueo de UI**: La interfaz gráfica debe seguir respondiendo durante el escaneo

### 6.2 Threading en Python

**Concepto:**
Un thread (hilo) es una unidad de ejecución independiente dentro de un proceso. Python proporciona el módulo `threading` para crear y gestionar threads.

**Uso en el proyecto:**
- **Thread de escaneo**: Realiza escaneos periódicos de la red completa
- **Thread de ping continuo**: Monitorea hosts conocidos continuamente
- **Thread de limpieza**: Elimina hosts expirados periódicamente
- **Threads de ping paralelo**: Múltiples threads para escanear hosts simultáneamente

**Thread Safety:**
El acceso a estructuras de datos compartidas se protege mediante locks (cerrojos) para evitar condiciones de carrera (race conditions).

---

## REFERENCIAS BIBLIOGRÁFICAS

1. Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/

2. Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force. https://tools.ietf.org/html/rfc792

3. Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol: Or Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware*. RFC 826. Internet Engineering Task Force. https://tools.ietf.org/html/rfc826

4. Postel, J. (1981). *Internet Protocol*. RFC 791. Internet Engineering Task Force. https://tools.ietf.org/html/rfc791

5. Braden, R. (Ed.). (1989). *Requirements for Internet Hosts -- Communication Layers*. RFC 1122. Internet Engineering Task Force. https://tools.ietf.org/html/rfc1122

6. Python Software Foundation. (2024). *threading — Thread-based parallelism*. Python 3.12 Documentation. https://docs.python.org/3/library/threading.html

7. Wikipedia Contributors. (2024). *Scapy*. Wikipedia. https://en.wikipedia.org/wiki/Scapy

8. Wikipedia Contributors. (2024). *Address Resolution Protocol*. Wikipedia. https://es.wikipedia.org/wiki/Protocolo_de_resoluci%C3%B3n_de_direcciones

9. Wikipedia Contributors. (2024). *Internet Control Message Protocol*. Wikipedia. https://es.wikipedia.org/wiki/Protocolo_de_mensajes_de_control_de_internet

---

**Nota para el informe:**
Este documento está estructurado en secciones independientes que pueden copiarse directamente al informe. Cada sección incluye:
- Definiciones teóricas
- Explicaciones técnicas
- Referencias académicas
- Aplicación práctica en el proyecto
- Ejemplos de código cuando es relevante

Las referencias están listas para ser incluidas en la sección de Referencias del informe final.


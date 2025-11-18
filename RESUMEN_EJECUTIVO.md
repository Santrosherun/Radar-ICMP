# RESUMEN EJECUTIVO

## Sistema de Escaneo y Monitoreo de Red con Protocolos ICMP y ARP

---

### 1. INTRODUCCIÓN Y CONTEXTO

En el contexto actual de redes de computadoras, la capacidad de descubrir, monitorear y diagnosticar dispositivos en una red local es fundamental para la administración eficiente de infraestructuras de red, tanto en entornos domésticos como empresariales. Los protocolos de red de bajo nivel, específicamente ICMP (Internet Control Message Protocol) y ARP (Address Resolution Protocol), proporcionan mecanismos robustos para la detección de hosts activos y la resolución de direcciones físicas, respectivamente.

Este proyecto presenta el desarrollo e implementación de un sistema automatizado de escaneo y monitoreo de red que aprovecha estos protocolos fundamentales para proporcionar una solución integral de descubrimiento de dispositivos, análisis de rendimiento y visualización en tiempo real. El sistema implementado combina técnicas de programación concurrente, análisis estadístico de métricas de red y visualización gráfica interactiva para ofrecer una herramienta completa de diagnóstico y administración de red.

**Referencias de contexto:**
- Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force. https://tools.ietf.org/html/rfc792
- Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol*. RFC 826. Internet Engineering Task Force. https://tools.ietf.org/html/rfc826

---

### 2. OBJETIVOS DEL PROYECTO

El proyecto se desarrolló con el objetivo principal de crear un sistema automatizado que permita el descubrimiento, monitoreo y análisis de dispositivos en una red local mediante el uso de protocolos estándar de red. Los objetivos específicos incluyen:

**Objetivos Generales:**
- Desarrollar un sistema de escaneo de red que utilice protocolos ICMP y ARP para el descubrimiento de hosts activos
- Implementar un sistema de monitoreo continuo con capacidad de visualización en tiempo real
- Proporcionar métricas y estadísticas avanzadas para el análisis de rendimiento de red

**Objetivos Específicos:**
- Implementar escaneo ICMP paralelo para descubrimiento eficiente de hosts en redes locales IPv4
- Aprender y mantener una tabla de correspondencia IP-MAC mediante solicitudes ARP
- Generar estadísticas en tiempo real de latencia, pérdida de paquetes y throughput
- Detectar automáticamente anomalías en la red (latencia alta, jitter, hosts offline)
- Visualizar información de red de forma intuitiva mediante una interfaz gráfica tipo radar
- Identificar tipos de dispositivos mediante análisis de direcciones MAC (OUI - Organizationally Unique Identifier)

---

### 3. METODOLOGÍA Y TECNOLOGÍAS UTILIZADAS

El sistema fue desarrollado utilizando el lenguaje de programación Python 3.7+, aprovechando bibliotecas especializadas para el manejo de paquetes de red y visualización gráfica. La arquitectura del sistema se basa en programación concurrente mediante threads para permitir operaciones paralelas de escaneo sin bloquear la interfaz de usuario.

**Tecnologías Principales:**

1. **Scapy**: Biblioteca de manipulación de paquetes de red que permite la construcción, envío y recepción de paquetes ICMP y ARP a nivel de protocolo. Scapy proporciona control granular sobre los campos de los protocolos de red, permitiendo la implementación de funcionalidades avanzadas como paquetes ICMP personalizados.

   *Referencia:* Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/

2. **Pygame**: Biblioteca de desarrollo de videojuegos utilizada para la implementación de la interfaz gráfica de visualización en tiempo real. Permite renderizado eficiente a 60 FPS y manejo de eventos de usuario.

   *Referencia:* Pygame Community. (2024). *Pygame Documentation*. https://www.pygame.org/docs/

3. **psutil**: Biblioteca multiplataforma para obtener información del sistema, utilizada para la detección automática de la configuración de red local (interfaz activa, dirección IP, máscara de subred).

   *Referencia:* Giampaolo, S. (2024). *psutil: Cross-platform lib for process and system monitoring*. https://psutil.readthedocs.io/

4. **Threading (Python)**: Módulo estándar de Python para programación concurrente, utilizado para implementar threads de escaneo, monitoreo continuo y limpieza de hosts expirados.

   *Referencia:* Python Software Foundation. (2024). *threading — Thread-based parallelism*. Python Documentation. https://docs.python.org/3/library/threading.html

**Metodología de Desarrollo:**

El desarrollo siguió un enfoque modular, separando las responsabilidades en tres componentes principales:
- **Motor de Escaneo (`ICMPScanner`)**: Implementa la lógica de descubrimiento de hosts, aprendizaje de MACs y cálculo de estadísticas
- **Aplicación Principal (`ICMPRadarApp`)**: Coordina los componentes y gestiona el ciclo de vida de la aplicación
- **Visualización (`RadarDisplay`)**: Renderiza la interfaz gráfica y presenta la información de forma intuitiva

---

### 4. CARACTERÍSTICAS PRINCIPALES IMPLEMENTADAS

El sistema implementado incluye las siguientes características principales:

**4.1 Descubrimiento Automático de Red**
- Detección automática de la red local mediante análisis de interfaces de red activas
- Cálculo automático del rango de red a partir de la configuración del sistema
- Soporte para redes privadas estándar (192.168.x.x, 10.x.x.x, 172.16-31.x.x)

**4.2 Escaneo ICMP Paralelo**
- Escaneo concurrente de hasta 20 hosts simultáneamente mediante threading
- Implementación de reintentos configurables para mejorar la tasa de descubrimiento
- Manejo robusto de timeouts y errores de red

**4.3 Aprendizaje de Direcciones MAC (ARP)**
- Solicitudes ARP automáticas para aprender direcciones MAC de hosts descubiertos
- Mantenimiento de una tabla ARP persistente durante la ejecución
- Optimización mediante cacheo para evitar broadcasts redundantes

**4.4 Sistema de Estadísticas Avanzadas**
- Contadores de paquetes: enviados, recibidos y perdidos
- Métricas de latencia: mínimo, máximo, promedio y total acumulado
- Cálculo de métricas derivadas:
  - Tasa de pérdida de paquetes: `(paquetes_perdidos / paquetes_enviados) × 100%`
  - Latencia promedio: `latencia_total / paquetes_recibidos`
  - Throughput: `paquetes_enviados / tiempo_transcurrido` (paquetes por segundo)

**4.5 Historial de Latencia**
- Almacenamiento de las últimas 30 mediciones de latencia por host
- Cálculo de jitter (variabilidad de latencia) mediante desviación estándar
- Detección de tendencias y patrones de comportamiento

**4.6 Gestión de Estado de Hosts**
- Rastreo de hosts activos con timestamps de última vez visto
- Transición automática de hosts activos a offline cuando no responden
- Historial de hosts offline con información de última latencia conocida
- Recuperación automática cuando hosts vuelven a estar online

**4.7 Detección de Anomalías**
- Identificación de hosts con latencia anormalmente alta (>100ms o >2× promedio)
- Detección de jitter alto (desviación estándar >30ms)
- Alertas de hosts recientemente desconectados (últimos 60 segundos)

**4.8 Identificación de Dispositivos**
- Detección de tipo de dispositivo mediante análisis de OUI (primeros 3 bytes de MAC)
- Clasificación automática: Routers, PCs, Smartphones, Dispositivos IoT
- Generación de hostnames sintéticos basados en IP cuando DNS no está disponible

**4.9 Paquetes ICMP Personalizados**
- Soporte para múltiples tipos de mensajes ICMP:
  - Tipo 8: Echo Request (ping estándar)
  - Tipo 13: Timestamp Request
  - Tipo 15: Information Request
  - Tipo 17: Address Mask Request
- Payload configurable para pruebas de diferentes tamaños de paquete

**4.10 Visualización en Tiempo Real**
- Interfaz gráfica tipo radar militar con barrido rotatorio
- Mapeo de latencia a distancia radial (mayor latencia = más lejos del centro)
- Codificación por colores según rendimiento (verde: <10ms, amarillo: 10-50ms, rojo: >50ms)
- Panel de estadísticas en tiempo real
- Dashboard de salud de red con clasificación de hosts
- Gráfica de latencia histórica (últimos 60 puntos)
- Sistema de búsqueda y filtrado de hosts

---

### 5. RESULTADOS Y LOGROS

El sistema desarrollado logra exitosamente todos los objetivos planteados, proporcionando una herramienta completa y funcional para el escaneo y monitoreo de redes locales. Los resultados principales incluyen:

**5.1 Funcionalidad Completa**
- Sistema completamente operativo capaz de escanear redes locales IPv4
- Descubrimiento confiable de hosts activos mediante ICMP
- Aprendizaje exitoso de direcciones MAC mediante ARP
- Visualización fluida en tiempo real a 60 FPS

**5.2 Rendimiento**
- Escaneo eficiente de redes completas (/24) en tiempos razonables (<5 segundos)
- Monitoreo continuo con bajo impacto en recursos del sistema
- Optimizaciones implementadas: límite de threads concurrentes, cacheo de MACs, intervalos configurables

**5.3 Métricas y Análisis**
- Cálculo preciso de estadísticas de red en tiempo real
- Detección efectiva de anomalías (latencia alta, jitter, hosts offline)
- Historial de latencia que permite análisis de tendencias

**5.4 Experiencia de Usuario**
- Interfaz gráfica intuitiva y visualmente atractiva
- Información presentada de forma clara y accesible
- Controles interactivos para exploración de la red

---

### 6. APLICACIONES PRÁCTICAS

El sistema desarrollado tiene aplicaciones prácticas en diversos contextos:

**6.1 Administración de Red Doméstica**
- Inventario automático de dispositivos conectados a la red
- Monitoreo de la salud general de la red
- Identificación de dispositivos desconocidos o no autorizados

**6.2 Diagnóstico de Problemas de Red**
- Detección automática de hosts con problemas de latencia
- Identificación de dispositivos que causan degradación de red
- Análisis de patrones de comportamiento anómalos

**6.3 Laboratorios y Entornos Educativos**
- Herramienta educativa para comprender protocolos ICMP y ARP
- Visualización práctica de conceptos de red
- Experimentación con diferentes tipos de paquetes ICMP

**6.4 Pequeñas y Medianas Empresas**
- Monitoreo básico de infraestructura de red
- Inventario de dispositivos de red
- Detección temprana de problemas de conectividad

---

### 7. CONSIDERACIONES TÉCNICAS Y LIMITACIONES

**7.1 Requisitos del Sistema**
- Requiere permisos de administrador/root para enviar paquetes ICMP
- Compatible con sistemas operativos Windows, Linux y macOS
- Dependencia de que los hosts respondan a pings ICMP (algunos dispositivos pueden bloquearlos)

**7.2 Limitaciones Conocidas**
- Soporte limitado a IPv4 (no incluye IPv6)
- Funciona únicamente en redes locales (no escanea Internet)
- Algunos dispositivos con ahorro de energía pueden responder intermitentemente
- La detección de tipo de dispositivo depende de la disponibilidad de información OUI

**7.3 Optimizaciones Implementadas**
- Thread safety mediante locks para acceso seguro a datos compartidos
- Gestión de memoria eficiente (historial limitado a 30 valores por host)
- Optimización de rendimiento gráfico para mantener 60 FPS
- Cacheo de anomalías para reducir cálculos redundantes

---

### 8. CONCLUSIONES

Este proyecto demuestra exitosamente la viabilidad y utilidad de desarrollar herramientas personalizadas de monitoreo de red utilizando protocolos fundamentales como ICMP y ARP. El sistema implementado proporciona una solución completa que combina descubrimiento automático, análisis estadístico avanzado y visualización intuitiva, ofreciendo valor práctico tanto para usuarios domésticos como para administradores de red.

La implementación aprovecha eficientemente las capacidades de Python y bibliotecas especializadas como Scapy para lograr un control granular sobre los protocolos de red, mientras que la programación concurrente permite operaciones paralelas sin comprometer la responsividad de la interfaz de usuario.

Los resultados obtenidos validan el enfoque metodológico utilizado y demuestran que es posible crear herramientas profesionales de administración de red utilizando tecnologías de código abierto y estándares de protocolos bien establecidos.

---

### 9. TRABAJO FUTURO

Las siguientes mejoras y extensiones se identifican como trabajo futuro potencial:

1. **Soporte IPv6**: Extender el sistema para incluir escaneo y monitoreo de redes IPv6
2. **Persistencia de Datos**: Implementar almacenamiento en base de datos para análisis histórico
3. **API REST**: Exponer funcionalidades mediante API web para acceso remoto
4. **Gráficos Avanzados**: Visualizaciones más sofisticadas de tendencias históricas
5. **Sistema de Alertas**: Notificaciones configurables para eventos específicos
6. **Fingerprinting Avanzado**: Detección de sistemas operativos y servicios mediante técnicas avanzadas
7. **Exportación de Reportes**: Generación de reportes en PDF o HTML con estadísticas

---

### REFERENCIAS PRINCIPALES

1. Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. Internet Engineering Task Force. https://tools.ietf.org/html/rfc792

2. Plummer, D. C. (1982). *An Ethernet Address Resolution Protocol: Or Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware*. RFC 826. Internet Engineering Task Force. https://tools.ietf.org/html/rfc826

3. Postel, J. (1981). *Internet Protocol*. RFC 791. Internet Engineering Task Force. https://tools.ietf.org/html/rfc791

4. Biondi, P., & Desclaux, F. (2024). *Scapy: Packet manipulation library*. https://scapy.net/

5. Python Software Foundation. (2024). *Python Programming Language*. https://www.python.org/

6. Python Software Foundation. (2024). *threading — Thread-based parallelism*. Python 3.12 Documentation. https://docs.python.org/3/library/threading.html

7. Giampaolo, S. (2024). *psutil: Cross-platform lib for process and system monitoring in Python*. https://psutil.readthedocs.io/

8. Pygame Community. (2024). *Pygame Documentation*. https://www.pygame.org/docs/

9. Braden, R. (Ed.). (1989). *Requirements for Internet Hosts -- Communication Layers*. RFC 1122. Internet Engineering Task Force. https://tools.ietf.org/html/rfc1122

---

**Longitud aproximada:** 1,200-1,500 palabras (2-3 páginas en formato Word estándar)

**Fecha de elaboración:** [Fecha actual]

**Autor:** [Tu nombre]


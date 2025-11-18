# Guía de Estructura para Informe en Word
## Sistema de Escaneo de Red con ICMP y ARP

---

## 📋 ESTRUCTURA GENERAL DEL INFORME

### **PORTADA**
- Título del proyecto
- Nombre del estudiante
- Materia/Asignatura
- Institución
- Fecha

---

## 1. RESUMEN EJECUTIVO / ABSTRACT (1-2 páginas)

### Puntos Clave a Incluir:
- **Objetivo principal**: Desarrollar un sistema de escaneo de red que utiliza ICMP y ARP para descubrir y monitorear hosts en una red local
- **Tecnologías utilizadas**: Python, Scapy, Pygame, threading
- **Resultados principales**: Sistema funcional con visualización en tiempo real, estadísticas avanzadas y detección de anomalías
- **Aplicaciones prácticas**: Administración de red, diagnóstico, inventario de dispositivos

### Cómo Escribirlo:
Escribe un párrafo conciso (150-200 palabras) que explique qué es el proyecto, qué hace y por qué es relevante. Debe ser comprensible para alguien que no conoce el tema técnico.

---

## 2. INTRODUCCIÓN (2-3 páginas)

### 2.1 Contexto y Justificación
**Puntos clave:**
- Importancia del monitoreo de red en entornos actuales
- Necesidad de herramientas de diagnóstico y descubrimiento de dispositivos
- Limitaciones de herramientas tradicionales (ping, arp)

**Cómo escribirlo:**
Explica por qué es importante monitorear redes locales, menciona casos de uso reales (administración de red doméstica, pequeñas empresas, laboratorios).

### 2.2 Objetivos del Proyecto
**Objetivos Generales:**
- Desarrollar un sistema automatizado de escaneo de red
- Implementar visualización en tiempo real de hosts activos
- Proporcionar métricas y estadísticas de red

**Objetivos Específicos:**
- Implementar escaneo ICMP para descubrimiento de hosts
- Aprender direcciones MAC mediante ARP
- Generar estadísticas de latencia y pérdida de paquetes
- Detectar anomalías en la red
- Visualizar información de forma intuitiva

**Cómo escribirlo:**
Lista los objetivos de forma clara y medible. Usa viñetas para organizarlos.

### 2.3 Alcance del Proyecto
**Incluir:**
- Redes IPv4 locales (192.168.x.x, 10.x.x.x, etc.)
- Protocolos ICMP y ARP
- Visualización en tiempo real
- Sistema de estadísticas

**Limitaciones:**
- Solo IPv4 (no IPv6)
- Requiere permisos de administrador
- Funciona en redes locales

**Cómo escribirlo:**
Define claramente qué cubre el proyecto y qué no, para establecer expectativas realistas.

---

## 3. MARCO TEÓRICO (4-6 páginas)

### 3.1 Protocolo ICMP (Internet Control Message Protocol)
**Puntos clave a explicar:**
- **Definición**: Protocolo de capa 3 para mensajes de control y diagnóstico
- **Tipos de mensajes relevantes**:
  - Tipo 8, Código 0: Echo Request (ping request)
  - Tipo 0, Código 0: Echo Reply (ping reply)
  - Tipo 13: Timestamp Request
  - Tipo 17: Address Mask Request
- **Estructura del mensaje ICMP**: Mostrar diagrama de campos (Tipo, Código, Checksum, Identificador, Secuencia, Datos)
- **Uso en el proyecto**: Cómo se utiliza para descubrir hosts activos

**Cómo escribirlo:**
Explica el protocolo de forma técnica pero accesible. Incluye un diagrama ASCII o referencia a la estructura. Menciona las RFCs relevantes (RFC 792).

### 3.2 Protocolo ARP (Address Resolution Protocol)
**Puntos clave a explicar:**
- **Definición**: Resuelve direcciones IP (Capa 3) a direcciones MAC (Capa 2)
- **Funcionamiento**: 
  - ARP Request: Broadcast para solicitar MAC
  - ARP Reply: Respuesta con dirección MAC
- **Estructura del paquete ARP**: Mostrar campos principales
- **Tabla ARP**: Concepto de cacheo de direcciones MAC
- **Uso en el proyecto**: Aprender direcciones MAC de hosts descubiertos

**Cómo escribirlo:**
Explica el proceso ARP paso a paso. Incluye un diagrama de flujo del proceso de resolución. Menciona RFC 826.

### 3.3 Modelo OSI y Capas de Red
**Puntos clave:**
- Posición de ICMP (Capa 3 - Red)
- Posición de ARP (Capa 2 - Enlace de Datos)
- Interacción entre capas en el proyecto

**Cómo escribirlo:**
Breve explicación del modelo OSI y cómo se relacionan los protocolos utilizados.

### 3.4 Conceptos de Red Avanzados
**Puntos clave:**
- **RTT (Round Trip Time)**: Tiempo de ida y vuelta de un paquete
- **Jitter**: Variación en la latencia entre paquetes consecutivos
- **Packet Loss Rate**: Porcentaje de paquetes perdidos
- **Throughput**: Tasa de transferencia de datos
- **OUI (Organizationally Unique Identifier)**: Primeros 3 bytes de MAC para identificar fabricantes

**Cómo escribirlo:**
Define cada concepto con ejemplos prácticos. Explica cómo se calculan en el proyecto.

---

## 4. DISEÑO Y ARQUITECTURA DEL SISTEMA (3-4 páginas)

### 4.1 Arquitectura General
**Puntos clave:**
- **Componentes principales**:
  - `ICMPScanner`: Motor de escaneo y monitoreo
  - `ICMPRadarApp`: Aplicación principal que coordina componentes
  - `RadarDisplay`: Visualización gráfica (si aplica)
- **Flujo de datos**: Diagrama de cómo interactúan los componentes

**Cómo escribirlo:**
Crea un diagrama de arquitectura (puedes usar texto ASCII o referenciar un diagrama). Explica la separación de responsabilidades.

### 4.2 Estructura de Datos
**Puntos clave:**
- `active_hosts`: Diccionario de hosts activos con latencia y timestamps
- `offline_hosts`: Historial de hosts desconectados
- `learned_macs`: Tabla ARP aprendida (IP -> MAC)
- `latency_history`: Historial de latencia por host (últimos 30 valores)
- `stats`: Estadísticas globales (paquetes, latencia, throughput)

**Cómo escribirlo:**
Describe cada estructura de datos, su propósito y formato. Puedes incluir ejemplos de datos.

### 4.3 Diseño de Threading
**Puntos clave:**
- **Threads principales**:
  - Thread de escaneo: Escanea la red periódicamente
  - Thread de ping continuo: Monitorea hosts conocidos
  - Thread de limpieza: Elimina hosts expirados
  - Thread principal: Visualización y control
- **Thread safety**: Uso de locks para acceso seguro a datos compartidos

**Cómo escribirlo:**
Explica por qué se usa threading (concurrencia, no bloquear la UI). Menciona los locks utilizados y su propósito.

---

## 5. IMPLEMENTACIÓN TÉCNICA (6-8 páginas)

### 5.1 Detección Automática de Red
**Puntos clave:**
- Uso de `psutil` para detectar interfaz de red activa
- Cálculo de rango de red a partir de IP y máscara
- Fallback a red por defecto si falla la detección

**Cómo escribirlo:**
Explica el algoritmo de detección. Incluye código relevante con comentarios explicativos.

### 5.2 Escaneo ICMP
**Puntos clave:**
- Función `ping_host()`: Envía paquete ICMP y mide latencia
- Función `scan_network()`: Escanea todo el rango de red en paralelo
- Uso de threading para pings paralelos (hasta 20 threads concurrentes)
- Manejo de reintentos y timeouts

**Cómo escribirlo:**
Describe el proceso paso a paso. Explica por qué se usa threading paralelo. Menciona optimizaciones (límite de threads).

### 5.3 Aprendizaje de Direcciones MAC (ARP)
**Puntos clave:**
- Función `_learn_mac_via_arp()`: Envía ARP request para aprender MAC
- Integración con escaneo ICMP: Solo aprende MAC si no se conoce
- Tabla ARP persistente durante la ejecución

**Cómo escribirlo:**
Explica el proceso ARP. Muestra cómo se integra con el escaneo ICMP.

### 5.4 Sistema de Estadísticas
**Puntos clave:**
- Contadores de paquetes (enviados, recibidos, perdidos)
- Métricas de latencia (min, max, promedio, total)
- Cálculo de métricas derivadas:
  - Packet loss rate: `(packets_lost / packets_sent) × 100`
  - Average latency: `total_latency / packets_received`
  - Throughput: `packets_sent / elapsed_time`

**Cómo escribirlo:**
Explica cada métrica y su fórmula. Muestra ejemplos de valores típicos.

### 5.5 Historial de Latencia
**Puntos clave:**
- Almacenamiento de últimas 30 mediciones por host
- Cálculo de jitter (desviación estándar)
- Detección de tendencias

**Cómo escribirlo:**
Explica por qué se limita a 30 valores (gestión de memoria). Muestra cómo se calcula el jitter.

### 5.6 Gestión de Estado de Hosts
**Puntos clave:**
- Transición de hosts activos a offline
- Persistencia de hosts (tiempo antes de considerar offline)
- Recuperación automática cuando hosts vuelven online

**Cómo escribirlo:**
Explica el algoritmo de limpieza. Muestra cómo se manejan los estados.

### 5.7 Detección de Anomalías
**Puntos clave:**
- **Latencia alta**: Más del doble del promedio o > 100ms
- **Jitter alto**: Desviación estándar > 30ms
- **Hosts recientemente offline**: Desconectados en últimos 60 segundos

**Cómo escribirlo:**
Explica cada tipo de anomalía y su criterio de detección. Muestra ejemplos.

---

## 6. CARACTERÍSTICAS AVANZADAS (2-3 páginas)

### 6.1 Identificación de Dispositivos
**Puntos clave:**
- Detección de tipo de dispositivo por OUI (MAC)
- Hostnames sintéticos basados en IP
- Clasificación de dispositivos (Router, PC, Phone, etc.)

**Cómo escribirlo:**
Explica cómo funciona la detección por OUI. Menciona limitaciones (no todos los dispositivos tienen OUI reconocible).

### 6.2 Paquetes ICMP Personalizados
**Puntos clave:**
- Función `send_custom_icmp()`: Soporte para múltiples tipos ICMP
- Tipos soportados: Echo Request, Timestamp Request, Information Request, Address Mask Request
- Payload configurable

**Cómo escribirlo:**
Explica cada tipo de ICMP y su propósito. Muestra cuándo sería útil cada uno.

### 6.3 Visualización en Tiempo Real
**Puntos clave:**
- Interfaz gráfica con Pygame
- Visualización tipo radar de hosts
- Actualización en tiempo real (60 FPS)
- Mostrar estadísticas y anomalías

**Cómo escribirlo:**
Describe la interfaz visual. Explica las decisiones de diseño (por qué tipo radar, colores, etc.).

---

## 7. PRUEBAS Y RESULTADOS (3-4 páginas)

### 7.1 Metodología de Pruebas
**Puntos clave:**
- Escenarios de prueba:
  - Red doméstica pequeña (5-10 dispositivos)
  - Red con múltiples tipos de dispositivos
  - Pruebas de latencia y pérdida de paquetes
  - Pruebas de detección de hosts offline

**Cómo escribirlo:**
Describe cómo se probó el sistema. Menciona el entorno de pruebas.

### 7.2 Resultados Obtenidos
**Puntos clave:**
- Número de hosts descubiertos
- Precisión de detección
- Rendimiento del escaneo (tiempo, throughput)
- Ejemplos de estadísticas capturadas
- Casos de detección de anomalías

**Cómo escribirlo:**
Presenta resultados concretos con tablas o gráficos si es posible. Incluye capturas de pantalla de la interfaz.

### 7.3 Análisis de Resultados
**Puntos clave:**
- Interpretación de métricas obtenidas
- Identificación de patrones
- Comparación con valores esperados

**Cómo escribirlo:**
Analiza los resultados. Explica qué significan los valores obtenidos.

---

## 8. CONSIDERACIONES TÉCNICAS Y LIMITACIONES (2-3 páginas)

### 8.1 Thread Safety
**Puntos clave:**
- Uso de locks para estructuras compartidas
- Prevención de race conditions
- Patrones de sincronización utilizados

**Cómo escribirlo:**
Explica por qué es importante y cómo se implementó.

### 8.2 Gestión de Memoria
**Puntos clave:**
- Limitación de historial de latencia (30 valores)
- Limpieza periódica de hosts expirados
- Estimación de uso de memoria

**Cómo escribirlo:**
Explica las decisiones de diseño relacionadas con memoria.

### 8.3 Limitaciones del Sistema
**Puntos clave:**
- Requiere permisos de administrador
- Solo funciona en redes locales
- Solo soporta IPv4
- Dependencia de respuestas ICMP (algunos hosts pueden bloquear)

**Cómo escribirlo:**
Lista las limitaciones de forma honesta. Explica por qué existen y posibles soluciones futuras.

### 8.4 Optimizaciones Implementadas
**Puntos clave:**
- Límite de threads concurrentes (20)
- Intervalo de ping continuo (5 segundos)
- Reintentos reducidos (1 por defecto)
- Cache de anomalías

**Cómo escribirlo:**
Explica cada optimización y su impacto en el rendimiento.

---

## 9. CONCLUSIONES (2-3 páginas)

### 9.1 Logros Alcanzados
**Puntos clave:**
- Sistema funcional de escaneo y monitoreo
- Visualización en tiempo real
- Estadísticas avanzadas
- Detección de anomalías

**Cómo escribirlo:**
Resume los logros principales del proyecto.

### 9.2 Aplicaciones Prácticas
**Puntos clave:**
- Administración de red doméstica
- Diagnóstico de problemas de red
- Inventario de dispositivos
- Monitoreo de seguridad

**Cómo escribirlo:**
Explica casos de uso reales donde el sistema sería útil.

### 9.3 Trabajo Futuro
**Puntos clave:**
- Soporte IPv6
- Persistencia de datos (base de datos)
- API REST para acceso remoto
- Gráficos de tendencias históricas
- Sistema de alertas configurable
- Fingerprinting avanzado de dispositivos

**Cómo escribirlo:**
Propone mejoras futuras de forma realista y priorizada.

---

## 10. REFERENCIAS (1-2 páginas)

### Estándares y RFCs
- RFC 792: Internet Control Message Protocol (ICMP)
- RFC 826: Ethernet Address Resolution Protocol (ARP)
- RFC 791: Internet Protocol (IP)

### Bibliotecas y Herramientas
- Scapy: https://scapy.net/
- Pygame: https://www.pygame.org/
- psutil: https://psutil.readthedocs.io/

### Documentación Técnica
- Python Threading: https://docs.python.org/3/library/threading.html
- Modelo OSI: Referencias estándar

**Cómo escribirlo:**
Formatea las referencias según el estilo requerido (APA, IEEE, etc.).

---

## 11. ANEXOS (Opcional)

### A. Código Fuente Completo
- Incluir código completo o referencias a repositorio

### B. Capturas de Pantalla
- Interfaz gráfica
- Ejemplos de salida
- Estadísticas capturadas

### C. Diagramas Adicionales
- Diagramas de flujo detallados
- Diagramas de secuencia
- Diagramas de clases (si aplica)

---

## 📝 CONSEJOS PARA LA REDACCIÓN

### Estilo de Escritura
1. **Usa voz activa**: "El sistema escanea la red" en lugar de "La red es escaneada por el sistema"
2. **Sé específico**: Evita generalidades, incluye números y ejemplos concretos
3. **Explica el "por qué"**: No solo describas qué hace, explica por qué se diseñó así
4. **Usa diagramas**: Los diagramas ayudan mucho a entender conceptos técnicos
5. **Cita código relevante**: Cuando menciones funcionalidades, incluye fragmentos de código con explicaciones

### Formato en Word
1. **Usa estilos de título**: Título 1, Título 2, etc. para navegación fácil
2. **Numeración automática**: Usa la numeración automática de Word para secciones
3. **Tablas y figuras**: Numera todas las tablas y figuras, y referencia en el texto
4. **Índice automático**: Genera un índice automático al final
5. **Espaciado consistente**: Usa espaciado uniforme entre párrafos

### Contenido Técnico
1. **Equilibrio**: No todo código, no todo teoría. Balancea explicaciones conceptuales con detalles técnicos
2. **Ejemplos**: Incluye ejemplos concretos de uso y resultados
3. **Comparaciones**: Compara con herramientas similares si es relevante
4. **Problemas y soluciones**: Menciona problemas encontrados y cómo se resolvieron

### Longitud Sugerida
- **Total**: 20-30 páginas (sin contar anexos)
- **Por sección**:
  - Resumen: 1-2 páginas
  - Introducción: 2-3 páginas
  - Marco Teórico: 4-6 páginas
  - Diseño: 3-4 páginas
  - Implementación: 6-8 páginas
  - Características: 2-3 páginas
  - Pruebas: 3-4 páginas
  - Consideraciones: 2-3 páginas
  - Conclusiones: 2-3 páginas
  - Referencias: 1-2 páginas

---

## ✅ CHECKLIST ANTES DE ENTREGAR

- [ ] Todas las secciones están completas
- [ ] Diagramas están numerados y referenciados
- [ ] Código está formateado correctamente
- [ ] Referencias están en formato correcto
- [ ] Ortografía y gramática revisadas
- [ ] Numeración de páginas correcta
- [ ] Índice generado y actualizado
- [ ] Portada completa
- [ ] Espaciado y formato consistentes
- [ ] Tablas y figuras tienen títulos descriptivos

---

**¡Buena suerte con tu informe!** 🚀


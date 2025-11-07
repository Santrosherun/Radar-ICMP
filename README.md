# 🛰️ ICMP Radar - Manual de Usuario

Una aplicación en Python que utiliza **Scapy** y **Pygame** para crear una visualización tipo radar militar de los dispositivos activos en tu red local mediante paquetes ICMP (ping).

![ICMP Radar Demo](https://img.shields.io/badge/Status-Funcional-brightgreen)
![Python](https://img.shields.io/badge/Python-3.7+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 🎯 Características Principales

### 🔍 **Detección de Red**
- **Descubrimiento automático** de la red local
- **Escaneo continuo** con paquetes ICMP cada 1-3 segundos
- **Ping continuo** a hosts conocidos cada 2 segundos
- **Optimización ARP** para reducir tráfico de red

### 🎨 **Visualización Avanzada**
- **Radar militar** en tiempo real con barrido rotatorio
- **Mapeo de latencia** a distancia radial (mayor latencia = más lejos del centro)
- **Colores codificados** por rendimiento:
  - 🟢 **Verde**: < 10ms (excelente)
  - 🟡 **Amarillo**: 10-50ms (bueno)
  - 🔴 **Rojo**: > 50ms (lento)
- **Etiquetas compactas** (.157 en lugar de 192.168.1.157)

### 🖱️ **Interfaz Interactiva**
- **Hover detallado** con información completa del dispositivo
- **Identificación automática** de tipos de dispositivo (Router, PC, Smartphone, etc.)
- **Panel de información** en tiempo real
- **Optimización de rendimiento** para 60 FPS

## 🚀 Uso Básico

### **Ejecución Simple**
```bash
# Ejecutar con configuración automática
python icmp_radar.py
```

### **Con Opciones Personalizadas**
```bash
# Escaneo más frecuente
python icmp_radar.py -i 0.5

# Red específica con persistencia larga
python icmp_radar.py -n 192.168.1.0/24 -p 60

# Ventana grande con información detallada
python icmp_radar.py -s 1200x900 -v
```

## ⚙️ Opciones de Configuración

### **Argumentos de Línea de Comandos**

| Argumento | Tipo | Descripción | Ejemplo | Default |
|-----------|------|-------------|---------|---------|
| `-n, --network` | str | Rango de red CIDR | `-n 10.0.0.0/24` | Auto-detectar |
| `-i, --interval` | float | Intervalo entre escaneos completos | `-i 0.5` | 1.0s |
| `-p, --persist` | int | Tiempo de persistencia de hosts | `-p 60` | 30s |
| `-s, --size` | str | Tamaño de ventana | `-s 1000x800` | 800x600 |
| `-v, --verbose` | flag | Información detallada | `-v` | False |
| `-h, --help` | flag | Mostrar ayuda | `-h` | - |

### **Ejemplos de Configuración**

```bash
# Radar súper responsivo (escaneo cada 0.5s, persistencia 15s)
python icmp_radar.py -i 0.5 -p 15 -v

# Radar estable (escaneo cada 3s, persistencia 2 minutos)
python icmp_radar.py -i 3 -p 120

# Red corporativa grande
python icmp_radar.py -n 10.0.0.0/16 -i 2 -p 90 -s 1400x1000
```

## 🖥️ Interfaz de Usuario

### **Elementos del Radar**

#### **Centro del Radar**
- Representa tu dispositivo (latencia = 0ms)
- Punto de referencia para todas las mediciones

#### **Círculos Concéntricos**
- **Círculo interior**: Latencia muy baja (< 25ms)
- **Círculo medio**: Latencia moderada (25-50ms)
- **Círculo exterior**: Latencia alta (50-100ms)

#### **Línea de Barrido**
- Rota continuamente simulando un radar real
- Velocidad: 2° por frame (optimizada para rendimiento)

#### **Hosts Detectados**
- **Puntos coloreados** según latencia
- **Etiquetas compactas** (.157, .1, .26, etc.)
- **Efectos de hover** con información detallada

### **Panel de Información**
- **Hosts Activos**: Número total detectado
- **MACs Aprendidas**: Direcciones MAC en cache
- **Estado del Escaneo**: Progreso actual
- **Tiempo de Escaneo**: Duración del último escaneo

### **Sistema de Hover**
Al pasar el mouse sobre cualquier host:
```
IP: 192.168.1.157
Host: .157
Latencia: 15.2ms
Dispositivo: TP-Link
Tipo: Router/AP
MAC: 14:82:5b:78:99:63
```

## 🔧 Funcionamiento Técnico

### **Arquitectura del Sistema**

#### **Módulos Principales**
1. **`icmp_radar.py`**: Aplicación principal y coordinación
2. **`icmp_scanner.py`**: Motor de escaneo ICMP con optimizaciones ARP
3. **`radar_display.py`**: Visualización con Pygame y efectos gráficos

#### **Proceso de Escaneo Dual**

**1. Escaneo Completo (Intervalo configurable)**
```
Cada 1-3 segundos:
├── Escanea toda la red (ej: 192.168.1.0/24)
├── Descubre nuevos hosts
├── Aprende direcciones MAC
└── Actualiza base de datos de hosts
```

**2. Ping Continuo (Cada 2 segundos)**
```
Solo a hosts conocidos:
├── Ping rápido a IPs ya detectadas
├── Actualiza latencia en tiempo real
├── Mantiene hosts "vivos" en el radar
└── Usa MACs aprendidas (sin broadcast)
```

### **Optimizaciones de Rendimiento**

#### **Red**
- **Threads limitados**: Máximo 20 concurrentes
- **Cache ARP**: Evita broadcasts redundantes
- **Ping inteligente**: Reintentos solo cuando es necesario

#### **Gráficos**
- **60 FPS estables** con `pygame.time.Clock()`
- **Renderizado optimizado**: Sin efectos costosos
- **Hover selectivo**: Etiquetas solo cerca del mouse

### **Sistema de Persistencia**

Los hosts permanecen visibles según el tiempo configurado:
- **15 segundos**: Radar muy dinámico, hosts desaparecen rápido
- **30 segundos**: Balance ideal (default)
- **60+ segundos**: Radar estable, hosts persisten más tiempo

## 🎮 Controles

| Acción | Control |
|--------|---------|
| **Salir** | ESC o cerrar ventana |
| **Ver detalles** | Hover sobre host |
| **Información** | Panel superior derecho |

## 📊 Interpretación de Resultados

### **Colores de Latencia**
- **🟢 Verde (< 10ms)**: Red local excelente, dispositivos cableados
- **🟡 Amarillo (10-50ms)**: WiFi normal, dispositivos móviles
- **🔴 Rojo (> 50ms)**: Conexión lenta, problemas de red o dispositivos lejanos

### **Posición Radial**
- **Centro**: Tu dispositivo (0ms)
- **Cerca del centro**: Respuesta muy rápida
- **Borde exterior**: Respuesta lenta o problemas de conectividad

### **Identificación de Dispositivos**

El sistema identifica automáticamente:
- **Routers**: .1, .254 + MACs de fabricantes conocidos
- **PCs**: MACs Intel, AMD
- **Smartphones**: MACs Apple, Samsung, Xiaomi
- **Dispositivos IoT**: Patrones de comportamiento específicos

## ⚠️ Consideraciones Importantes

### **Permisos Requeridos**
- **Windows**: Ejecutar PowerShell como Administrador
- **Linux/macOS**: Usar `sudo python icmp_radar.py`

### **Limitaciones de Red**
- Algunos dispositivos bloquean ping por seguridad
- Firewalls corporativos pueden interferir
- Dispositivos en modo ahorro de energía responden intermitentemente

### **Rendimiento**
- **Intervalos cortos** (0.5s): Más responsivo, mayor uso de CPU
- **Intervalos largos** (3s): Más eficiente, menos tráfico de red
- **Persistencia alta**: Radar más estable, menos "parpadeo"

## 🎓 Casos de Uso

### **Diagnóstico de Red**
```bash
# Detectar problemas de latencia
python icmp_radar.py -i 1 -p 15 -v
```

### **Monitoreo Continuo**
```bash
# Supervisión de red estable
python icmp_radar.py -i 2 -p 120
```

### **Análisis Detallado**
```bash
# Red específica con información completa
python icmp_radar.py -n 192.168.1.0/24 -i 0.5 -v -s 1200x900
```

### **Presentaciones**
```bash
# Visualización impactante para demos
python icmp_radar.py -s 1400x1000 -i 1
```

## 🔍 Solución de Problemas

### **No se detectan hosts**
- Verificar permisos de administrador
- Comprobar firewall local
- Probar con `-n` especificando red manualmente

### **Rendimiento lento**
- Aumentar intervalo: `-i 3`
- Reducir persistencia: `-p 15`
- Usar ventana más pequeña: `-s 600x400`

### **Hosts aparecen y desaparecen**
- Aumentar persistencia: `-p 60`
- Reducir intervalo: `-i 0.5`
- Normal en dispositivos móviles con ahorro de energía

---

**¡Explora tu red como nunca antes con el ICMP Radar!** 🛰️✨

*Proyecto desarrollado con fines educativos y de diagnóstico de red.*
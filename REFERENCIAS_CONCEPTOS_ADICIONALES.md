# REFERENCIAS PARA CONCEPTOS ADICIONALES RELEVANTES

## Referencias Específicas por Subsección

---

### 5.1 MODELO OSI Y CAPAS DE RED

**Referencias necesarias:**

1. **ISO/IEC 7498-1:1994** - Modelo de Referencia OSI (Open Systems Interconnection)
   - International Organization for Standardization (ISO)
   - *Information technology -- Open Systems Interconnection -- Basic Reference Model: The Basic Model*
   - Esta es la referencia oficial del modelo OSI
   - Disponible en: https://www.iso.org/standard/20269.html

2. **Zimmermann, H. (1980)** - "OSI Reference Model - The ISO Model of Architecture for Open Systems Interconnection"
   - IEEE Transactions on Communications
   - Vol. 28, No. 4, pp. 425-432
   - Artículo fundacional que explica el modelo OSI

3. **Stallings, W. (2017)** - *Data and Computer Communications* (11th ed.)
   - Prentice Hall
   - Capítulo 2: "Protocol Architecture, TCP/IP, and Internet-Based Applications"
   - Explica la relación entre OSI y TCP/IP

**Referencia recomendada para el informe:**
```
ISO/IEC. (1994). Information technology -- Open Systems Interconnection -- 
Basic Reference Model: The Basic Model (ISO/IEC 7498-1:1994). 
International Organization for Standardization.
```

---

### 5.2 DIRECCIONES MAC Y OUI (ORGANIZATIONALLY UNIQUE IDENTIFIER)

**Referencias necesarias:**

1. **IEEE 802-2014** - Estándar IEEE para direcciones MAC
   - IEEE Standards Association
   - *IEEE Standard for Local and Metropolitan Area Networks: Overview and Architecture*
   - Define el formato de direcciones MAC de 48 bits
   - Disponible en: https://standards.ieee.org/standard/802-2014.html

2. **IEEE Registration Authority** - OUI Database
   - IEEE Standards Association
   - *IEEE Registration Authority: Public OUI Listing*
   - Base de datos oficial de OUI asignados a fabricantes
   - Disponible en: https://standards.ieee.org/products-services/regauth/oui/

3. **IEEE 802.3-2018** - Ethernet Standard
   - IEEE Standards Association
   - *IEEE Standard for Ethernet*
   - Define el uso de direcciones MAC en Ethernet
   - Disponible en: https://standards.ieee.org/standard/802_3-2018.html

**Referencias recomendadas para el informe:**
```
IEEE Standards Association. (2014). IEEE Standard for Local and 
Metropolitan Area Networks: Overview and Architecture (IEEE Std 802-2014). 
IEEE.

IEEE Registration Authority. (2024). Public OUI Listing. 
IEEE Standards Association. https://standards.ieee.org/products-services/regauth/oui/
```

---

### 5.3 LATENCIA Y MÉTRICAS DE RED

**Referencias necesarias:**

1. **ITU-T G.1010** - Quality of Service requirements
   - International Telecommunication Union
   - *End-user multimedia QoS categories*
   - Define métricas de calidad de servicio incluyendo latencia
   - Disponible en: https://www.itu.int/rec/T-REC-G.1010

2. **RFC 2681** - A One-way Delay Metric for IPPM
   - Almes, G., Kalidindi, S., & Zekauskas, M. (1999)
   - Internet Engineering Task Force
   - Define métricas de latencia unidireccional
   - Disponible en: https://tools.ietf.org/html/rfc2681

3. **RFC 3393** - IP Packet Delay Variation Metric for IP Performance Metrics (IPPM)
   - Demichelis, C., & Chimento, P. (2002)
   - Internet Engineering Task Force
   - Define métricas de jitter (variación de latencia)
   - Disponible en: https://tools.ietf.org/html/rfc3393

4. **Paxson, V., Almes, G., Mahdavi, J., & Mathis, M. (1998)** - "Framework for IP Performance Metrics"
   - RFC 2330
   - Internet Engineering Task Force
   - Marco general para métricas de rendimiento IP
   - Disponible en: https://tools.ietf.org/html/rfc2330

**Referencias recomendadas para el informe:**
```
Almes, G., Kalidindi, S., & Zekauskas, M. (1999). A One-way Delay Metric 
for IPPM (RFC 2681). Internet Engineering Task Force. 
https://tools.ietf.org/html/rfc2681

Demichelis, C., & Chimento, P. (2002). IP Packet Delay Variation Metric 
for IP Performance Metrics (IPPM) (RFC 3393). Internet Engineering Task Force. 
https://tools.ietf.org/html/rfc3393

ITU-T. (2001). End-user multimedia QoS categories (ITU-T Recommendation G.1010). 
International Telecommunication Union.
```

---

### 5.4 TASA DE PÉRDIDA DE PAQUETES

**Referencias necesarias:**

1. **RFC 2680** - A One-way Packet Loss Metric for IPPM
   - Almes, G., Kalidindi, S., & Zekauskas, M. (1999)
   - Internet Engineering Task Force
   - Define métricas de pérdida de paquetes
   - Disponible en: https://tools.ietf.org/html/rfc2680

2. **ITU-T Y.1540** - Internet protocol data communication service - IP packet transfer and availability performance parameters
   - International Telecommunication Union
   - Define parámetros de rendimiento incluyendo pérdida de paquetes
   - Disponible en: https://www.itu.int/rec/T-REC-Y.1540

3. **Paxson, V., Almes, G., Mahdavi, J., & Mathis, M. (1998)** - "Framework for IP Performance Metrics"
   - RFC 2330 (ya mencionado en 5.3, pero también aplica aquí)
   - Define el marco general para métricas de pérdida

**Referencias recomendadas para el informe:**
```
Almes, G., Kalidindi, S., & Zekauskas, M. (1999). A One-way Packet Loss 
Metric for IPPM (RFC 2680). Internet Engineering Task Force. 
https://tools.ietf.org/html/rfc2680

ITU-T. (2019). Internet protocol data communication service - IP packet 
transfer and availability performance parameters (ITU-T Recommendation Y.1540). 
International Telecommunication Union.
```

---

### 5.5 THROUGHPUT DE RED

**Referencias necesarias:**

1. **RFC 3148** - A Framework for Defining Empirical Bulk Transfer Capacity Metrics
   - Mathis, M., & Heffner, J. (2001)
   - Internet Engineering Task Force
   - Define métricas de capacidad de transferencia (throughput)
   - Disponible en: https://tools.ietf.org/html/rfc3148

2. **ITU-T I.350** - General aspects of quality of service and network performance in digital networks, including ISDN
   - International Telecommunication Union
   - Define parámetros de rendimiento de red incluyendo throughput
   - Disponible en: https://www.itu.int/rec/T-REC-I.350

3. **Paxson, V., Almes, G., Mahdavi, J., & Mathis, M. (1998)** - "Framework for IP Performance Metrics"
   - RFC 2330 (ya mencionado, aplica también aquí)

**Referencias recomendadas para el informe:**
```
Mathis, M., & Heffner, J. (2001). A Framework for Defining Empirical Bulk 
Transfer Capacity Metrics (RFC 3148). Internet Engineering Task Force. 
https://tools.ietf.org/html/rfc3148
```

---

### 6. PROGRAMACIÓN CONCURRENTE Y THREADING

**Referencias necesarias:**

1. **Python Software Foundation. (2024)** - *threading — Thread-based parallelism*
   - Python 3.12 Documentation
   - Documentación oficial del módulo threading de Python
   - Disponible en: https://docs.python.org/3/library/threading.html

2. **Tanenbaum, A. S., & Bos, H. (2015)** - *Modern Operating Systems* (4th ed.)
   - Prentice Hall
   - Capítulo 2: "Processes and Threads"
   - Explica conceptos fundamentales de threading y concurrencia

3. **Herlihy, M., & Shavit, N. (2012)** - *The Art of Multiprocessor Programming* (Revised 1st ed.)
   - Morgan Kaufmann
   - Explica programación concurrente y thread safety

**Referencias recomendadas para el informe:**
```
Python Software Foundation. (2024). threading — Thread-based parallelism. 
Python 3.12 Documentation. https://docs.python.org/3/library/threading.html

Tanenbaum, A. S., & Bos, H. (2015). Modern Operating Systems (4th ed.). 
Prentice Hall.
```

---

## RESUMEN DE REFERENCIAS PARA AGREGAR AL DOCUMENTO

Agrega estas referencias a la sección de **REFERENCIAS BIBLIOGRÁFICAS** del documento MARCO_TEORICO.md:

### Nuevas Referencias a Agregar:

10. ISO/IEC. (1994). *Information technology -- Open Systems Interconnection -- Basic Reference Model: The Basic Model* (ISO/IEC 7498-1:1994). International Organization for Standardization.

11. IEEE Standards Association. (2014). *IEEE Standard for Local and Metropolitan Area Networks: Overview and Architecture* (IEEE Std 802-2014). IEEE.

12. IEEE Registration Authority. (2024). *Public OUI Listing*. IEEE Standards Association. https://standards.ieee.org/products-services/regauth/oui/

13. Almes, G., Kalidindi, S., & Zekauskas, M. (1999). *A One-way Delay Metric for IPPM* (RFC 2681). Internet Engineering Task Force. https://tools.ietf.org/html/rfc2681

14. Almes, G., Kalidindi, S., & Zekauskas, M. (1999). *A One-way Packet Loss Metric for IPPM* (RFC 2680). Internet Engineering Task Force. https://tools.ietf.org/html/rfc2680

15. Demichelis, C., & Chimento, P. (2002). *IP Packet Delay Variation Metric for IP Performance Metrics (IPPM)* (RFC 3393). Internet Engineering Task Force. https://tools.ietf.org/html/rfc3393

16. Mathis, M., & Heffner, J. (2001). *A Framework for Defining Empirical Bulk Transfer Capacity Metrics* (RFC 3148). Internet Engineering Task Force. https://tools.ietf.org/html/rfc3148

17. Paxson, V., Almes, G., Mahdavi, J., & Mathis, M. (1998). *Framework for IP Performance Metrics* (RFC 2330). Internet Engineering Task Force. https://tools.ietf.org/html/rfc2330

18. ITU-T. (2001). *End-user multimedia QoS categories* (ITU-T Recommendation G.1010). International Telecommunication Union.

19. ITU-T. (2019). *Internet protocol data communication service - IP packet transfer and availability performance parameters* (ITU-T Recommendation Y.1540). International Telecommunication Union.

20. Tanenbaum, A. S., & Bos, H. (2015). *Modern Operating Systems* (4th ed.). Prentice Hall.

---

## NOTAS IMPORTANTES

1. **Formato de citas**: Las referencias están en formato estándar académico. Ajusta según el estilo requerido (APA, IEEE, etc.)

2. **Acceso a documentos**: Algunos estándares (ISO, IEEE) pueden requerir compra o acceso institucional. Las RFCs son de acceso libre.

3. **URLs**: Incluye URLs cuando estén disponibles públicamente (RFCs, documentación Python)

4. **Fechas**: Verifica las fechas de las últimas versiones de los estándares, ya que pueden haber sido actualizados

5. **Citas en el texto**: Cuando menciones estos conceptos en el informe, cita las referencias correspondientes. Por ejemplo:
   - "El modelo OSI (ISO/IEC, 1994) define siete capas..."
   - "Las direcciones MAC están definidas en el estándar IEEE 802 (IEEE Standards Association, 2014)..."
   - "La latencia se mide según las métricas IPPM (Almes et al., 1999)..."

---

**Total de nuevas referencias a agregar: 11 referencias**

Estas referencias cubren todos los conceptos adicionales relevantes mencionados en la sección 5 y 6 del documento MARCO_TEORICO.md.


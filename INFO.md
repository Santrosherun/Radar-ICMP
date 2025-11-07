# INFO IMPORTANTE


El Proceso Normal es:
- Tu aplicación: "Quiero enviar ping a 192.168.1.100"
- Scapy: "Necesito la MAC de 192.168.1.100"
- ARP lookup: Scapy busca en la tabla ARP local
- Si no la encuentra: "Using broadcast" (usar difusión)
---

# 🔍 ¿Por Qué Sigue Apareciendo el Warning?

Razón Principal: Scapy vs Sistema Operativo
El problema es que Scapy mantiene su propia tabla ARP interna, separada de la tabla ARP del sistema operativo. Aunque Windows ya tenga las direcciones MAC en su tabla ARP, Scapy no las consulta automáticamente.
---

# Poblar tabla ARP scrapy
Ping a 192.168.1.100 → "No conozco MAC" → Broadcast
Host responde → Scapy aprende: "192.168.1.100 = aa:bb:cc:dd:ee:ff"
Guarda en self.learned_macs
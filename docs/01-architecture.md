# 01 — Arquitectura

## Propósito

El laboratorio conecta tres dispositivos de red —router Cisco, firewall FortiGate y switch Cisco— con un contenedor Docker de administración. El contenedor ejecuta las auditorías, las remediaciones y las pruebas de verificación.

## Diagrama

```mermaid
flowchart LR
    R1["R1 · c7200<br/>203.0.113.21/30"]
    FW1["FW1 · FortiGate 7.0.9<br/>port1 203.0.113.22/30<br/>port2 10.21.75.1/24"]
    SW1["SW1 · IOSvL2<br/>10.21.75.2/24"]
    CT["cis-lab · Docker<br/>10.21.75.10/24"]
    R1 --- FW1 --- SW1 --- CT
```

## Roles

- **R1:** router de borde simulado y origen de pruebas desde el segmento WAN.
- **FW1:** firewall que conecta el segmento de tránsito con la LAN de gestión.
- **SW1:** switch de acceso que interconecta el firewall y el contenedor.
- **cis-lab:** nodo de administración, auditoría automatizada, verificación TCP/TLS y syslog.

![Topología](../images/01-topology-gns3.png)

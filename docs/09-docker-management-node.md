# 09 — Nodo de administración Docker

## Función

`cis-lab` es un contenedor Docker conectado a la LAN de gestión mediante SW1. Integra el motor Python, Netmiko, herramientas de verificación y recepción syslog.

## Parámetros de red

| Parámetro | Valor |
|---|---|
| Interfaz | `eth0` |
| IP | `10.21.75.10/24` |
| Gateway | `10.21.75.1` |
| Volumen de trabajo | `/work` |
| Directorio de aplicación | `/opt/cis-lab` |
| CLI | `/usr/local/bin/cis-lab` |

## Variables de entorno

```text
CISCO_USER
CISCO_PASS
CISCO_ENABLE
FGT_USER
FGT_PASS
```

Las credenciales pueden solicitarse interactivamente cuando no estén definidas. No se almacenan en el inventario versionado.

## Directorios

- `/opt/cis-lab/`: motor Python y scripts auxiliares.
- `/work/inventory.json`: inventario usado por el wrapper.
- `/work/informes/`: informes y respaldos.
- `/work/logs/`: archivos de syslog.

## Construcción

El Dockerfile original y el contexto completo de construcción no forman parte de los archivos recibidos para esta documentación. Por ello, no se incorpora un Dockerfile reconstruido que pueda diferir de la imagen ejecutada. La imagen local utilizada fue identificada como `cis-lab:1.0`.

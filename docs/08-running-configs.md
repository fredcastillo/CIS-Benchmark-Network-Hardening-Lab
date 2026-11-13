# 08 — Running-configs antes y después

## Estado inicial

Los archivos de `configs/before/` documentan la configuración inicial utilizada para establecer la línea base de la auditoría. En ellos se muestran los parámetros débiles relevantes para la práctica, como Telnet, HTTP, credenciales reversibles y administración WAN habilitada.

## Estado posterior

`apply` crea respaldos antes de modificar los equipos. Los archivos `backup_*.cfg` que produce el script corresponden al estado anterior a la aplicación.

El repositorio incluye un extracto VTY observado en R1 y el comando de remediación WAN definido en el script. Estos extractos no se presentan como sustitutos de running-config completos.

Para completar la evidencia posterior, exportar desde los equipos endurecidos:

- R1: `show running-config`
- SW1: `show running-config`
- FW1: `show full-configuration`

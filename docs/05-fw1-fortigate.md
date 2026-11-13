# 05 — FW1: FortiGate 7.0.9

## Plataforma

FortiGate-VM64-KVM v7.0.9, build 0444.

## Función y direccionamiento

| Interfaz | IP | Uso |
|---|---|---|
| port1 | `203.0.113.22/30` | WAN hacia R1 |
| port2 | `10.21.75.1/24` | LAN hacia SW1 |

## Configuración inicial

```text
config system global
    set hostname FW1
end

config system interface
    edit "port1"
        set mode static
        set ip 203.0.113.22 255.255.255.252
        set allowaccess ping https ssh http telnet
        set alias "WAN-R1"
    next
    edit "port2"
        set mode static
        set ip 10.21.75.1 255.255.255.0
        set allowaccess ping https ssh http telnet
        set alias "LAN"
    next
end

config router static
    edit 1
        set gateway 203.0.113.21
        set device "port1"
    next
end

config firewall policy
    edit 1
        set name "LAN-to-WAN"
        set srcintf "port2"
        set dstintf "port1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set nat enable
        set logtraffic disable
    next
end
```

La configuración inicial permite servicios de administración en ambas interfaces y no habilita el registro de tráfico de la política mostrada.

## Controles evaluados

El script incluye controles de banners, hostname, NTP, política de contraseñas, bloqueo administrativo, timeout, cifrado TLS, SNMP, `allowaccess`, trusted hosts, syslog y logging de políticas.

El renombrado de la cuenta administrativa por defecto se clasifica como `MANUAL`.

## Administración WAN

El control de interfaz WAN comprueba `port1` y remedia los permisos administrativos para permitir únicamente ping:

```text
config system interface
    edit "port1"
        set allowaccess ping
    next
end
```

La administración HTTPS por LAN debe seguir disponible para permitir gestionar el firewall desde la red autorizada.

## Comandos de consulta

```text
get system status
show full-configuration system global
show full-configuration system interface
show full-configuration system admin
show full-configuration log syslogd setting
show full-configuration firewall policy
```

![Prueba de acceso WAN](../images/09-wan-management-blocked.png)

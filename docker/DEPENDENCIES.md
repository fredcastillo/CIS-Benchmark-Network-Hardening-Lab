# Dependencias del contenedor cis-lab

## Python

```text
netmiko>=4.2
paramiko==3.5.1
```

Paramiko 3.5.1 fue utilizado en el entorno corregido para mantener compatibilidad de negociación SSH con las imágenes IOS emuladas.

## Herramientas de sistema utilizadas por los scripts

- Bash
- OpenSSH client
- netcat (`nc`)
- OpenSSL (`openssl s_client`)
- Nmap (opcional, para `cis-lab verify --nmap`)
- rsyslog / rsyslogd
- iproute2 (`ip`)
- utilidades básicas de Linux (`timeout`, `tail`, `pgrep`, `tar`)

El Dockerfile original no fue proporcionado y no se reconstruye en este repositorio.

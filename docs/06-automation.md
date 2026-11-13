# 06 — Automatización y scripts

## Archivos ejecutables

| Archivo | Función |
|---|---|
| `scripts/hardening_cis.py` | Evaluación CIS, remediación, respaldo e informes |
| `scripts/cis-lab` | Comando unificado del contenedor |
| `scripts/verify.sh` | Pruebas externas TCP/TLS |

## `cis-lab`

```bash
cis-lab help
cis-lab audit
cis-lab apply
cis-lab verify
cis-lab verify --nmap
cis-lab list
cis-lab ip 10.21.75.10/24 10.21.75.1
cis-lab syslog
cis-lab logs
cis-lab shell
```

La versión utilizada durante la demostración no implementa un subcomando `fails`.

## Motor Python

```bash
python3 /opt/cis-lab/hardening_cis.py --list-checks
python3 /opt/cis-lab/hardening_cis.py --mode audit --inventory /work/inventory.json --outdir /work/informes
python3 /opt/cis-lab/hardening_cis.py --mode apply --inventory /work/inventory.json --outdir /work/informes
python3 /opt/cis-lab/hardening_cis.py --mode apply --only R1,SW1
```

El modo `apply` solicita escribir `APLICAR`, a menos que se utilice `--yes`.

## Wrapper de shell

El wrapper determina las rutas de la aplicación, volumen de trabajo, inventario e informes. `audit` y `apply` invocan el motor Python. `verify` ejecuta `verify.sh`. `syslog` inicia rsyslog y `logs` sigue los archivos recibidos.

## Informes

Los informes HTML son destinados a revisión visual. Los JSON contienen los resultados estructurados. El modo apply almacena respaldos previos y un diff generado al comparar las configuraciones recopiladas.

## Syslog

El wrapper prepara `/work/logs/` e inicia rsyslog usando `/etc/rsyslog.conf`. El comando `cis-lab logs` muestra en vivo los archivos de registro de esa ruta.


## Ubicación de archivos dentro del contenedor

El wrapper utilizado busca `hardening_cis.py`, `verify.sh` e `inventory.example.json` dentro de `/opt/cis-lab/`, y el comando se instala en `/usr/local/bin/cis-lab`. El mapeo de archivos del repositorio es:

```bash
mkdir -p /opt/cis-lab
cp scripts/hardening_cis.py /opt/cis-lab/hardening_cis.py
cp scripts/verify.sh /opt/cis-lab/verify.sh
cp inventory.example.json /opt/cis-lab/inventory.example.json
cp scripts/cis-lab /usr/local/bin/cis-lab
chmod +x /usr/local/bin/cis-lab /opt/cis-lab/verify.sh
```

El inventario en uso dentro de la práctica se conserva además en `inventory/inventory.json`.

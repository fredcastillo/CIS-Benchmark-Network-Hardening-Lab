# cis-lab - Imagen Docker para laboratorios GNS3

Imagen auxiliar para ejecutar auditorías y tareas de hardening CIS sobre equipos Cisco IOS y FortiGate. Incluye Netmiko, herramientas de conectividad, OpenSSL, Nmap, Netcat y rsyslog.

## Requisito previo: incorporar el script principal

El archivo `hardening_cis.py` debe ser la copia exacta utilizada en la práctica. No se incluye una versión distinta porque el script guardado anteriormente en el repositorio no coincide con el SHA-256 del archivo extraído de la imagen GNS3.

Desde PowerShell, después de extraer esta carpeta dentro del repositorio, copia el archivo directamente desde la VM GNS3:

```powershell
scp gns3@192.168.232.130:/home/gns3/cis-lab-build-review/from-image/hardening_cis.py .\docker\hardening_cis.py
```

Verifica en la VM que el original extraído tenga este SHA-256:

```text
d002f6368074267be4615c61c54d55e5057bfd515c75f7fa05f079c2688694c9
```

Si la carpeta destino en Windows tiene otro nombre, ajusta la ruta local del comando SCP.

## Construir la imagen

Ejecuta desde esta carpeta, una vez añadido `hardening_cis.py`:

```bash
docker build -t cis-lab:1.0 .
```

La dependencia Paramiko queda fijada en 3.5.1 para reproducir la corrección de compatibilidad SSH aplicada durante el laboratorio. Netmiko se restringe a la rama mayor 4.

## Validar antes de publicar

```bash
docker run --rm --entrypoint python3 cis-lab:1.0 -c "import netmiko,paramiko; print('Netmiko',netmiko.__version__); print('Paramiko',paramiko.__version__)"
docker run --rm cis-lab:1.0 cis-lab list
docker run --rm cis-lab:1.0 cis-lab help
```

La lista de controles debe imprimirse y Paramiko debe indicar 3.5.1.

## Publicar en Docker Hub

Inicia sesión usando un Personal Access Token de Docker Hub:

```bash
docker login --username fredcastillo
docker tag cis-lab:1.0 fredcastillo/cis-lab:1.0
docker tag cis-lab:1.0 fredcastillo/cis-lab:latest
docker push fredcastillo/cis-lab:1.0
docker push fredcastillo/cis-lab:latest
```

No guardes el token, contraseñas de los dispositivos ni archivos `.env` en el repositorio o en la imagen.

## Descargar y ejecutar

```bash
docker pull fredcastillo/cis-lab:1.0
docker run --rm -it -v "$PWD:/work" fredcastillo/cis-lab:1.0
```

Para operar contra dispositivos de red, el contenedor debe tener conectividad hacia las IP de administración y un inventario propio en `/work/inventory.json`. La imagen crea una copia de `inventory.example.json` cuando ese archivo no existe.

En GNS3, importa `fredcastillo/cis-lab:1.0` como Docker container template y asigna las interfaces/red según la topología. El montaje persistente `/work` conserva informes y logs fuera de la capa de la imagen.

## Comandos disponibles

```bash
cis-lab help
cis-lab list
cis-lab audit
cis-lab audit --only R1,SW1
cis-lab apply --only R1,SW1
cis-lab verify
cis-lab verify --nmap
cis-lab syslog
cis-lab logs
cis-lab ip 10.21.75.10/24 10.21.75.1
```

`apply` modifica configuración de red. Primero ejecuta `audit`, revisa el inventario y conserva acceso por consola de GNS3. No uses `--yes` hasta verificar la red de administración.

## Inventario

`inventory.example.json` usa el direccionamiento del laboratorio como ejemplo. Cópialo a `/work/inventory.json` y adapta IP, plataforma, rol, red de administración, interfaz WAN y excepciones. No contiene credenciales.

## Consideraciones de seguridad

- Las credenciales se entregan mediante variables de entorno en tiempo de ejecución o se solicitan interactivamente; nunca se incorporan al Dockerfile.
- `/work` es un volumen persistente para inventario local, informes y logs. No publiques su contenido sin revisarlo.
- `ssh_legacy.conf` habilita algoritmos heredados únicamente para las IP de los equipos de laboratorio indicados. Amplía ese alcance solo si es necesario y en redes aisladas.
- Paramiko 3.5.1 se fija para compatibilidad con el IOS antiguo utilizado en el laboratorio; no debe interpretarse como recomendación universal para otros proyectos.
- Los controles y referencias CIS deben contrastarse con la edición exacta del benchmark aplicable. Este proyecto es un laboratorio educativo independiente y no está afiliado a CIS.

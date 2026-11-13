# Nodo Docker cis-lab

La imagen utilizada en el entorno se identificó como `cis-lab:1.0`. Se ejecutó como nodo Docker en GNS3 y se conectó a SW1 para acceder a la LAN de gestión.

El contenedor utilizó `/opt/cis-lab` para los componentes de la aplicación y `/work` como volumen de trabajo persistente para inventario, informes y logs.

El Dockerfile y el contexto original de construcción no fueron proporcionados entre los archivos revisados, por lo que no se agrega una reconstrucción no verificada.

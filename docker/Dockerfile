FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="cis-lab" \
      org.opencontainers.image.description="Auditoria y hardening de Cisco IOS y FortiGate para laboratorios GNS3" \
      org.opencontainers.image.authors="Fred Sneyder Castillo Apolinar" \
      org.opencontainers.image.version="1.0"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client telnet nmap openssl netcat-openbsd \
        iputils-ping traceroute tcpdump iproute2 \
        rsyslog procps less nano curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt

RUN mkdir -p /opt/cis-lab /work/informes /work/logs

COPY hardening_cis.py /opt/cis-lab/hardening_cis.py
COPY inventory.example.json /opt/cis-lab/inventory.example.json
COPY verify.sh /opt/cis-lab/verify.sh
COPY cis-lab /usr/local/bin/cis-lab
COPY rsyslog.conf /etc/rsyslog.conf
COPY ssh_legacy.conf /etc/ssh/ssh_config.d/10-cis-lab-legacy.conf

RUN chmod 0755 /usr/local/bin/cis-lab /opt/cis-lab/verify.sh

WORKDIR /work
VOLUME ["/work"]
CMD ["cis-lab", "shell"]

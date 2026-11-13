#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hardening_cis.py - Auditoría y hardening basado en CIS Benchmarks (laboratorio GNS3)

Dispositivos soportados : Cisco IOS (router c7200 / switch IOSvL2) y FortiGate 7.0.x
Autor                   : Laboratorio académico de Seguridad de Redes
Red del laboratorio     : 10.21.75.0/24

MODOS
  --mode audit : SOLO lee la configuración y genera el informe. No cambia nada.
  --mode apply : respalda la config, aplica las reglas que fallan, guarda y
                 genera un informe póstumo (antes / después).

REQUISITOS
  pip install "netmiko>=4.2"

CREDENCIALES (nunca se escriben en el informe ni en el código)
  Variables de entorno opcionales: CISCO_USER, CISCO_PASS, CISCO_ENABLE, FGT_USER, FGT_PASS
  Si no existen, el script las pide por teclado.

EJEMPLOS
  python3 hardening_cis.py --list-checks
  python3 hardening_cis.py --mode audit
  python3 hardening_cis.py --mode apply --only R1,SW1
  python3 hardening_cis.py --mode apply --yes --outdir informes

NOTA: la numeración CIS corresponde al benchmark "CIS Cisco IOS 15" y a la guía
"CIS FortiGate 7.0.x". Verifica la numeración exacta contra la versión de tu PDF.
"""
import argparse
import difflib
import getpass
import html
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List

PASS, FAIL, ERR, MANUAL, EXC = "PASS", "FAIL", "ERROR", "MANUAL", "EXCEPCION"
WEIGHT = {"Alta": 3, "Media": 2, "Baja": 1}
ROUTER, SWITCH, FIREWALL = "router", "switch", "firewall"
BOTH = (ROUTER, SWITCH)
STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
BANNER = ("ACCESO RESTRINGIDO - Solo personal autorizado. "
          "La actividad en este equipo es monitoreada y registrada.")

# Mapeo orientativo control -> técnica MITRE ATT&CK que mitiga (verificar en attack.mitre.org)
ATTACK = {}
for _ids, _t in (("C-01 C-03", "T1552"), ("C-02 C-04 C-05 C-06 C-07 F-12", "T1078"),
                 ("C-08 C-18 C-19 F-08 F-10", "T1040"), ("C-09 C-11 F-11", "T1021"),
                 ("C-10 F-07", "T1563"), ("C-15 F-09", "T1602"), ("C-20 C-21 F-05 F-06", "T1110"),
                 ("C-22 C-23 C-24 C-25", "T1046"), ("C-26", "T1499"), ("C-27", "T1190"),
                 ("C-28 C-29 C-30 C-31 C-32 C-33 F-13 F-14", "T1070"), ("C-35", "T1557.002"),
                 ("C-36 C-37 C-39", "T1557"), ("C-38", "T1200"), ("F-15", "T1133")):
    for _i in _ids.split():
        ATTACK[_i] = _t


# ============================================================================
# Modelo de datos
# ============================================================================
@dataclass
class Check:
    cid: str
    cis: str
    title: str
    why: str          # por qué se aplica (va al informe)
    sev: str          # Alta / Media / Baja
    roles: tuple
    evaluate: Callable  # (ctx) -> (bool, detalle)
    fix: Callable       # (ctx) -> [comandos]
    manual: bool = False  # True = solo se reporta, no se aplica automáticamente
    slow: bool = False    # comandos lentos (generación de llaves RSA)


class Ctx:
    """Contexto de un dispositivo: salidas de 'show', parámetros y secretos."""

    def __init__(self, text, params, secrets):
        self.text, self.params, self.secrets = text, params, secrets

    @property
    def run(self):
        return self.text.get("run", "")


# ============================================================================
# CISCO IOS - utilidades de parseo
# ============================================================================
def cisco_blocks(run, header_re):
    """Devuelve [(encabezado, [líneas hijas])] de los bloques que coinciden."""
    out, cur = [], None
    for ln in run.splitlines():
        if not ln.strip() or ln.startswith("!"):
            cur = None
            continue
        if not ln[0].isspace():
            cur = (ln.strip(), []) if re.match(header_re, ln) else None
            if cur is not None:
                out.append(cur)
        elif cur is not None:
            cur[1].append(ln.strip())
    return out


LINE_RE = {"con": r"^line con 0", "aux": r"^line aux", "vty": r"^line vty"}


def line_blocks(kinds):
    return lambda c: [b for k in kinds for b in cisco_blocks(c.run, LINE_RE[k])]


def ifaces(c):
    return cisco_blocks(c.run, r"^interface ")


def all_present(*patterns):
    def ev(c):
        miss = [p.replace("^", "").replace("\\b", "") for p in patterns if re.search(p, c.run, re.M) is None]
        return (not miss), "OK" if not miss else "Faltan: " + ", ".join(miss)
    return ev


def present(pattern):
    def ev(c):
        ok = re.search(pattern, c.run, re.M) is not None
        return ok, "OK" if ok else "No configurado"
    return ev


def absent(pattern):
    def ev(c):
        m = re.search(pattern, c.run, re.M)
        return m is None, "OK" if m is None else f"Presente: {m.group(0).strip()}"
    return ev


def block_rule(getter, is_bad, fix_lines, pre=None):
    """Regla sobre bloques (líneas/interfaces): evalúa y genera la corrección."""
    def bad(c):
        return [h for h, kids in getter(c) if is_bad(kids)]

    def ev(c):
        b = bad(c)
        return (not b), "OK" if not b else "Incumplen: " + "; ".join(b)

    def fx(c):
        cmds = list(pre(c)) if pre else []
        for h in bad(c):
            cmds += [h] + list(fix_lines)
        return cmds
    return ev, fx


def timeout_bad(kids):
    for k in kids:
        m = re.match(r"exec-timeout (\d+)(?: (\d+))?$", k)
        if m:
            t = int(m.group(1)) * 60 + int(m.group(2) or 0)
            return t == 0 or t > 600
    return True


def rsa_sizes(text):
    """Estima los bits de cada llave RSA a partir del encabezado DER del 'Key Data'."""
    out = {}
    for chunk in re.split(r"(?m)^Key name:\s*", text)[1:]:
        label = chunk.splitlines()[0].strip().lower()
        m = re.search(r"Key Data:\s*([0-9A-Fa-f\s]+)", chunk)
        if not m:
            continue
        h = re.sub(r"\s+", "", m.group(1))
        if h.startswith("3082"):
            n = int(h[4:8], 16)
        elif h.startswith("3081"):
            n = int(h[4:6], 16)
        else:
            continue
        out[label] = round(((n - 30) * 8) / 256) * 256
    return out


def active_ssh_label(c):
    m = re.search(r"^ip ssh rsa keypair-name (\S+)", c.run, re.M)
    if m:
        return m.group(1).lower()
    h = re.search(r"^hostname (\S+)", c.run, re.M)
    d = re.search(r"^ip domain[- ]name (\S+)", c.run, re.M)
    return f"{h.group(1)}.{d.group(1)}".lower() if h and d else None


def log_level(c, which):
    m = re.search(rf"^\s*{which} logging: level (\w+)", c.text.get("logging", ""), re.M | re.I)
    return m.group(1).lower() if m else None


# ============================================================================
# CISCO IOS - definición de controles (el orden = orden seguro de aplicación)
# ============================================================================
CISCO: List[Check] = []


def add_c(cis, title, why, sev, ev, fx, roles=BOTH, **kw):
    CISCO.append(Check(f"C-{len(CISCO) + 1:02d}", cis, title, why, sev, roles, ev, fx, **kw))


# ---- Management plane: credenciales ---------------------------------------
def ev_enable(c):
    s = re.search(r"^enable secret ", c.run, re.M)
    p = re.search(r"^enable password ", c.run, re.M)
    if s and not p:
        return True, "OK"
    return False, "Falta 'enable secret'" if not s else "Existe 'enable password' (reversible)"


add_c("1.4.1", "'enable secret' configurado (sin 'enable password')",
      "El hash del enable secret no es reversible; 'enable password' se puede descifrar fácilmente.",
      "Alta", ev_enable,
      lambda c: ["no enable password", f"enable secret {c.secrets['enable']}"])


def user_lines(c):
    return re.findall(r"^username (\S+)(.*)$", c.run, re.M)


def users_bad(c):
    return [u for u, r in user_lines(c)
            if not re.search(r"\bsecret\b", r) or re.search(r"privilege (?!1\b)\d+", r)]


def ev_users(c):
    if not user_lines(c):
        return False, "No hay usuarios locales"
    b = users_bad(c)
    return (not b), "OK" if not b else "Sin 'secret' o privilegio != 1: " + ", ".join(b)


add_c("1.4.3 / 1.2.1", "Usuarios locales con 'secret' y 'privilege 1'",
      "Evita contraseñas reversibles y obliga a pasar por 'enable' para tener privilegio 15 (mínimo privilegio).",
      "Alta", ev_users,
      lambda c: [f"username {c.secrets['user']} privilege 1 secret {c.secrets['user_pass']}"])

add_c("1.4.2", "'service password-encryption' habilitado",
      "Cifra (tipo 7) las contraseñas que queden en texto claro en la configuración.",
      "Media", present(r"^service password-encryption"), lambda c: ["service password-encryption"])

# ---- AAA ------------------------------------------------------------------
add_c("1.1.1", "'aaa new-model' habilitado",
      "Base del modelo AAA: autenticación centralizada y consistente en consola/VTY.",
      "Alta", present(r"^aaa new-model"), lambda c: ["aaa new-model"])
add_c("1.1.2", "'aaa authentication login default' configurado",
      "Define el método de autenticación de login (local) y evita accesos sin credenciales.",
      "Alta", present(r"^aaa authentication login default (local|group)"),
      lambda c: ["aaa authentication login default local"])
add_c("1.1.3", "'aaa authentication enable default' configurado",
      "Protege el paso a modo privilegiado con el método definido.",
      "Media", present(r"^aaa authentication enable default"),
      lambda c: ["aaa authentication enable default enable"])

ev, fx = block_rule(line_blocks(("con", "vty")),
                    lambda k: not any(x.startswith("login authentication") for x in k),
                    ["login authentication CIS_LOGIN"],
                    pre=lambda c: ["aaa authentication login CIS_LOGIN local"])
add_c("1.1.4 / 1.1.6", "'login authentication' en line con 0 y line vty",
      "Cada línea de acceso debe autenticar contra una lista AAA explícita.", "Alta", ev, fx)

# ---- Acceso a líneas ------------------------------------------------------
ev, fx = block_rule(line_blocks(("vty",)), lambda k: "transport input ssh" not in k,
                    ["transport input ssh"])
add_c("1.2.2", "'transport input ssh' en line vty",
      "Telnet envía usuario y clave en texto claro; SSH cifra la sesión de administración.",
      "Alta", ev, fx)

ev, fx = block_rule(line_blocks(("aux",)),
                    lambda k: "no exec" not in k or "transport input none" not in k,
                    ["no exec", "transport input none"])
add_c("1.2.3 / 1.2.9", "Línea AUX deshabilitada ('no exec' + 'transport input none')",
      "Un puerto auxiliar abierto es una puerta de entrada fuera del control de la red.",
      "Media", ev, fx)

ev, fx = block_rule(line_blocks(("con", "aux", "vty")), timeout_bad, ["exec-timeout 5 0"])
add_c("1.2.6 - 1.2.8", "'exec-timeout' <= 10 min en con/aux/vty",
      "Cierra sesiones inactivas y reduce el riesgo de sesiones abandonadas y secuestradas.",
      "Media", ev, fx)


def pre_vty_acl(c):
    net = c.params["mgmt_subnet"]
    return ["ip access-list standard CIS_VTY_ACL",
            f"permit {net.network_address} {net.hostmask}",
            "deny any log", "exit"]


ev, fx = block_rule(line_blocks(("vty",)),
                    lambda k: not any(x.startswith("access-class") for x in k),
                    ["access-class CIS_VTY_ACL in"], pre=pre_vty_acl)
add_c("1.2.4 / 1.2.5", "ACL + 'access-class' en line vty (solo red de gestión)",
      "Solo las IP de la VLAN de gestión pueden iniciar sesión remota en el equipo.",
      "Alta", ev, fx)

# ---- Banners --------------------------------------------------------------
for kind, ref in (("exec", "1.3.1"), ("login", "1.3.2"), ("motd", "1.3.3")):
    add_c(ref, f"'banner {kind}' configurado",
          "Aviso legal de acceso no autorizado; respaldo legal ante un incidente.", "Baja",
          present(rf"^banner {kind}\b"),
          lambda c, k=kind: [f"banner {k} #{BANNER}#"])


# ---- SNMP -----------------------------------------------------------------
def ev_snmp(c):
    n = re.findall(r"^snmp-server community (\S+)", c.run, re.M)
    return (not n), "OK" if not n else "Communities definidas: " + ", ".join(n)


add_c("1.5.x", "SNMP deshabilitado cuando no se usa (sin 'public/private')",
      "Las communities v1/v2c viajan en claro y suelen ser 'public/private'; amplían la superficie.",
      "Alta", ev_snmp,
      lambda c: [f"no snmp-server community {n}"
                 for n in re.findall(r"^snmp-server community (\S+)", c.run, re.M)] + ["no snmp-server"])

# ---- SSH ------------------------------------------------------------------


def ev_host(c):
    m = re.search(r"^hostname (\S+)", c.run, re.M)
    ok = bool(m) and m.group(1) not in ("Router", "Switch")
    return ok, "OK" if ok else "Hostname por defecto"


add_c("2.1.1.1.1", "Hostname definido (no por defecto)",
      "Requisito para generar llaves SSH e identificar el equipo en los logs.", "Baja",
      ev_host, lambda c: [f"hostname {c.params['hostname']}"])
add_c("2.1.1.1.2", "'ip domain-name' configurado",
      "Requisito para generar llaves RSA de SSH.", "Baja",
      present(r"^ip domain[- ]name \S+"), lambda c: [f"ip domain-name {c.params['domain']}"])


def ev_rsa(c):
    sizes = rsa_sizes(c.text.get("rsa", ""))
    lbl = active_ssh_label(c)
    bits = sizes.get(lbl) if lbl else None
    if bits is None:
        return False, "No se encontró llave RSA activa para SSH"
    return bits >= 2048, f"Llave '{lbl}' ~{bits} bits"


add_c("2.1.1.1.3", "Llave RSA de SSH >= 2048 bits",
      "Llaves de 1024 bits se consideran débiles; 2048 es el mínimo recomendado.", "Alta",
      ev_rsa,
      lambda c: ["crypto key generate rsa general-keys modulus 2048 label CIS-SSH",
                 "ip ssh rsa keypair-name CIS-SSH"], slow=True)
add_c("2.1.1.2", "SSH versión 2", "SSHv1 tiene fallas criptográficas conocidas.", "Alta",
      present(r"^ip ssh version 2"), lambda c: ["ip ssh version 2"])


def ev_ssh_to(c):
    m = re.search(r"^ip ssh time-out (\d+)", c.run, re.M)
    return bool(m) and int(m.group(1)) <= 60, "OK" if m and int(m.group(1)) <= 60 else "time-out no definido o > 60 s"


add_c("2.1.1.1.4", "'ip ssh time-out' <= 60 s",
      "Reduce la ventana para ataques durante la negociación SSH.", "Baja", ev_ssh_to,
      lambda c: ["ip ssh time-out 60"])
add_c("2.1.1.1.5", "'ip ssh authentication-retries' <= 3",
      "Limita los intentos de adivinar contraseñas por sesión.", "Media",
      present(r"^ip ssh authentication-retries [1-3]$"),
      lambda c: ["ip ssh authentication-retries 3"])

# ---- Servicios globales ---------------------------------------------------
add_c("2.1.2", "'no cdp run'", "CDP revela modelo, IOS e IPs a cualquier vecino L2.", "Media",
      present(r"^no cdp run"), lambda c: ["no cdp run"])
add_c("2.1.3", "'no ip bootp server'", "Servicio BOOTP innecesario.", "Baja",
      present(r"^no ip bootp server"), lambda c: ["no ip bootp server"])
add_c("2.1.4", "'no service dhcp'", "El equipo no debe actuar como DHCP si no se necesita.", "Baja",
      present(r"^no service dhcp"), lambda c: ["no service dhcp"])
add_c("2.1.5", "'no ip identd'", "Servicio identd innecesario que filtra información.", "Baja",
      absent(r"^ip identd"), lambda c: ["no ip identd"])
add_c("2.1.6 / 2.1.7", "'service tcp-keepalives-in/out'",
      "Libera sesiones TCP huérfanas (consume menos recursos y evita sesiones fantasma).", "Baja",
      all_present(r"^service tcp-keepalives-in", r"^service tcp-keepalives-out"),
      lambda c: ["service tcp-keepalives-in", "service tcp-keepalives-out"])
add_c("Complementaria", "Servidor HTTP/HTTPS del router deshabilitado",
      "La interfaz web del IOS es superficie de ataque innecesaria en un equipo gestionado por CLI.",
      "Media", absent(r"^ip http (server|secure-server)"),
      lambda c: ["no ip http server", "no ip http secure-server"])

# ---- Logging --------------------------------------------------------------
add_c("2.2.1", "'logging on'", "Los eventos deben generarse siempre.", "Media",
      absent(r"^no logging on"), lambda c: ["logging on"])


def ev_buf(c):
    m = re.search(r"^logging buffered (\d+)", c.run, re.M)
    ok = bool(m) and int(m.group(1)) >= 16384
    return ok, "OK" if ok else "Buffer no configurado o < 16384"


add_c("2.2.2", "'logging buffered' >= 16384 bytes",
      "Conserva el historial local si el servidor syslog no está disponible.", "Baja",
      ev_buf, lambda c: ["logging buffered 64000"])
add_c("2.2.3", "'logging console critical'",
      "Evita saturar la consola y mantiene visibles los eventos críticos.", "Baja",
      lambda c: (log_level(c, "Console") in ("critical", "alerts", "emergencies"),
                 f"nivel actual: {log_level(c, 'Console')}"),
      lambda c: ["logging console critical"])
add_c("2.2.4", "'logging host' hacia el servidor syslog",
      "Centraliza los logs fuera del equipo; un atacante no puede borrarlos localmente.", "Media",
      present(r"^logging (?:host )?\d{1,3}(?:\.\d{1,3}){3}"),
      lambda c: [f"logging host {c.params['syslog']}"])
add_c("2.2.5", "'logging trap informational'", "Nivel de detalle adecuado para auditoría.", "Baja",
      lambda c: (log_level(c, "Trap") == "informational", f"nivel actual: {log_level(c, 'Trap')}"),
      lambda c: ["logging trap informational"])
add_c("2.2.6 / 2.2.7", "'service timestamps debug/log datetime'",
      "Sin marca de tiempo no se pueden correlacionar eventos en un incidente.", "Media",
      all_present(r"^service timestamps debug datetime", r"^service timestamps log datetime"),
      lambda c: ["service timestamps debug datetime msec localtime show-timezone",
                 "service timestamps log datetime msec localtime show-timezone"])

# ---- Data plane -----------------------------------------------------------
add_c("3.1.1", "'no ip source-route'",
      "Impide que un atacante dicte la ruta del paquete (evasión de controles).", "Media",
      present(r"^no ip source-route"), lambda c: ["no ip source-route"])

ev, fx = block_rule(lambda c: [(h, k) for h, k in ifaces(c) if not h.startswith("interface Loopback")],
                    lambda k: any(re.match(r"ip address \d", x) for x in k)
                    and "no ip proxy-arp" not in k and "shutdown" not in k,
                    ["no ip proxy-arp"])
add_c("3.1.2", "'no ip proxy-arp' en interfaces con IP",
      "Evita que el equipo responda ARP por otros hosts (suplantación / fuga entre segmentos).",
      "Media", ev, fx)

# ---- Switch (complementarias L2; no son parte del CIS IOS) ---------------
trunks = lambda c: [(h, k) for h, k in ifaces(c) if "switchport mode trunk" in k]
ev, fx = block_rule(trunks, lambda k: "switchport nonegotiate" not in k, ["switchport nonegotiate"])
add_c("Complementaria L2", "'switchport nonegotiate' en troncales",
      "Desactiva DTP: un atacante no puede negociar un trunk desde un puerto de usuario.", "Alta",
      ev, fx, roles=(SWITCH,))

ev, fx = block_rule(trunks,
                    lambda k: not any(re.match(r"switchport trunk native vlan (?!1$)\d+", x) for x in k),
                    ["switchport trunk native vlan 999"],
                    pre=lambda c: ["vlan 999", "name NATIVA-SIN-USO", "exit"])
add_c("Complementaria L2", "VLAN nativa de troncales distinta de la VLAN 1",
      "Mitiga VLAN hopping (doble etiquetado) usando una VLAN nativa sin hosts.", "Alta",
      ev, fx, roles=(SWITCH,))

def ev_unused(c):
    b = [(h, k) for h, k in ifaces(c) if re.match(r"interface (Gigabit|Fast)Ethernet", h)]
    bad = [h for h, k in b if not any(x.startswith("switchport") for x in k)
           and not any(x.startswith(("description", "ip address")) for x in k) and "shutdown" not in k]
    return (not bad), "OK" if not bad else f"{len(bad)} puertos sin uso activos: " + ", ".join(bad[:4]) + ("..." if len(bad) > 4 else "")


def fx_unused(c):
    cmds = []
    for h, k in ifaces(c):
        if (re.match(r"interface (Gigabit|Fast)Ethernet", h)
                and not any(x.startswith("switchport") for x in k)
                and not any(x.startswith(("description", "ip address")) for x in k)
                and "shutdown" not in k):
            cmds += [h, "description PUERTO-SIN-USO", "shutdown"]
    return cmds


add_c("Complementaria L2", "Puertos sin uso apagados (shutdown)",
      "Un puerto libre y activo permite conectar un equipo no autorizado a la red.", "Media",
      ev_unused, fx_unused, roles=(SWITCH,))


def access_ports(c):
    return [(h, k) for h, k in ifaces(c) if "switchport mode access" in k]


def bpdu_state(c):
    g = re.search(r"^spanning-tree portfast (edge )?bpduguard default", c.run, re.M) is not None
    nopf = [h for h, k in access_ports(c) if not any(x.startswith("spanning-tree portfast") for x in k)]
    return g, nopf


def ev_bpdu(c):
    g, nopf = bpdu_state(c)
    if g and not nopf:
        return True, "OK"
    msg = []
    if not g:
        msg.append("falta 'spanning-tree portfast [edge] bpduguard default' global")
    if nopf:
        msg.append("sin portfast: " + ", ".join(nopf))
    return False, "; ".join(msg)


def fx_bpdu(c):
    # IOS antiguo usa 'portfast'; IOS moderno usa 'portfast edge'. Se prueban ambas sintaxis.
    g, nopf = bpdu_state(c)
    cmds = [] if g else ["spanning-tree portfast bpduguard default", "spanning-tree portfast edge bpduguard default"]
    for h in nopf:
        cmds += [h, "spanning-tree portfast", "spanning-tree portfast edge"]
    return cmds


add_c("Complementaria L2", "BPDU Guard por defecto + PortFast en puertos de acceso",
      "Un puerto de usuario que reciba BPDUs (switch rogue) se apaga solo; protege la topología STP.",
      "Media", ev_bpdu, fx_bpdu, roles=(SWITCH,))

CISCO_CMDS = {"run": "show running-config",
              "rsa": "show crypto key mypubkey rsa",
              "logging": "show logging | include logging:",
              "version": "show version | include Version"}


# ============================================================================
# FORTIGATE - utilidades de parseo
# ============================================================================
def forti_parse(text):
    """Devuelve (entradas{nombre:{clave:valor}}, planos{clave:valor}) del nivel principal."""
    entries, flat, depth, cur = {}, {}, 0, None
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("config "):
            depth += 1
        elif s == "end":
            depth -= 1
        elif s.startswith("edit ") and depth == 1:
            cur = s[5:].strip().strip('"')
            entries[cur] = {}
        elif s == "next" and depth == 1:
            cur = None
        elif s.startswith("set ") and depth == 1:
            k, _, v = s[4:].partition(" ")
            (entries[cur] if cur is not None else flat)[k] = v.strip()
    return entries, flat


def unq(v):
    return v.strip().strip('"')


def fg(c, key):
    return forti_parse(c.text.get(key, ""))


def fg_val(c, key, name):
    return unq(fg(c, key)[1].get(name, ""))


def fg_int(c, key, name):
    try:
        return int(fg_val(c, key, name))
    except ValueError:
        return None


FORTI: List[Check] = []


def add_f(cis, title, why, sev, ev, fx, **kw):
    FORTI.append(Check(f"F-{len(FORTI) + 1:02d}", cis, title, why, sev, (FIREWALL,), ev, fx, **kw))


def banner_msgs(c):
    return ['config system replacemsg admin "pre_admin-disclaimer-text"', f'set buffer "{BANNER}"', "end",
            'config system replacemsg admin "post_admin-disclaimer-text"', f'set buffer "{BANNER}"', "end"]


add_f("FGT 7.0 · System Settings · Banner pre-login", "Banner de pre-login habilitado",
      "Aviso legal antes de autenticarse; respaldo legal ante accesos no autorizados.", "Baja",
      lambda c: (fg_val(c, "global", "pre-login-banner") == "enable", f"pre-login-banner = {fg_val(c, 'global', 'pre-login-banner') or 'n/d'}"),
      lambda c: ["config system global", "set pre-login-banner enable", "end"] + banner_msgs(c))
add_f("FGT 7.0 · System Settings · Banner post-login", "Banner de post-login habilitado",
      "Recuerda al administrador las políticas de uso aceptable tras autenticarse.", "Baja",
      lambda c: (fg_val(c, "global", "post-login-banner") == "enable", f"post-login-banner = {fg_val(c, 'global', 'post-login-banner') or 'n/d'}"),
      lambda c: ["config system global", "set post-login-banner enable", "end"])
add_f("FGT 7.0 · System Settings · Hostname", "Hostname distinto del valor por defecto",
      "Identifica el equipo en logs y evita revelar el modelo del firewall.", "Baja",
      lambda c: (not fg_val(c, "global", "hostname").lower().startswith("fortigate"), f"hostname = {fg_val(c, 'global', 'hostname')}"),
      lambda c: ["config system global", f"set hostname {c.params['hostname']}", "end"])
add_f("FGT 7.0 · System Settings · NTP", "Sincronización NTP habilitada",
      "Hora correcta = logs correlacionables y certificados/validaciones válidos.", "Media",
      lambda c: (fg_val(c, "ntp", "ntpsync") == "enable", f"ntpsync = {fg_val(c, 'ntp', 'ntpsync') or 'n/d'}"),
      lambda c: ["config system ntp", "set ntpsync enable", "set type custom", "config ntpserver", "edit 1",
                 f'set server "{c.params["ntp"]}"', "next", "end", "end"])


def ev_pwd(c):
    f = fg(c, "pwd")[1]
    g = lambda k: int(unq(f.get(k, "0")) or 0)
    ok = (unq(f.get("status", "")) == "enable" and g("minimum-length") >= 8 and g("min-upper-case-letter") >= 1
          and g("min-lower-case-letter") >= 1 and g("min-number") >= 1 and g("min-non-alphanumeric") >= 1)
    return ok, f"status={unq(f.get('status', 'n/d'))}, longitud min={g('minimum-length')}"


add_f("FGT 7.0 · System Settings · Password Policy", "Política de contraseñas (>=8 y complejidad)",
      "Obliga a contraseñas de administrador robustas contra fuerza bruta y diccionario.", "Alta",
      ev_pwd,
      lambda c: ["config system password-policy", "set status enable", "set apply-to admin-password",
                 "set minimum-length 12", "set min-lower-case-letter 1", "set min-upper-case-letter 1",
                 "set min-number 1", "set min-non-alphanumeric 1", "end"])


def ev_lock(c):
    t, d = fg_int(c, "global", "admin-lockout-threshold"), fg_int(c, "global", "admin-lockout-duration")
    ok = t is not None and d is not None and 1 <= t <= 3 and d >= 900
    return ok, f"threshold={t}, duration={d}s"


add_f("FGT 7.0 · System Settings · Admin lockout", "Bloqueo de admin: <=3 intentos y >=900 s",
      "Frena ataques de fuerza bruta contra la consola de administración.", "Alta",
      ev_lock, lambda c: ["config system global", "set admin-lockout-threshold 3",
                          "set admin-lockout-duration 900", "end"])


def ev_idle(c):
    t = fg_int(c, "global", "admintimeout")
    return (t is not None and 1 <= t <= 5), f"admintimeout = {t} min"


add_f("FGT 7.0 · System Settings · Idle timeout", "Timeout de inactividad de admin <= 5 min",
      "Cierra sesiones de administración abandonadas.", "Media",
      ev_idle, lambda c: ["config system global", "set admintimeout 5", "end"])


def ev_tls(c):
    sc = fg_val(c, "global", "strong-crypto")
    v = fg_val(c, "global", "admin-https-ssl-versions")
    ok = sc in ("enable", "") and bool(v) and "tlsv1-0" not in v and "tlsv1-1" not in v
    return ok, f"strong-crypto={sc or 'no visible (por defecto enable)'}, tls={v or 'n/d'}"


add_f("FGT 7.0 · System Settings · Cifrado administrativo", "strong-crypto y solo TLS 1.2/1.3 en la GUI",
      "TLS 1.0/1.1 y cifradores débiles permiten ataques de downgrade al tráfico de administración.", "Alta",
      ev_tls, lambda c: ["config system global", "set strong-crypto enable",
                         "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"])
add_f("FGT 7.0 · System Settings · SNMP", "Agente SNMP deshabilitado",
      "SNMP v1/v2c es inseguro; se deshabilita si no se monitorea.", "Media",
      lambda c: (fg_val(c, "snmp", "status") == "disable", f"status = {fg_val(c, 'snmp', 'status') or 'n/d'}"),
      lambda c: ["config system snmp sysinfo", "set status disable", "end"])


def iface_bad(c):
    out = {}
    for name, kv in fg(c, "iface")[0].items():
        toks = unq(kv.get("allowaccess", "")).split()
        if {"http", "telnet"} & set(toks):
            out[name] = toks
    return out


def ev_iface(c):
    b = iface_bad(c)
    return (not b), "OK" if not b else "HTTP/Telnet en: " + ", ".join(f"{n}" for n in b)


def fx_iface(c):
    cmds = ["config system interface"]
    for name, toks in iface_bad(c).items():
        keep = [t for t in toks if t not in ("http", "telnet")]
        cmds += [f'edit "{name}"', ("set allowaccess " + " ".join(keep)) if keep else "unset allowaccess", "next"]
    return cmds + ["end"]


add_f("FGT 7.0 · Network · Acceso administrativo", "Sin HTTP ni Telnet en 'allowaccess' de interfaces",
      "Solo canales cifrados (HTTPS/SSH) para administrar; HTTP/Telnet exponen credenciales.", "Alta",
      ev_iface, fx_iface)


def admin_bad(c):
    return [n for n, kv in fg(c, "admin")[0].items()
            if unq(kv.get("trusthost1", "0.0.0.0 0.0.0.0")) == "0.0.0.0 0.0.0.0"]


def ev_trust(c):
    b = admin_bad(c)
    return (not b), "OK" if not b else "Admins sin trusthost: " + ", ".join(b)


def fx_trust(c):
    net = c.params["mgmt_subnet"]
    cmds = ["config system admin"]
    for n in admin_bad(c):
        cmds += [f'edit "{n}"', f"set trusthost1 {net.network_address} {net.netmask}", "next"]
    return cmds + ["end"]


add_f("FGT 7.0 · System Settings · Trusted hosts", "Administradores restringidos con 'trusthost'",
      "La cuenta admin solo puede iniciar sesión desde la red de gestión.", "Alta", ev_trust, fx_trust)
add_f("FGT 7.0 · System Settings · Admin por defecto", "Cuenta 'admin' por defecto renombrada (MANUAL)",
      "Un nombre de usuario conocido facilita la fuerza bruta. No se automatiza por riesgo de perder acceso.",
      "Media",
      lambda c: ("admin" not in fg(c, "admin")[0], "Existe la cuenta 'admin' por defecto"),
      lambda c: ["Crear nuevo super_admin con trusthost y contraseña fuerte:",
                 "  config system admin / edit <nuevo> / set accprofile super_admin / set password *** / end",
                 "Entrar con el nuevo usuario y eliminar: config system admin / delete admin / end"],
      manual=True)


def ev_syslog(c):
    st, sv = fg_val(c, "syslog", "status"), fg_val(c, "syslog", "server")
    return (st == "enable" and bool(sv)), f"status={st or 'n/d'}, server={sv or 'n/d'}"


add_f("FGT 7.0 · Logging · Syslog", "Logs enviados a un servidor syslog",
      "Logs centralizados e inalterables fuera del firewall para auditoría y respuesta a incidentes.", "Media",
      ev_syslog, lambda c: ["config log syslogd setting", "set status enable",
                            f"set server {c.params['syslog']}", "set port 514", "end"])


def policy_bad(c):
    return [i for i, kv in fg(c, "policy")[0].items() if unq(kv.get("logtraffic", "")) == "disable"]


def ev_policy(c):
    b = policy_bad(c)
    return (not b), "OK" if not b else "Políticas sin log (ID): " + ", ".join(b)


def fx_policy(c):
    cmds = ["config firewall policy"]
    for i in policy_bad(c):
        cmds += [f"edit {i}", "set logtraffic all", "next"]
    return cmds + ["end"]


add_f("FGT 7.0 · Policy & Objects · Logging", "Todas las políticas registran tráfico",
      "Sin log de tráfico no hay evidencia ni detección de comportamiento anómalo.", "Alta",
      ev_policy, fx_policy)

def wan_bad(c):
    kv = fg(c, "iface")[0].get(c.params["wan_iface"])
    if kv is None:
        return None
    return [t for t in unq(kv.get("allowaccess", "")).split() if t != "ping"]


def ev_wan(c):
    b = wan_bad(c)
    if b is None:
        return False, f"Interfaz {c.params['wan_iface']} no encontrada (use --wan-iface)"
    return (not b), "OK" if not b else f"Administración abierta en {c.params['wan_iface']}: " + ", ".join(b)


add_f("FGT 7.0 · Network · Interfaz WAN", "La interfaz WAN solo responde ping (sin administración)",
      "Nunca se debe poder administrar el firewall desde la zona no confiable; elimina HTTPS/SSH/Telnet expuestos a Internet.",
      "Alta", ev_wan,
      lambda c: ["config system interface", f'edit "{c.params["wan_iface"]}"', "set allowaccess ping", "next", "end"]
      if wan_bad(c) is not None else [])

FGT_CMDS = {"global": "show full-configuration system global",
            "pwd": "show full-configuration system password-policy",
            "iface": "show full-configuration system interface",
            "admin": "show full-configuration system admin",
            "snmp": "show full-configuration system snmp sysinfo",
            "syslog": "show full-configuration log syslogd setting",
            "ntp": "show full-configuration system ntp",
            "policy": "show full-configuration firewall policy",
            "version": "get system status"}


# ============================================================================
# Motor: conexión, evaluación, aplicación
# ============================================================================
def family_of(dev):
    return "fortinet" if dev["platform"].startswith("fortinet") else "cisco"


def get_creds(fam):
    if fam == "cisco":
        u = os.getenv("CISCO_USER") or input("Usuario Cisco (R1/SW1): ")
        p = os.getenv("CISCO_PASS") or getpass.getpass("Contraseña Cisco: ")
        e = os.getenv("CISCO_ENABLE") or getpass.getpass("Enable (Enter = misma contraseña): ")
        return {"user": u, "password": p, "enable": e or p}
    u = os.getenv("FGT_USER") or input("Usuario FortiGate: ")
    p = os.getenv("FGT_PASS") or getpass.getpass("Contraseña FortiGate: ")
    return {"user": u, "password": p}


def connect(dev, cr):
    from netmiko import ConnectHandler  # import tardio: --list-checks no requiere netmiko
    p = {"device_type": dev["platform"], "host": dev["host"], "username": cr["user"],
         "password": cr["password"], "fast_cli": False, "conn_timeout": 30, "timeout": 120,
         "port": dev.get("port", 23 if "telnet" in dev["platform"] else 22)}
    if family_of(dev) == "cisco":
        p["secret"] = cr["enable"]
    conn = ConnectHandler(**p)
    if family_of(dev) == "cisco":
        conn.enable()
    return conn


def collect(conn, fam):
    cmds = CISCO_CMDS if fam == "cisco" else FGT_CMDS
    return {k: conn.send_command(v, read_timeout=180) for k, v in cmds.items()}


SECRET_RE = re.compile(r"(?i)\b(secret|password)\b( \d| ENC)? \S+")


def redact(cmd):
    return SECRET_RE.sub(lambda m: f"{m.group(1)} ********", cmd)


def evaluate(checks, ctx, role, exceptions=None):
    exceptions = exceptions or {}
    res = []
    for ch in checks:
        if role not in ch.roles:
            continue
        r = {"id": ch.cid, "cis": ch.cis, "title": ch.title, "why": ch.why, "sev": ch.sev, "cmds": [],
             "attack": ATTACK.get(ch.cid, "-")}
        try:
            ok, detail = ch.evaluate(ctx)
            r["status"] = PASS if ok else (MANUAL if ch.manual else FAIL)
            r["detail"] = detail
            if not ok and ch.cid in exceptions:
                r["status"] = EXC
                r["detail"] = f"{detail} | Excepcion: {exceptions[ch.cid]}"
            elif not ok:
                r["cmds"] = [redact(x) for x in ch.fix(ctx)]
        except Exception as e:  # un control roto no debe tumbar el escaneo
            r["status"], r["detail"] = ERR, f"{type(e).__name__}: {e}"
        res.append(r)
    return res


ERR_PAT = {"cisco": re.compile(r"^%.*(Invalid|Incomplete|Ambiguous|Unrecognized|rror).*$", re.M | re.I),
           "fortinet": re.compile(r"^.*(Command fail|Unknown action|parse error|invalid|error).*$", re.M | re.I)}


def apply_fixes(conn, fam, checks, ctx, results):
    by_id = {c.cid: c for c in checks}
    done = {}
    for r in results:
        if r["status"] != FAIL:
            continue
        ch = by_id[r["id"]]
        cmds = ch.fix(ctx)
        if not cmds:
            continue
        print(f"    [+] {ch.cid} {ch.title}")
        out = conn.send_config_set(cmds, cmd_verify=False, read_timeout=300 if ch.slow else 90)
        errs = [m.group(0).strip() for m in ERR_PAT[fam].finditer(out)]
        done[ch.cid] = {"cmds": [redact(x) for x in cmds], "errors": errs}
    return done


def backup(conn, dev, ctx, fam, outdir):
    txt = ctx.text["run"] if fam == "cisco" else conn.send_command("show full-configuration", read_timeout=300)
    path = os.path.join(outdir, f"backup_{dev['name']}_{STAMP}.cfg")
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
    return path


def summarize(res):
    """Cuenta estados y calcula el puntaje ponderado por severidad (Alta 3, Media 2, Baja 1).
    Las excepciones documentadas no cuentan ni a favor ni en contra."""
    n = {PASS: 0, FAIL: 0, MANUAL: 0, ERR: 0, EXC: 0}
    got = tot = 0
    for r in res:
        n[r["status"]] += 1
        if r["status"] != EXC:
            w = WEIGHT.get(r["sev"], 1)
            tot += w
            got += w if r["status"] == PASS else 0
    return n, (round(100 * got / tot) if tot else 0)


def fmt(n):
    return f"{n[PASS]} PASS / {n[FAIL]} FAIL / {n[MANUAL]} MANUAL / {n[EXC]} EXCEPCION"


VOLATILE = re.compile(r"^(Building configuration|Current configuration|! Last configuration|"
                      r"! NVRAM config|ntp clock-period|Using \d+ out of)")


def make_diff(a, b, fam):
    keys = ["run"] if fam == "cisco" else [k for k in FGT_CMDS if k != "version"]

    def lines(ctx):
        t = "\n".join(ctx.text.get(k, "") for k in keys)
        return [redact(x.rstrip()) for x in t.splitlines() if x.strip() and not VOLATILE.match(x)]
    return "\n".join(difflib.unified_diff(lines(a), lines(b), "antes", "despues", lineterm="", n=1))


def first_version(text):
    for ln in text.splitlines():
        if "Version" in ln:
            return ln.strip()
    return ""


def process(dev, creds, args):
    fam, role = family_of(dev), dev["role"]
    checks = CISCO if fam == "cisco" else FORTI
    exc = dev.get("exceptions", {})
    rec = {"name": dev["name"], "host": dev["host"], "role": role, "family": fam, "version": "",
           "before": [], "after": None, "applied": {}, "error": None, "backup": None, "diff": ""}
    print(f"\n=== {dev['name']} ({dev['host']}, {role}) ===")
    if args.mode == "apply" and "telnet" in dev["platform"]:
        print("  [!] Aplicar por Telnet corta tu propia sesion al exigir SSH. Usa platform 'cisco_ios' (SSH).")
    conn = None
    try:
        cr = creds[fam]
        conn = connect(dev, cr)
        params = {"mgmt_subnet": ipaddress.ip_network(dev.get("mgmt_subnet", args.mgmt_subnet)),
                  "syslog": dev.get("syslog", args.syslog), "domain": args.domain, "ntp": args.ntp,
                  "wan_iface": dev.get("wan_iface", args.wan_iface),
                  "hostname": dev.get("hostname") or re.sub(r"[^A-Za-z0-9-]", "-", dev["name"])}
        secrets = {"user": cr["user"], "user_pass": cr["password"], "enable": cr.get("enable") or cr["password"]}
        ctx = Ctx(collect(conn, fam), params, secrets)
        rec["version"] = first_version(ctx.text.get("version", ""))
        rec["before"] = evaluate(checks, ctx, role, exc)
        n, score = summarize(rec["before"])
        print(f"  Version : {rec['version']}")
        print(f"  Estado inicial: {fmt(n)}  ->  {score}%")
        if args.mode == "apply":
            rec["backup"] = backup(conn, dev, ctx, fam, args.outdir)
            print(f"  Respaldo: {rec['backup']}")
            rec["applied"] = apply_fixes(conn, fam, checks, ctx, rec["before"])
            if fam == "cisco":
                # Solo se guarda si todavia se puede entrar (evita quedar bloqueado por la ACL de VTY)
                try:
                    conn2 = connect(dev, cr)
                    if not args.no_save and rec["applied"]:
                        conn2.save_config()
                    conn.disconnect()
                    conn = conn2
                except Exception as e:
                    rec["error"] = ("No se pudo reconectar tras aplicar; NO se guardo la configuracion "
                                    f"(un 'reload' restaura el estado previo). Detalle: {e}")
                    print(f"  [!] {rec['error']}")
                    conn.disconnect()
                    conn = None
            if conn is not None:
                ctx2 = Ctx(collect(conn, fam), params, secrets)
                rec["after"] = evaluate(checks, ctx2, role, exc)
                rec["diff"] = make_diff(ctx, ctx2, fam)
                n2, score2 = summarize(rec["after"])
                print(f"  Estado final  : {fmt(n2)}  ->  {score2}%")
        if conn is not None:
            conn.disconnect()
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"
        print(f"  [!] ERROR: {rec['error']}")
    return rec


# ============================================================================
# Informes (JSON + HTML)
# ============================================================================
def build_html(rep):
    e = html.escape
    apply_mode = rep["meta"]["mode"] == "apply"
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}"
           "h1{margin-bottom:0}h2{margin-top:32px;border-bottom:2px solid #444;padding-bottom:4px}"
           "table{border-collapse:collapse;width:100%;font-size:13px}"
           "th,td{border:1px solid #ccc;padding:6px;vertical-align:top;text-align:left}"
           "th{background:#2b3a55;color:#fff}pre{margin:0;white-space:pre-wrap;font-size:12px}"
           ".PASS{background:#d8f3dc;font-weight:600}.FAIL{background:#ffd6d6;font-weight:600}"
           ".MANUAL{background:#fff1c1;font-weight:600}.ERROR{background:#ddd;font-weight:600}"
           ".EXCEPCION{background:#dbe7ff;font-weight:600}.meta{color:#555}details{margin-top:10px}")
    p = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Informe CIS</title>"
         f"<style>{css}</style></head><body>",
         "<h1>Informe de cumplimiento CIS</h1>",
         f"<p class='meta'>Modo: <b>{e(rep['meta']['mode'].upper())}</b> &middot; Fecha: {e(rep['meta']['date'])} &middot; "
         f"Autor: {e(rep['meta']['author'])}<br>Puntaje ponderado por severidad (Alta 3, Media 2, Baja 1); "
         "las excepciones documentadas no puntuan. Mapeo ATT&amp;CK orientativo.</p>"]
    for d in rep["devices"]:
        p.append(f"<h2>{e(d['name'])} <small>({e(d['host'])} &middot; {e(d['role'])})</small></h2>")
        if d.get("version"):
            p.append(f"<p class='meta'>{e(d['version'])}</p>")
        if d["error"]:
            p.append(f"<p class='FAIL'>{e(d['error'])}</p>")
        if not d["before"]:
            continue
        n, s_ = summarize(d["before"])
        line = f"Antes: {fmt(n)} = <b>{s_}%</b>"
        if d["after"]:
            n2, s2 = summarize(d["after"])
            line += f" &nbsp;&rarr;&nbsp; Despues: {fmt(n2)} = <b>{s2}%</b>"
        p.append(f"<p>{line}</p>")
        if d["backup"]:
            p.append(f"<p class='meta'>Respaldo previo: {e(d['backup'])}</p>")
        after = {r["id"]: r for r in (d["after"] or [])}
        head = "<tr><th>ID</th><th>CIS</th><th>ATT&amp;CK</th><th>Control</th><th>Sev.</th>"
        head += "<th>Antes</th><th>Despues</th>" if apply_mode else "<th>Estado</th>"
        head += "<th>Detalle</th><th>Por que</th><th>" + ("Comandos aplicados" if apply_mode else "Remediacion propuesta") + "</th></tr>"
        p.append("<table>" + head)
        for r in d["before"]:
            a = after.get(r["id"])
            cells = (f"<td>{e(r['id'])}</td><td>{e(r['cis'])}</td><td>{e(r.get('attack', '-'))}</td>"
                     f"<td>{e(r['title'])}</td><td>{e(r['sev'])}</td><td class='{r['status']}'>{r['status']}</td>")
            if apply_mode:
                cells += f"<td class='{a['status']}'>{a['status']}</td>" if a else "<td>-</td>"
            detail = (a or r)["detail"]
            ap = d["applied"].get(r["id"])
            cmds = ap["cmds"] if ap else r["cmds"]
            extra = ""
            if ap and ap["errors"]:
                extra = "\n!! Errores del equipo:\n" + "\n".join(ap["errors"])
            cells += f"<td>{e(detail)}</td><td>{e(r['why'])}</td><td><pre>{e(chr(10).join(cmds) + extra)}</pre></td>"
            p.append(f"<tr>{cells}</tr>")
        p.append("</table>")
        if d.get("diff"):
            p.append(f"<details><summary>Diff de configuracion (antes &rarr; despues)</summary><pre>{e(d['diff'])}</pre></details>")
    p.append("</body></html>")
    return "".join(p)


def print_checks():
    print("| ID | CIS | ATT&CK | Aplica a | Sev. | Control |\n|---|---|---|---|---|---|")
    for ch in CISCO + FORTI:
        print(f"| {ch.cid} | {ch.cis} | {ATTACK.get(ch.cid, '-')} | {'/'.join(ch.roles)} | {ch.sev} | {ch.title} |")


# ============================================================================
# CLI
# ============================================================================
def main():
    ap = argparse.ArgumentParser(description="Auditoría / hardening CIS para Cisco IOS y FortiGate (GNS3)")
    ap.add_argument("--mode", choices=["audit", "apply"], help="audit = solo informe | apply = aplicar + informe póstumo")
    ap.add_argument("--inventory", default="inventory.json")
    ap.add_argument("--only", help="Nombres separados por coma (ej: R1,SW1)")
    ap.add_argument("--outdir", default="informes")
    ap.add_argument("--mgmt-subnet", default="10.21.75.10/32", help="Red autorizada a administrar (vty ACL / trusthost); se puede fijar por equipo en el inventario")
    ap.add_argument("--syslog", default="10.21.75.10", help="IP del servidor syslog")
    ap.add_argument("--domain", default="lab2175.local")
    ap.add_argument("--ntp", default="203.0.113.100", help="Servidor NTP (R1 como ntp master)")
    ap.add_argument("--wan-iface", default="port1", help="Interfaz WAN del FortiGate")
    ap.add_argument("--fail-under", type=int, default=0, help="Codigo de salida 2 si algun puntaje queda por debajo")
    ap.add_argument("--yes", action="store_true", help="No pedir confirmación en modo apply")
    ap.add_argument("--no-save", action="store_true", help="No ejecutar 'write memory' en Cisco")
    ap.add_argument("--list-checks", action="store_true", help="Lista los controles y sale")
    args = ap.parse_args()

    if args.list_checks:
        print_checks()
        return
    if not args.mode:
        ap.error("--mode es obligatorio (audit | apply)")

    with open(args.inventory, encoding="utf-8") as f:
        devices = json.load(f)["devices"]
    if args.only:
        sel = {x.strip() for x in args.only.split(",")}
        devices = [d for d in devices if d["name"] in sel]
    if not devices:
        sys.exit("No hay dispositivos que procesar.")

    if args.mode == "apply" and not args.yes:
        print(f"Se MODIFICARÁ la configuración de: {', '.join(d['name'] for d in devices)}")
        print(f"La administración quedará limitada a {args.mgmt_subnet}. Asegúrate de estar dentro de esa red.")
        if input("Escribe APLICAR para continuar: ").strip() != "APLICAR":
            sys.exit("Cancelado.")

    os.makedirs(args.outdir, exist_ok=True)
    creds = {fam: get_creds(fam) for fam in {family_of(d) for d in devices}}
    rep = {"meta": {"mode": args.mode, "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "author": "Laboratorio académico de Seguridad de Redes"},
           "devices": [process(d, creds, args) for d in devices]}

    base = os.path.join(args.outdir, f"informe_{args.mode}_{STAMP}")
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2, ensure_ascii=False)
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(build_html(rep))
    print(f"\nInforme generado:\n  {base}.html\n  {base}.json")
    if args.fail_under:
        low = []
        for d in rep["devices"]:
            res = d["after"] or d["before"]
            if not res or summarize(res)[1] < args.fail_under:
                low.append(d["name"])
        if low:
            print(f"[!] Puntaje < {args.fail_under}% en: {', '.join(low)}")
            sys.exit(2)


if __name__ == "__main__":
    main()

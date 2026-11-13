#!/usr/bin/env bash
# verify.sh - pruebas externas desde el contenedor. Ejecutar ANTES y DESPUES del hardening.
# Cada prueba compara lo observado contra el resultado esperado de un equipo ya endurecido.
R1="${R1_IP:-203.0.113.21}"; SW1="${SW1_IP:-10.21.75.2}"; FW1="${FW1_IP:-10.21.75.1}"
OUT="${CIS_OUTDIR:-/work/informes}"; mkdir -p "$OUT"
F="$OUT/verify_$(date +%Y%m%d_%H%M%S).txt"
ok=0; bad=0; skip=0

line() { printf '%s\n' "$1" | tee -a "$F"; }
count() { if [ "$1" = "CUMPLE" ]; then ok=$((ok+1)); elif [ "$1" = "NO CUMPLE" ]; then bad=$((bad+1)); else skip=$((skip+1)); fi; }

port() {  # descripcion esperado host puerto
  local got res
  if nc -z -w 3 "$3" "$4" >/dev/null 2>&1; then got=abierto; else got=cerrado; fi
  [ "$got" = "$2" ] && res="CUMPLE" || res="NO CUMPLE"; count "$res"
  line "$(printf '%-46s esperado=%-8s observado=%-8s %s' "$1" "$2" "$got" "$res")"
}

tls() {  # version esperado
  local out res got
  out=$(echo | timeout 10 openssl s_client -connect "$FW1:443" "-$1" -cipher 'ALL:@SECLEVEL=0' 2>&1)
  if echo "$out" | grep -q "BEGIN CERTIFICATE"; then got=negocia
  elif echo "$out" | grep -qi "no protocols available"; then got="inconcluso"
  else got=rechaza; fi
  if [ "$got" = "inconcluso" ]; then res="INCONCLUSO"; elif [ "$got" = "$2" ]; then res="CUMPLE"; else res="NO CUMPLE"; fi
  count "$res"
  line "$(printf '%-46s esperado=%-8s observado=%-8s %s' "FW1 $FW1:443 $1" "$2" "$got" "$res")"
}

line "== cis-lab verify  $(date '+%Y-%m-%d %H:%M:%S') =="
line "-- Puertos (esperado = equipo endurecido) --"
for h in "R1:$R1" "SW1:$SW1" "FW1:$FW1"; do
  n=${h%%:*}; ip=${h#*:}
  port "$n $ip:23  Telnet" cerrado "$ip" 23
  port "$n $ip:80  HTTP"   cerrado "$ip" 80
  port "$n $ip:22  SSH"    abierto "$ip" 22
done
port "R1  $R1:443 HTTPS (router)" cerrado "$R1" 443
port "FW1 $FW1:443 HTTPS (GUI por LAN)" abierto "$FW1" 443
line "-- TLS de la GUI del FortiGate --"
tls tls1_1 rechaza
tls tls1_2 negocia
line ""
line "Resumen: $ok CUMPLE | $bad NO CUMPLE | $skip INCONCLUSO"
line "PRUEBA MANUAL (desde la CLI de R1, simula un atacante externo):"
line "  R1# telnet 203.0.113.22 443    -> debe fallar tras el hardening (WAN del Forti sin administracion)"
line "  R1# telnet 203.0.113.22 22     -> debe fallar"

if [ "${1:-}" = "--nmap" ]; then
  line ""; line "-- nmap (evidencia) --"
  nmap -Pn -p 22,23,80,443 "$R1" "$SW1" "$FW1" | tee -a "$F"
fi
echo; echo "Guardado en $F"

#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <subnet|ip|file>"
  exit 1
fi

OUTDIR="scan_$(echo $TARGET | tr '/' '_')"
mkdir -p "$OUTDIR"

echo "[+] Target     : $TARGET"
echo "[+] Output dir : $OUTDIR"
echo

########################################
# STAGE 1 — HOST DISCOVERY
########################################
echo "[+] Stage 1: Host discovery..."

if [ -f "$TARGET" ]; then
  nmap -Pn -T4 -iL "$TARGET" -oG "$OUTDIR/01_alive.gnmap" > /dev/null
else
  nmap -Pn -T4 "$TARGET" -oG "$OUTDIR/01_alive.gnmap" > /dev/null
fi

grep "Up" "$OUTDIR/01_alive.gnmap" | awk '{print $2}' > "$OUTDIR/02_target.txt"

########################################
# STAGE 2 — FAST PORT DISCOVERY
########################################
echo "[+] Stage 2: Fast port mapping..."

nmap -Pn --top-ports 1000 --open -T4 \
-iL "$OUTDIR/02_target.txt" \
-oN "$OUTDIR/03_ports.txt" > /dev/null

########################################
# PARSE IP + PORT + SERVICE
########################################
awk '
/Nmap scan report for/ {ip=$5}
/^[0-9]+\/tcp[[:space:]]+open/ {
  split($1,p,"/");
  port=p[1];
  service=$3;
  print ip, port, service
}
' "$OUTDIR/03_ports.txt" > "$OUTDIR/04_ip_port_service.txt"

awk '
{
  ip=$1; port=$2; service=$3;
  key=service"|"port;
  group[key]=group[key] ? group[key]","ip : ip;
}
END {
  for (k in group) {
    split(k,a,"|");
    printf "%s %s %s\n", a[1], a[2], group[k];
  }
}
' "$OUTDIR/04_ip_port_service.txt" > "$OUTDIR/05_grouped.txt"

########################################
# STAGE 3 — SMART NSE PER SERVICE (BULK, FIXED)
########################################
echo "[+] Stage 3: Smart NSE per SERVICE (bulk scan)..."

> "$OUTDIR/03_detail_all.txt"

while read service port ips; do
  echo "   -> $service : $port"

  IPFILE="$OUTDIR/tmp_${service}_${port}.txt"
  echo "$ips" | tr ',' '\n' > "$IPFILE"

  case "$service" in
    http|http-proxy|blackice-icecap|blackice-alerts)
      SCRIPTS="http-* and not brute"
      ;;
    https|https-alt)
      SCRIPTS="(http-* or ssl-*) and not brute"
      ;;
    ssh)
      SCRIPTS="ssh-* and not brute"
      ;;
    ftp)
      SCRIPTS="ftp-* and not brute"
      ;;
    telnet)
      SCRIPTS="telnet-* and not brute"
      ;;
    smtp)
      SCRIPTS="smtp-* and not brute"
      ;;
    pop3)
      SCRIPTS="pop3-* and not brute"
      ;;
    imap)
      SCRIPTS="imap-* and not brute"
      ;;
    ldap)
      SCRIPTS="ldap-* and not brute"
      ;;
    microsoft-ds|netbios-ssn)
      SCRIPTS="smb-* and not brute"
      ;;
    msrpc)
      SCRIPTS="msrpc-* and not brute"
      ;;
    ms-wbt-server|vmrdp)
      SCRIPTS="rdp-* and not brute"
      ;;
    snmp)
      SCRIPTS="snmp-* and not brute"
      ;;
    ms-sql-s)
      SCRIPTS="ms-sql-* and not brute"
      ;;
    mysql)
      SCRIPTS="mysql-* and not brute"
      ;;
    sip)
      SCRIPTS="sip-* and not brute"
      ;;
    jetdirect)
      SCRIPTS="printer-* and not brute"
      ;;
    cisco-sccp)
      SCRIPTS="cisco-* and not brute"
      ;;
    uucp-rlogin)
      SCRIPTS="rlogin-* and not brute"
      ;;
    time)
      SCRIPTS="default and not brute"
      ;;
    *)
      SCRIPTS="default and not brute"
      ;;
  esac

  nmap -Pn -sS -sV -O -T4 --max-retries 1 \
  --script "$SCRIPTS" \
  -p"$port" -iL "$IPFILE" >> "$OUTDIR/03_detail_all.txt"

  rm -f "$IPFILE"

done < "$OUTDIR/05_grouped.txt"

########################################
# EXTRACT WEB TARGETS
########################################
awk '$1 ~ /http|https/ {print $3}' "$OUTDIR/05_grouped.txt" | tr ',' '\n' | sort -u > "$OUTDIR/06_ip_web.txt"

########################################
# HTTPX PROBE
########################################
if command -v httpx >/dev/null 2>&1; then
  echo "[+] Probing web with httpx..."
  cat "$OUTDIR/06_ip_web.txt" | httpx -silent -threads 50 \
  -o "$OUTDIR/07_httpx_alive.txt"
fi

echo
echo "[✓] DONE"
echo "[✓] Nmap detail : $OUTDIR/03_detail_all.txt"
echo "[✓] Web targets : $OUTDIR/06_ip_web.txt"
echo "[✓] HTTPX alive : $OUTDIR/07_httpx_alive.txt"

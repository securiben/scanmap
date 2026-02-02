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
    http|http-proxy)
      SCRIPTS="http-title,http-methods,http-enum,http-auth"
      ;;
    https|https-alt)
      SCRIPTS="http-title,http-methods,http-enum,http-auth,ssl-cert,ssl-enum-ciphers"
      ;;
    ssh)
      SCRIPTS="ssh-hostkey,ssh2-enum-algos,ssh-auth-methods"
      ;;
    ftp)
      SCRIPTS="ftp-anon,ftp-bounce"
      ;;
    telnet)
      SCRIPTS="telnet-encryption,telnet-ntlm-info"
      ;;
    smtp)
      SCRIPTS="smtp-commands,smtp-open-relay"
      ;;
    pop3)
      SCRIPTS="pop3-capabilities"
      ;;
    imap)
      SCRIPTS="imap-capabilities"
      ;;
    ldap)
      SCRIPTS="ldap-rootdse,ldap-search"
      ;;
    microsoft-ds|netbios-ssn)
      SCRIPTS="smb-enum-shares,smb-enum-users,smb-ls,smb-os-discovery,smb-security-mode"
      ;;
    msrpc)
      SCRIPTS="msrpc-enum"
      ;;
    ms-wbt-server)
      SCRIPTS="rdp-ntlm-info,rdp-enum-encryption"
      ;;
    snmp)
      SCRIPTS="snmp-info,snmp-interfaces,snmp-processes"
      ;;
    ms-sql-s)
      SCRIPTS="ms-sql-info,ms-sql-config,ms-sql-ntlm-info,ms-sql-empty-password"
      ;;
    mysql)
      SCRIPTS="mysql-info,mysql-empty-password"
      ;;
    *)
      SCRIPTS="default,safe"
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

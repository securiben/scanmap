#!/bin/bash
clear

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
# PROGRESS BAR
########################################
progress () {
  local current=$1
  local total=$2
  local width=40

  local percent=$((current * 100 / total))
  local filled=$((current * width / total))
  local empty=$((width - filled))

  printf "\r[%-${width}s] %d%% (%d/%d)" \
    "$(printf '#%.0s' $(seq 1 $filled))" \
    "$percent" "$current" "$total"
}

########################################
# STAGE 1 — REAL HOST DISCOVERY (FAST)
########################################
echo "[+] Stage 1: Host discovery (TCP SYN ping)..."

if [ -f "$TARGET" ]; then
  TARGETS=$(cat "$TARGET")
else
  TARGETS="$TARGET"
fi

TOTAL_NET=$(echo "$TARGETS" | wc -l)
COUNT=0
> "$OUTDIR/01_alive.gnmap"

while read net; do
  COUNT=$((COUNT+1))
  progress $COUNT $TOTAL_NET

  nmap -sn -T4 "$net" \
  -oG - >> "$OUTDIR/01_alive.gnmap"

done <<< "$TARGETS"

echo
grep "Up" "$OUTDIR/01_alive.gnmap" | awk '{print $2}' | sort -V > "$OUTDIR/02_target.txt"

########################################
# STAGE 2 — FAST PORT DISCOVERY (WITH PROGRESS)
########################################
echo "[+] Stage 2: Fast port mapping..."

TOTAL_IP=$(wc -l < "$OUTDIR/02_target.txt")
COUNT=0
> "$OUTDIR/03_ports.txt"

while read ip; do
  COUNT=$((COUNT+1))
  progress $COUNT $TOTAL_IP

  nmap -p- --open -T4 "$ip" \
  -oN - >> "$OUTDIR/03_ports.txt"

done < "$OUTDIR/02_target.txt"

echo

########################################
# PARSE IP + PORT + SERVICE (SORTED)
########################################
awk '
/Nmap scan report for/ {ip=$5}
/^[0-9]+\/tcp[[:space:]]+open/ {
  split($1,p,"/");
  port=p[1];
  service=$3;
  print ip, port, service
}
' "$OUTDIR/03_ports.txt" | sort -V > "$OUTDIR/04_ip_port_service.txt"

########################################
# GROUP BY SERVICE + PORT (ORDERED)
########################################
awk '
{
  ip=$1; port=$2; service=$3;
  key=service"|"port;
  group[key]=group[key] ? group[key]","ip : ip;
}
END {
  n=asorti(group, idx)
  for (i=1; i<=n; i++) {
    k=idx[i]
    split(k,a,"|")

    split(group[k], ips, ",")
    asort(ips)

    iplist=""
    for (j=1; j<=length(ips); j++)
      iplist = iplist ? iplist","ips[j] : ips[j]

    printf "%s %s %s\n", a[1], a[2], iplist
  }
}
' "$OUTDIR/04_ip_port_service.txt" > "$OUTDIR/05_grouped.txt"

########################################
# STAGE 3 — SMART NSE PER SERVICE (WITH PROGRESS)
########################################
echo "[+] Stage 3: Smart NSE per SERVICE (bulk)..."

TOTAL_GROUP=$(wc -l < "$OUTDIR/05_grouped.txt")
COUNT=0
> "$OUTDIR/03_detail_all.txt"

while read service port ips; do
  COUNT=$((COUNT+1))
  progress $COUNT $TOTAL_GROUP

  IPFILE="$OUTDIR/tmp_${service}_${port}.txt"
  echo "$ips" | tr ',' '\n' | sort -V > "$IPFILE"

  case "$service" in
    http|http-proxy)
      SCRIPTS="http-title,http-methods,http-headers,http-server-header"
      ;;
    https|https-alt)
      SCRIPTS="http-title,http-methods,http-headers,ssl-cert,ssl-enum-ciphers"
      ;;
    ssh) SCRIPTS="ssh-* and not brute" ;;
    ftp) SCRIPTS="ftp-* and not brute" ;;
    telnet) SCRIPTS="telnet-* and not brute" ;;
    smtp) SCRIPTS="smtp-* and not brute" ;;
    pop3) SCRIPTS="pop3-* and not brute" ;;
    imap) SCRIPTS="imap-* and not brute" ;;
    ldap) SCRIPTS="ldap-* and not brute" ;;
    microsoft-ds|netbios-ssn) SCRIPTS="smb-* and not brute" ;;
    msrpc) SCRIPTS="msrpc-* and not brute" ;;
    ms-wbt-server|vmrdp) SCRIPTS="rdp-* and not brute" ;;
    snmp) SCRIPTS="snmp-* and not brute" ;;
    ms-sql-s) SCRIPTS="ms-sql-* and not brute" ;;
    mysql) SCRIPTS="mysql-* and not brute" ;;
    sip) SCRIPTS="sip-* and not brute" ;;
    cisco-sccp) SCRIPTS="cisco-* and not brute" ;;
    *) SCRIPTS="default and not brute" ;;
  esac

  nmap -Pn -sS -sV -O -T4 --max-retries 1 \
  --script "$SCRIPTS" \
  -p"$port" -iL "$IPFILE" >> "$OUTDIR/03_detail_all.txt"

  rm -f "$IPFILE"

done < "$OUTDIR/05_grouped.txt"

echo

########################################
# EXTRACT WEB TARGETS
########################################
awk '$1 ~ /http|https/ {print $3}' "$OUTDIR/05_grouped.txt" | tr ',' '\n' | sort -V -u > "$OUTDIR/06_ip_web.txt"

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

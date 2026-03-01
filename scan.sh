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

  printf "\r[%-${width}s] %d%% (%d/%d)" \
    "$(printf '#%.0s' $(seq 1 $filled))" \
    "$percent" "$current" "$total"
}

########################################
# STAGE 1 — HOST DISCOVERY
########################################
echo "[+] Stage 1: Host discovery..."

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
  nmap -sn -T4 "$net" -oG - >> "$OUTDIR/01_alive.gnmap"
done <<< "$TARGETS"

echo
grep "Up" "$OUTDIR/01_alive.gnmap" | awk '{print $2}' | sort -V > "$OUTDIR/02_target.txt"

########################################
# STAGE 2 — PORT DISCOVERY
########################################
echo "[+] Stage 2: Fast port mapping..."

TOTAL_IP=$(wc -l < "$OUTDIR/02_target.txt")
COUNT=0
> "$OUTDIR/03_ports.txt"

while read ip; do
  COUNT=$((COUNT+1))
  progress $COUNT $TOTAL_IP
  nmap --top-ports 1000 --open -T4 "$ip" -oN - >> "$OUTDIR/03_ports.txt"
done < "$OUTDIR/02_target.txt"

echo

########################################
# PARSE IP + PORT + SERVICE
########################################
awk '
/Nmap scan report for/ {ip=$5}
/^[0-9]+\/tcp[[:space:]]+open/ {
  split($1,p,"/");
  print ip, p[1], $3
}
' "$OUTDIR/03_ports.txt" | sort -V > "$OUTDIR/04_ip_port_service.txt"

########################################
# GROUP BY SERVICE + PORT
########################################
awk '
{
  key=$3"|"$2
  group[key]=group[key]?group[key]","$1:$1
}
END{
  n=asorti(group, idx)
  for(i=1;i<=n;i++){
    split(idx[i],a,"|")
    print a[1], a[2], group[idx[i]]
  }
}
' "$OUTDIR/04_ip_port_service.txt" > "$OUTDIR/05_grouped.txt"

########################################
# STAGE 3 — NSE PER SERVICE
########################################
echo "[+] Stage 3: Smart NSE per SERVICE..."

TOTAL_GROUP=$(wc -l < "$OUTDIR/05_grouped.txt")
COUNT=0
> "$OUTDIR/03_detail_all.txt"

while read service port ips; do
  COUNT=$((COUNT+1))
  progress $COUNT $TOTAL_GROUP

  IPFILE="$OUTDIR/tmp.txt"
  echo "$ips" | tr ',' '\n' > "$IPFILE"

  case "$service" in
    http|http-proxy) SCRIPTS="http-title,http-methods,http-headers,http-server-header" ;;
    https|https-alt) SCRIPTS="http-title,http-methods,http-headers,ssl-cert,ssl-enum-ciphers" ;;
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
    *) SCRIPTS="default and not brute" ;;
  esac

  nmap -Pn -sS -sV -O -T4 --max-retries 1 \
    --script "$SCRIPTS" -p"$port" -iL "$IPFILE" \
    >> "$OUTDIR/03_detail_all.txt"

done < "$OUTDIR/05_grouped.txt"

echo

########################################
# EXTRACT WEB TARGETS
########################################
awk '$1 ~ /http|https/ {print $3}' "$OUTDIR/05_grouped.txt" | tr ',' '\n' | sort -u > "$OUTDIR/06_ip_web.txt"

########################################
# HTTPX PROBE
########################################
if command -v httpx >/dev/null 2>&1; then
  echo "[+] Probing web with httpx..."
  cat "$OUTDIR/06_ip_web.txt" | httpx -silent -threads 50 -o "$OUTDIR/07_httpx_alive.txt"
fi

########################################
# STAGE 4 — NUCLEI
########################################
if command -v nuclei >/dev/null 2>&1; then
  echo
  echo "[+] Stage 4: Nuclei scanning..."

  TARGET_WEB="$OUTDIR/02_target.txt"
  NUCLEI_OUT="$OUTDIR/nuclei-result.txt"
  > "$NUCLEI_OUT"
  
  echo "[+] javascript"
  cat "$TARGET_WEB" | nuclei -silent -tags vuln,cve,discovery,vkev,panel,xss,wordpress,exposure,wp-plugin,osint/ >> "$NUCLEI_OUT"
  
fi

echo
echo "[✓] DONE"
echo "[✓] Nmap detail : $OUTDIR/03_detail_all.txt"
echo "[✓] Web targets : $OUTDIR/06_ip_web.txt"
echo "[✓] HTTPX alive : $OUTDIR/07_httpx_alive.txt"
echo "[✓] Nuclei      : $OUTDIR/nuclei-result.txt"

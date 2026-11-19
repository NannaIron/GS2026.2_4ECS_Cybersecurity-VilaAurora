#!/usr/bin/env bash
# Confere a sintaxe dos registros SPF/DKIM/DMARC do arquivo de zona (sem publicar nada).
set -euo pipefail
Z="$(dirname "$0")/dns/vilaaurora.zone"
ok=0; bad=0
check() { if echo "$2" | grep -qE "$3"; then echo "[OK ] $1"; ok=$((ok+1)); else echo "[FALHOU] $1"; bad=$((bad+1)); fi; }
SPF=$(grep -oP '(?<=")v=spf1[^"]*' "$Z" | head -1)
DKIM=$(grep -oP '(?<=")v=DKIM1[^"]*' "$Z" | head -1)
DMARC=$(grep -oP '(?<=")v=DMARC1[^"]*' "$Z" | head -1)
check "SPF presente e termina com -all" "$SPF" 'v=spf1 .*-all$'
check "DKIM com chave pública (p=)" "$DKIM" 'v=DKIM1;.*p='
check "DMARC com política quarantine ou reject" "$DMARC" 'v=DMARC1; *p=(quarantine|reject)'
check "DMARC com relatório agregado (rua)" "$DMARC" 'rua=mailto:'
echo "SPF:   $SPF"; echo "DKIM:  ${DKIM:0:40}..."; echo "DMARC: $DMARC"
echo "$ok OK, $bad falhas"; [ $bad -eq 0 ]

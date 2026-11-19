#!/usr/bin/env bash
# Reteste AUTOMATIZADO com sqlmap contra o painel SEGURO (roda no container operador, via VPN).
# Faz login (senha + TOTP) como auditora, pega o cookie de sessão e ataca o mesmo campo do incidente.
set -uo pipefail
OUT="/resultados/sqlmap-painel-seguro-${1:-com-waf}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
COOKIE=$(python3 - <<'PY'
import sys; sys.argv=["x"]
import importlib.util, re
spec = importlib.util.spec_from_file_location("tp", "/app/testes/cliente_painel.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
s = m.entrar("aud.helena")
print("session=" + s.cookies.get("session"))
PY
)
sqlmap -u "https://10.10.0.1:8443/acessos?busca=entrada" --cookie="$COOKIE" -p busca --dbms=PostgreSQL \
  --batch --level 3 --risk 2 --technique=BEUST --flush-session --output-dir="$OUT" 2>&1 | tee "$OUT/sqlmap.txt" | \
  grep -E "not injectable|do not appear|is vulnerable|injectable|WAF|403|CRITICAL|all tested" | tail -8
echo "saída completa: $OUT/sqlmap.txt"

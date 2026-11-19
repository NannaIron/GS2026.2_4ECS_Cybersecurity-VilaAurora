#!/usr/bin/env bash
# Demonstração "ANTES": sobe o legado (VPN só com senha + painel vulnerável) e reproduz o INC-VA-0712.
# uso: scripts/attack-demo.sh [--sqlmap]
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== 1/5 Subindo componentes LEGADOS (vpn-legada + painel-legado)"
docker compose --profile legado up -d vpn-legada painel-legado
sleep 4
echo "== 2/5 Restaurando agendamento original da bomba (06:30-08:30, 16:00-18:00)"
docker exec va-postgres psql -q -U aurora_owner -d aurora -c \
 "UPDATE agendamento_bomba SET hora_inicio=v.i::time, hora_fim=v.f::time, atualizado_por='reset-demo'
  FROM (VALUES (1,'06:30','08:30'),(2,'16:00','18:00')) v(id,i,f) WHERE agendamento_bomba.id=v.id;"
echo '{"ips": [], "usuarios": [], "peers": []}' | docker exec -i va-siem sh -c 'cat > /soar/bloqueios.json'
docker exec va-siem sh -c 'iptables -F BLOQUEIO_SOAR; rm -f /soar/observacao.json' || true

echo "== 3/5 Phishing simulado: a 'coordenadora' digita a senha na página falsa"
USR=coord.marina
PASS=$(python3 -c "import json;print([u for u in json.load(open('segredos/usuarios.json')) if u['login']=='$USR'][0]['senha'])")
if docker ps --format '{{.Names}}' | grep -q va-mailpit; then
  docker exec va-atacante python3 - <<PY || true
import smtplib
from email.message import EmailMessage
m = EmailMessage()
m["From"] = "Prefeitura de Serra Clara <ti@prefeitura-serraclara.example.com>"
m["To"] = "coord.marina@vilaaurora.example"
m["Subject"] = "URGENTE: atualização obrigatória do acesso ao painel até 18h"
m.set_content("Prezada coordenadora, por determinação do secretário, atualize seu acesso em http://painel-vilaaurora.example.com/atualizar (SIMULAÇÃO DE LABORATÓRIO)")
s = smtplib.SMTP("172.31.0.25", 1025, timeout=5)
s.send_message(m); s.quit()
print("   e-mail de phishing (simulado) entregue no Mailpit: http://127.0.0.1:8025")
PY
fi
echo "   credencial 'capturada': $USR / ******** (vem de segredos/usuarios.json; senha fictícia)"

echo "== 4/5 Atacante (172.31.0.66, 'internet') executa a cadeia do incidente"
if [ "${1:-}" = "--sqlmap" ]; then
  # Para o sqlmap explorar o legado até o fim, o SOAR fica em MODO OBSERVAÇÃO (como era antes do projeto:
  # sem resposta automática). O SIEM continua detectando. Sem --sqlmap, o SOAR bloqueia o atacante em < 1 s.
  echo "   (SOAR em modo observação por 10 min: detecta, mas não bloqueia)"
  echo "{\"expira_em\": $(( $(date +%s) + 600 ))}" | docker exec -i va-siem sh -c 'cat > /soar/observacao.json'
fi
docker exec va-atacante bash /ataque/inc_va_0712.sh "$USR" "$PASS" "${1:-}"
docker exec va-siem rm -f /soar/observacao.json

echo "== 5/5 Aguardando a borda puxar o agendamento adulterado e o SIEM correlacionar (20 s)"
sleep 20
echo "--- Borda (regra local de perfil seguro):"
docker exec va-siem sh -c "grep -h -E 'agendamento_fora_perfil|comando_remoto' /logs/borda.jsonl | tail -3" || true
echo "--- Alertas do SIEM e respostas do SOAR:"
docker exec va-siem cat /logs/central/alertas.jsonl | python3 scripts/ver_alertas.py 10
echo
echo "Próximo: make forensics (coleta de evidências) e make fix-demo (reteste na versão corrigida)."

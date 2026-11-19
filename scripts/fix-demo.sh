#!/usr/bin/env bash
# Demonstração "DEPOIS": mostra que a mesma cadeia de ataque NÃO funciona na arquitetura nova.
#  1) o atacante não alcança nada administrativo (só existe a porta UDP do WireGuard);
#  2) reteste do SQL Injection no painel SEGURO, via VPN + MFA, com e sem WAF (prova da causa raiz);
#  3) sqlmap contra o painel seguro;
#  4) privilégio mínimo do banco e segmentação.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== 0/4 Desligando o LEGADO (VPN só com senha e painel vulnerável)"
docker compose --profile legado stop vpn-legada painel-legado >/dev/null 2>&1 || true
echo "== 1/4 Atacante tenta repetir o ataque contra a arquitetura nova"
docker exec va-atacante sh -c 'curl -s -m 5 -o /dev/null -w "vpn-legada: HTTP %{http_code}\n" http://vpn-legada:8080/vpn/login || echo "vpn-legada: inacessível (desligada)";
  for p in 8443 9000 5432 22; do nc -z -w 2 172.31.0.10 $p && echo "nuvem:$p ABERTA (!)" || echo "nuvem:$p fechada"; done;
  curl -sk -m 5 https://10.10.0.1:8443/login -o /dev/null && echo "painel acessível (!)" || echo "painel 10.10.0.1:8443 inacessível sem chave WireGuard"'
# janela de pentest autorizado: SIEM continua detectando, SOAR não bloqueia o IP do operador por 15 min
echo "{\"ips\": [\"10.10.2.11\"], \"expira_em\": $(( $(date +%s) + 900 ))}" | docker exec -i va-siem sh -c 'cat > /soar/excecoes.json'
echo "== 2/4 Reteste com WAF LIGADO (defesa em profundidade)"
docker exec va-operador python3 /app/testes/teste_painel.py
echo "== 2b/4 Reteste com WAF DESLIGADO (prova de que a correção é na CAUSA RAIZ: parametrização + validação)"
WAF_ATIVO=0 docker compose up -d --no-deps painel-seguro >/dev/null 2>&1; sleep 4
docker exec va-operador python3 /app/testes/teste_painel.py --sem-waf
echo "== 3/4 sqlmap contra o painel seguro (WAF desligado, pior caso)"
sleep 31   # garante um código TOTP novo para o login do sqlmap
docker exec va-operador bash /app/testes/sqlmap_painel_seguro.sh sem-waf
docker compose up -d --no-deps painel-seguro >/dev/null 2>&1   # WAF de volta
echo "== 4/4 Segmentação, VPN e privilégio mínimo do banco"
bash testes/teste_segmentacao.sh | grep -E 'PASSOU|FALHOU|painel_app>'
docker exec va-siem rm -f /soar/excecoes.json
echo; echo "Resultados detalhados em resultados/ (teste-painel-*.json, sqlmap-*, teste-segmentacao-*)"

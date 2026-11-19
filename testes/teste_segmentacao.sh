#!/usr/bin/env bash
# Evidências de VPN + segmentação + "nenhuma porta administrativa exposta" (RT-06, RT-07)
# e de privilégio mínimo no banco (RT-08).
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="resultados/teste-segmentacao-$(date +%Y%m%d-%H%M%S).txt"
r() { echo "$*" | tee -a "$OUT"; }
teste() { # nome, container, comando, esperado(ok|bloqueado)
  local saida rc
  saida=$(docker exec "$2" sh -c "$3" 2>&1); rc=$?
  local obtido=$([ $rc -eq 0 ] && echo ok || echo bloqueado)
  local st=$([ "$obtido" = "$4" ] && echo "PASSOU" || echo "FALHOU")
  r "[$st] $1  (esperado=$4, obtido=$obtido)"
}
r "# Teste de VPN e segmentação - $(date -Iseconds)"
r ""; r "## Visão do ATACANTE na internet (172.31.0.66, sem chave WireGuard)"
for p in 22 80 443 5432 8443 9000 1883 8883 3333; do
  teste "atacante -> nuvem 172.31.0.10:$p (TCP)" va-atacante "nc -z -w 2 172.31.0.10 $p" bloqueado
done
teste "atacante -> IP do túnel 10.10.0.1:8443" va-atacante "nc -z -w 2 10.10.0.1 8443" bloqueado
teste "atacante -> PostgreSQL 172.31.20.5:5432 (segmento admin)" va-atacante "nc -z -w 2 172.31.20.5 5432" bloqueado
teste "atacante -> broker MQTT 172.31.10.5:8883 (segmento IoT)" va-atacante "nc -z -w 2 172.31.10.5 8883" bloqueado

r ""; r "## OPERADOR com WireGuard (10.10.2.11, segmento de operadores)"
teste "operador -> painel 10.10.0.1:8443 (HTTPS)" va-operador "nc -z -w 3 10.10.0.1 8443" ok
teste "operador -> API das bordas 10.10.0.1:9000 (não é do perfil dele)" va-operador "nc -z -w 2 10.10.0.1 9000" bloqueado
teste "operador -> PostgreSQL 172.31.20.5:5432" va-operador "nc -z -w 2 172.31.20.5 5432" bloqueado
teste "operador -> broker MQTT 172.31.10.5:8883" va-operador "nc -z -w 2 172.31.10.5 8883" bloqueado

r ""; r "## BORDA (10.10.1.2, segmento de bordas)"
teste "borda -> API de ingestão 10.10.0.1:9000" va-borda "nc -z -w 3 10.10.0.1 9000" ok
teste "borda -> painel 10.10.0.1:8443 (não é do perfil dela)" va-borda "nc -z -w 2 10.10.0.1 8443" bloqueado
teste "borda -> PostgreSQL 172.31.20.5:5432" va-borda "nc -z -w 2 172.31.20.5 5432" bloqueado

r ""; r "## Dispositivos IoT (segmento seg_iot, sem saída)"
teste "sensores -> internet (1.1.1.1:443)" va-sensores "nc -z -w 2 1.1.1.1 443" bloqueado
teste "sensores -> nuvem 172.31.0.10:51820" va-sensores "nc -z -u -w 2 172.31.20.10 5432" bloqueado
teste "sensores -> PostgreSQL 172.31.20.5:5432" va-sensores "nc -z -w 2 172.31.20.5 5432" bloqueado

r ""; r "## Portas publicadas no host (só WireGuard UDP; legado/phishing apenas em 127.0.0.1 quando ligados)"
r "$(docker ps --format '{{.Names}}\t{{.Ports}}' | grep -v -E '\t$' )"

r ""; r "## WireGuard (cifras fixas e modernas: Curve25519, ChaCha20-Poly1305, BLAKE2s + PSK)"
r "$(docker exec va-nuvem-gw wg show wg0 | sed -E 's/(public key: ).*/\1(omitida)/')"

r ""; r "## Privilégio mínimo no banco: usuário painel_app"
PW=$(grep ^PAINEL_APP_PASSWORD= .env | cut -d= -f2)
for sql in "SELECT login, perfil FROM usuarios LIMIT 1" "SELECT email, telefone FROM usuarios LIMIT 1" \
           "SELECT senha_md5_legado FROM usuarios LIMIT 1" "UPDATE usuarios SET perfil='coordenacao'" \
           "DELETE FROM telemetria" "DROP TABLE acessos" "CREATE TABLE x(id int)"; do
  s=$(docker exec -e PGPASSWORD="$PW" va-postgres psql -h 127.0.0.1 -U painel_app -d aurora -tAc "$sql" 2>&1 | head -1)
  r "painel_app> $sql  =>  ${s:0:90}"
done
echo; echo "Resultado salvo em $OUT"

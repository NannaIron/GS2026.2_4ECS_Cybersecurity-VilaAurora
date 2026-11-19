#!/usr/bin/env bash
# Coleta forense do INC-VA-0712 (RT-14): copia evidências, calcula SHA-256 NA HORA da
# coleta e registra a cadeia de custódia (quem, quando, onde, como).
# uso: forense/coletar.sh "Nome do(a) perito(a)"
set -euo pipefail
cd "$(dirname "$0")/.."
PERITO="${1:-$(whoami)}"
CASO="INC-VA-0712"
DIR="evidencias/${CASO}-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR/itens"
CUST="$DIR/cadeia_de_custodia.csv"
echo "id;item;arquivo;sha256;bytes;origem;metodo;coletado_por;data_hora_utc;estacao;observacao" > "$CUST"
N=0
registrar() { # arquivo origem metodo obs
  N=$((N+1)); local id=$(printf "EV-%03d" $N) f="$1"
  local h=$(sha256sum "$f" | cut -d' ' -f1) b=$(stat -c %s "$f")
  echo "$id;$(basename "$f");${f#$DIR/};$h;$b;$2;$3;$PERITO;$(date -u +%Y-%m-%dT%H:%M:%SZ);$(hostname);$4" >> "$CUST"
  printf "  %s %s  sha256=%s…\n" "$id" "${f#$DIR/}" "${h:0:16}"
}
echo "== Coleta $CASO por '$PERITO' em $DIR"

# 0) relógios (NTP) - base para correlacionar a linha do tempo
R="$DIR/itens/00_relogios_ntp.txt"
{ echo "host: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"; (timedatectl show 2>/dev/null | grep -E 'NTP|Synchronized|Timezone') || echo "timedatectl indisponível";
  for c in va-borda va-siem va-postgres va-mosquitto va-sensores; do echo "$c: $(docker exec $c date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; done
  echo "Obs.: containers usam o relógio do kernel do host; o host deve estar com NTP ativo (systemd-timesyncd/chrony)."; } > "$R"
registrar "$R" "host + containers" "date -u / timedatectl" "sincronismo de relógio"

# 1) logs centralizados (aplicações, VPN, SIEM, SOAR)
docker cp -q va-siem:/logs "$DIR/itens/logs"
for f in "$DIR"/itens/logs/*.jsonl "$DIR"/itens/logs/central/*.jsonl; do
  [ -f "$f" ] && registrar "$f" "va-siem:/logs/$(basename "$f")" "docker cp (somente leitura da origem)" "log JSON"
done
# 2) broker MQTT
docker cp -q va-mosquitto:/mosquitto/log/mosquitto.log "$DIR/itens/mosquitto.log"
registrar "$DIR/itens/mosquitto.log" "va-mosquitto:/mosquitto/log/mosquitto.log" "docker cp" "log do broker (mTLS)"
# 3) banco de dados
docker cp -q va-postgres:/pglogs/postgresql.log "$DIR/itens/postgresql.log"
registrar "$DIR/itens/postgresql.log" "va-postgres:/pglogs/postgresql.log" "docker cp" "log de consultas (log_statement)"
docker exec va-postgres pg_dump -U aurora_owner -d aurora --data-only -t agendamento_bomba -t comandos_borda -t alertas -t auditoria \
  > "$DIR/itens/db_tabelas_relevantes.sql"
registrar "$DIR/itens/db_tabelas_relevantes.sql" "va-postgres:aurora" "pg_dump --data-only" "agendamento, comandos, alertas, auditoria"
docker exec va-postgres psql -U aurora_owner -d aurora -c "SELECT perfil, count(*) FROM usuarios GROUP BY 1" \
  -c "SELECT * FROM agendamento_bomba" > "$DIR/itens/db_estado.txt"
registrar "$DIR/itens/db_estado.txt" "va-postgres:aurora" "psql (consulta de estado)" "minimização: só contagem de usuários"
# 4) buffer da borda (SQLite) - cópia consistente
docker exec va-borda sqlite3 /data/borda.db ".backup /tmp/borda_copia.db"
docker cp -q va-borda:/tmp/borda_copia.db "$DIR/itens/borda.db"; docker exec va-borda rm -f /tmp/borda_copia.db
registrar "$DIR/itens/borda.db" "va-borda:/data/borda.db" "sqlite3 .backup + docker cp" "buffer store-and-forward"
# 5) estado de rede / VPN / firewall
docker exec va-nuvem-gw sh -c 'wg show wg0 dump | cut -f1,3,4,5,6,7; echo; iptables -S; echo; iptables -L BLOQUEIO_SOAR -nv' > "$DIR/itens/vpn_firewall.txt"
registrar "$DIR/itens/vpn_firewall.txt" "va-nuvem-gw" "wg show dump (sem chaves privadas) + iptables" "estado volátil"
docker cp -q va-siem:/soar/bloqueios.json "$DIR/itens/soar_bloqueios.json" 2>/dev/null && \
  registrar "$DIR/itens/soar_bloqueios.json" "va-siem:/soar/bloqueios.json" "docker cp" "bloqueios aplicados pelo SOAR"
# 6) logs dos containers e metadados
docker compose --profile legado logs --timestamps --no-color > "$DIR/itens/docker_compose_logs.txt" 2>&1 || true
registrar "$DIR/itens/docker_compose_logs.txt" "docker engine" "docker compose logs --timestamps" "stdout/stderr dos serviços"
docker inspect $(docker ps -q --filter name=va-) > "$DIR/itens/docker_inspect.json"
registrar "$DIR/itens/docker_inspect.json" "docker engine" "docker inspect" "metadados (IPs, imagens, início)"
# 7) referência do red team (NÃO é evidência da vítima; usada só para validar a reconstrução)
ULT=$(ls -d resultados/ataque-* 2>/dev/null | tail -1 || true)
if [ -n "$ULT" ] && [ -f "$ULT/diario_atacante.txt" ]; then
  mkdir -p "$DIR/referencia_red_team"; cp "$ULT/diario_atacante.txt" "$DIR/referencia_red_team/"
  registrar "$DIR/referencia_red_team/diario_atacante.txt" "$ULT" "cp" "REFERÊNCIA do exercício, não evidência"
fi

# 8) manifesto, linha do tempo e proteção contra escrita
python3 forense/linha_do_tempo.py "$DIR"
( cd "$DIR" && find itens referencia_red_team -type f 2>/dev/null | sort | xargs sha256sum > SHA256SUMS )
sha256sum "$DIR/SHA256SUMS" "$DIR/cadeia_de_custodia.csv" | tee "$DIR/HASH_DO_MANIFESTO.txt"
chmod -R a-w "$DIR/itens"
echo
echo "Coleta concluída: $DIR"
echo "  cadeia de custódia: $CUST ($N itens)"
echo "  linha do tempo:     $DIR/linha_do_tempo.md (+ .csv)"
echo "  verificar depois:   forense/verificar.sh $DIR"

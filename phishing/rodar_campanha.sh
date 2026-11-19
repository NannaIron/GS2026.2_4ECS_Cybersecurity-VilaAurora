#!/usr/bin/env bash
# Sobe Gophish + Mailpit (se preciso), lê a API key do Gophish e roda a campanha simulada.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile phishing up -d mailpit gophish
for i in $(seq 1 30); do docker logs va-gophish 2>&1 | grep -q "Starting admin server" && break; sleep 1; done
sleep 2
docker cp va-gophish:/opt/gophish/gophish.db /tmp/gophish.db
KEY=$(docker run --rm -v /tmp/gophish.db:/g.db:ro vila-aurora/py:1.0 python3 -c \
  "import sqlite3;print(sqlite3.connect('/g.db').execute('select api_key from users limit 1').fetchone()[0])")
rm -f /tmp/gophish.db
echo "Admin do Gophish: https://127.0.0.1:3333  (usuário admin; senha inicial: docker logs va-gophish | grep password)"
echo "Caixa de e-mails do laboratório (Mailpit): http://127.0.0.1:8025"
docker run --rm --network vila-aurora_seg_phishing -e GOPHISH_API_KEY="$KEY" -v "$PWD/resultados:/resultados" \
  vila-aurora/py:1.0 python3 /app/phishing/campanha.py

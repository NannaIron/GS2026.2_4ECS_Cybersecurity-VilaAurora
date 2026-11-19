#!/usr/bin/env bash
# Prepara o laboratório: verifica pré-requisitos, constrói a imagem e gera TODOS os
# segredos (CA/certificados, chaves WireGuard, senhas, contas fictícias com TOTP).
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== Verificando pré-requisitos"
command -v docker >/dev/null || { echo "Instale o Docker (Arch: sudo pacman -S docker docker-compose docker-buildx)"; exit 1; }
docker compose version >/dev/null || { echo "Falta o plugin docker compose"; exit 1; }
if ! (lsmod 2>/dev/null | grep -q '^wireguard' || [ -d /sys/module/wireguard ]); then
  echo "Carregando módulo wireguard do kernel (precisa de sudo)..."
  sudo modprobe wireguard || { echo "Não consegui carregar o módulo wireguard"; exit 1; }
fi
[ -n "${HOST_UID:-}" ] || export HOST_UID=$(id -u) HOST_GID=$(id -g)
mkdir -p segredos pki resultados evidencias
echo "== Construindo imagem vila-aurora/py:1.0"
docker build -t vila-aurora/py:1.0 -f docker/py/Dockerfile .
RUN="docker run --rm -v $PWD:/repo -e HOST_UID=$HOST_UID -e HOST_GID=$HOST_GID vila-aurora/py:1.0"
echo "== Gerando segredos (.env, usuários fictícios, WireGuard)"
$RUN python3 /repo/scripts/gerar_segredos.py
echo "== Gerando PKI (CA própria + 1 certificado por dispositivo)"
$RUN python3 /repo/scripts/pki.py init
echo
echo "Pronto. Contas fictícias do painel (senha + semente TOTP) em segredos/usuarios.json"
echo "Próximo passo: make up"

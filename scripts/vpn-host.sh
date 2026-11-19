#!/usr/bin/env bash
# Conecta ESTE computador (host) à VPN WireGuard da Vila Aurora como operador(a),
# para abrir o painel seguro no navegador: https://10.10.0.1:8443
# uso: scripts/vpn-host.sh up|down
set -euo pipefail
cd "$(dirname "$0")/.."
CONF=segredos/wg/operador-host.conf
case "${1:-up}" in
  up)   sudo ip link add wg-aurora type wireguard
        grep -v '^Address' "$CONF" | sudo wg setconf wg-aurora /dev/stdin
        sudo ip addr add 10.10.2.10/32 dev wg-aurora
        sudo ip link set wg-aurora up
        sudo ip route add 10.10.0.1/32 dev wg-aurora
        echo "VPN ativa. Abra https://10.10.0.1:8443 (importe pki/painel/ca.crt como CA confiável no navegador"
        echo "ou aceite o aviso do certificado). Contas fictícias e sementes TOTP: segredos/usuarios.json"
        echo "Dica: python3 scripts/totp.py <login> mostra o código atual (só no laboratório).";;
  down) sudo ip link del wg-aurora && echo "VPN desligada.";;
esac

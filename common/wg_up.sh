#!/bin/sh
# Sobe uma interface WireGuard (kernel) sem wg-quick.
# uso: wg_up.sh <arquivo.conf> <endereco/cidr> [rota...]
# Requer cap NET_ADMIN no container e o módulo wireguard no kernel do host.
set -e
CONF="$1"; ADDR="$2"; shift 2
ip link del wg0 2>/dev/null || true
ip link add wg0 type wireguard
grep -v -E '^(Address|DNS|MTU)' "$CONF" > /tmp/wg0.conf
wg setconf wg0 /tmp/wg0.conf
rm -f /tmp/wg0.conf
ip addr add "$ADDR" dev wg0
ip link set mtu 1380 up dev wg0
for r in "$@"; do ip route replace "$r" dev wg0; done
echo "[wg] wg0 ativo em $ADDR"

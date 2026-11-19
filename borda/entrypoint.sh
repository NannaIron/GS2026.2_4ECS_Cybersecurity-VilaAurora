#!/bin/sh
# Nó de borda: túnel WireGuard até a nuvem + serviço de regras locais.
/app/common/wg_up.sh /segredos/wg/borda-vila.conf 10.10.1.2/32 10.10.0.1/32
# a borda não aceita conexões entrantes pelo túnel (só ela inicia a sincronização)
iptables -A INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0 -j DROP
exec python3 /app/borda/regras.py

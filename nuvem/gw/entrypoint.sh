#!/bin/sh
# Gateway da NUVEM: servidor WireGuard + firewall de segmentação (RT-06, RT-07).
# Os serviços da nuvem (API, painel, SIEM) compartilham este namespace de rede e só
# escutam no IP do túnel 10.10.0.1 -> nenhuma porta administrativa fica exposta.
set -e
/app/common/wg_up.sh /segredos/wg/nuvem.conf 10.10.0.1/16

iptables -F; iptables -X 2>/dev/null || true
iptables -N BLOQUEIO_SOAR                     # IPs bloqueados automaticamente pelo SOAR
iptables -P INPUT DROP
iptables -P FORWARD DROP                      # o gateway NÃO roteia entre segmentos
iptables -A INPUT -j BLOQUEIO_SOAR
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp --dport 51820 -j ACCEPT                       # só o WireGuard na "internet"
iptables -A INPUT -i wg0 -s 10.10.1.0/24 -p tcp --dport 9000 -j ACCEPT # bordas -> API de ingestão
iptables -A INPUT -i wg0 -s 10.10.2.0/24 -p tcp --dport 8443 -j ACCEPT # operadores -> painel (HTTPS+MFA)
iptables -A INPUT -i wg0 -p icmp -j ACCEPT
echo "[nuvem-gw] firewall aplicado:"; iptables -S
touch /tmp/pronto
exec sleep infinity

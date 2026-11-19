#!/usr/bin/env python3
"""Teste unitário das regras de detecção (RT-13) com eventos SINTÉTICOS, incluindo o
login VPN às 02:14 do cenário original. O SOAR é substituído por um registrador
(nenhuma ação real é executada).  uso: docker run --rm vila-aurora/py:1.0 python3 /app/siem/testar_regras.py
"""
import os
import sys

os.environ.setdefault("LOG_DIR", "/tmp/teste-logs")
sys.path.insert(0, "/app")
from siem import siem  # noqa: E402

disparos = []
siem.alerta = lambda regra, sev, resumo, ev, chave, respostas: disparos.append((regra, resumo, len(respostas)))

CASOS = [
    ("02:14 de IP externo, VPN legada (cenário original)", {"ts": "2026-10-28T05:14:00Z", "servico": "vpn-legada",
     "evento": "vpn_login", "tipo_vpn": "legada_senha", "usuario": "coord.marina", "ip_origem": "203.0.113.66",
     "sucesso": True}, "R1_vpn_login_anomalo"),
    ("02:14 de IP CONHECIDO (fora do horário)", {"ts": "2026-10-28T05:14:00Z", "servico": "vpn-wireguard",
     "evento": "vpn_login", "tipo_vpn": "wireguard", "peer": "operador-lab", "ip_origem": "172.31.0.20",
     "sucesso": True}, "R1_vpn_login_anomalo"),
    ("14:00 de IP conhecido (normal)", {"ts": "2026-10-28T17:00:00Z", "servico": "vpn-wireguard", "evento": "vpn_login",
     "tipo_vpn": "wireguard", "peer": "operador-lab", "ip_origem": "172.31.0.20", "sucesso": True}, None),
    ("UNION SELECT no painel legado", {"ts": "2026-10-28T05:16:00Z", "servico": "painel-legado",
     "evento": "legado_consulta", "busca": "x' UNION SELECT login,email FROM usuarios --", "ip_origem": "203.0.113.66"},
     "R2_sql_injection"),
    ("SQLi URL-encoded no painel seguro", {"ts": "2026-10-28T05:16:00Z", "servico": "painel-seguro",
     "evento": "http_request", "query": "busca=%27%20OR%20%271%27%3D%271", "ip_origem": "10.10.2.50"}, "R2_sql_injection"),
    ("busca normal", {"ts": "2026-10-28T17:00:00Z", "servico": "painel-seguro", "evento": "http_request",
     "query": "busca=entrada&espaco=ubs", "ip_origem": "10.10.2.11"}, None),
    ("cliente MQTT sem certificado", {"ts": "2026-10-28T05:20:00Z", "servico": "mosquitto", "evento": "mqtt_log",
     "mensagem": "OpenSSL Error[0]: error:0A0000C7:SSL routines::peer did not return a certificate"},
     "R3_dispositivo_sem_certificado_valido"),
    ("agendamento 00:00-23:59 rejeitado pela borda", {"ts": "2026-10-28T05:18:00Z", "servico": "borda",
     "evento": "agendamento_fora_perfil", "alvo": "escola-bomba-01", "motivo": "fora do perfil"},
     "R4_atuador_fora_do_perfil"),
    ("bomba ligada às 03:00", {"ts": "2026-10-28T06:00:00Z", "servico": "borda", "evento": "atuador_comando",
     "acao": "ligar", "alvo": "escola-bomba-01"}, "R4_atuador_fora_do_perfil"),
    ("bomba ligada às 16:30 (agenda normal)", {"ts": "2026-10-28T19:30:00Z", "servico": "borda",
     "evento": "atuador_comando", "acao": "ligar", "alvo": "escola-bomba-01"}, None),
    ("sensor enviando lixo", {"ts": "2026-10-28T05:30:00Z", "servico": "borda", "evento": "dispositivo_suspeito",
     "dispositivo": "horta-umidade-01"}, "R5_dispositivo_suspeito"),
]
falhas = 0
for nome, ev, esperado in CASOS:
    disparos.clear()
    siem.avaliar(ev)
    obtido = disparos[0][0] if disparos else None
    ok = obtido == esperado
    falhas += not ok
    print(f"[{'OK ' if ok else 'FALHOU'}] {nome:50s} esperado={esperado} obtido={obtido}"
          + (f" respostas_soar={disparos[0][2]}" if disparos else ""))
print(f"\n{len(CASOS) - falhas}/{len(CASOS)} casos corretos")
sys.exit(1 if falhas else 0)

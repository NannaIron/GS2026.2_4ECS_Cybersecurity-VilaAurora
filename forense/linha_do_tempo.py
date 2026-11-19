#!/usr/bin/env python3
"""Linha do tempo consolidada do INC-VA-0712 a partir das evidências coletadas.
Normaliza todas as fontes para UTC, ordena e mapeia cada evento no MITRE ATT&CK
(Enterprise e ICS). Gera linha_do_tempo.csv e linha_do_tempo.md.
uso: python3 forense/linha_do_tempo.py evidencias/INC-VA-0712-AAAAMMDD-HHMMSS
"""
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta

DIR = sys.argv[1]
IT = os.path.join(DIR, "itens")
BRT = timezone(timedelta(hours=-3))
SQLI = re.compile(r"union\s+select|;\s*update|'\s*(or|and)\s|--|pg_sleep", re.I)

# evento -> (tática, técnica ATT&CK, descrição)
ATTACK = {
    "phishing": ("TA0001 Initial Access", "T1566.002 Spearphishing Link (+T1598 voz clonada)"),
    "vpn_login_externo": ("TA0001 Initial Access", "T1078 Valid Accounts / T1133 External Remote Services"),
    "sqli_teste": ("TA0001 Initial Access", "T1190 Exploit Public-Facing Application"),
    "sqli_extracao": ("TA0009 Collection / TA0010 Exfiltration", "T1213 Data from Information Repositories / T1041"),
    "sqli_alteracao": ("ICS TA0106 Impair Process Control", "T0831 Manipulation of Control / T1565.001 Stored Data Manipulation"),
    "borda_rejeita": ("Defesa", "D3FEND: validação de comando na borda (perfil seguro)"),
    "deteccao": ("Defesa", "Detecção SIEM"),
    "resposta": ("Defesa", "Resposta SOAR (contenção)"),
    "aprovacao": ("Defesa", "Decisão humana (alto impacto)"),
    "disponibilidade": ("ICS TA0105 Impact", "T0826 Loss of Availability (link WAN) - mitigado por operação local"),
    "mtls": ("Defesa", "mTLS recusou dispositivo sem certificado válido"),
}
linhas = []


def add(ts, fonte, evento, desc, cat=None, ip="", usuario=""):
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    tat, tec = ATTACK.get(cat, ("", "")) if cat else ("", "")
    linhas.append({"ts_utc": d.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                   "ts_brt": d.astimezone(BRT).strftime("%d/%m/%Y %H:%M:%S"), "fonte": fonte, "evento": evento,
                   "descricao": desc[:220], "ip_origem": ip or "", "usuario": usuario or "", "tatica": tat,
                   "tecnica_attack": tec})


# 1) logs de aplicação (JSON)
for f in glob.glob(f"{IT}/logs/*.jsonl"):
    for l in open(f, errors="replace"):
        try:
            e = json.loads(l)
        except json.JSONDecodeError:
            continue
        ev, s = e.get("evento", ""), e.get("servico", os.path.basename(f))
        ip, u = e.get("ip_origem"), e.get("usuario")
        if ev == "vpn_login":
            ext = ip not in ("172.31.0.20", "172.31.0.2", "172.31.0.1")
            if e.get("tipo_vpn") == "wireguard" and not ext:
                continue  # handshakes rotineiros de pares conhecidos
            add(e["ts"], s, ev, f"Login VPN {e.get('tipo_vpn')} sucesso={e.get('sucesso')} mfa={e.get('mfa')}",
                "vpn_login_externo" if ext else None, ip, u)
        elif ev == "legado_consulta":
            b = e.get("busca", "")
            cat = ("sqli_alteracao" if re.search(r";\s*update", b, re.I) else
                   "sqli_extracao" if re.search(r"union", b, re.I) else "sqli_teste" if SQLI.search(b) or "'" in b else None)
            if cat:
                add(e["ts"], s, ev, f"Busca no histórico de acessos: {b}", cat, ip, u)
        elif ev in ("agendamento_fora_perfil", "comando_remoto_recusado", "atuador_comando_fora_horario"):
            add(e["ts"], s, ev, e.get("mensagem") or e.get("motivo", ""), "borda_rejeita")
        elif ev == "comando_remoto_executado":
            add(e["ts"], s, ev, f"Borda executou {e.get('acao')} (risco {e.get('risco')}, aprovado por {e.get('aprovado_por')})", "resposta")
        elif ev == "siem_alerta":
            add(e["ts"], s, ev, f"{e.get('regra')}: {e.get('resumo')} (MTTD {e.get('mttd_s')}s)", "deteccao")
        elif ev == "soar_acao":
            add(e["ts"], s, ev, f"SOAR {e.get('acao')} ip={e.get('ip', '')} usuario={e.get('usuario', '')} "
                                f"disp={e.get('dispositivo', '')}", "resposta", e.get("ip", ""))
        elif ev == "soar_pedido_aprovacao_humana":
            add(e["ts"], s, ev, f"Pedido de aprovação humana: {e.get('acao')} (comando {e.get('comando')})", "aprovacao")
        elif ev == "aprovacao_humana":
            add(e["ts"], s, ev, f"{e.get('usuario')} {e.get('decisao')} comando {e.get('comando')} ({e.get('acao')})", "aprovacao", "", e.get("usuario"))
        elif ev in ("vpn_legada_ip_bloqueado", "vpn_legada_sessao_encerrada", "waf_bloqueio"):
            add(e["ts"], s, ev, f"Acesso negado ({ev})", "resposta", ip, u)
        elif ev in ("wan_link_caiu", "wan_link_voltou", "reconciliacao"):
            add(e["ts"], s, ev, json.dumps({k: v for k, v in e.items() if k in ("offline_s", "pendentes", "faltantes", "mensagem")},
                                           ensure_ascii=False), "disponibilidade")
        elif ev == "alarme_local":
            add(e["ts"], s, ev, f"ALARME LOCAL {e.get('tipo')}: {e.get('mensagem')} (link WAN={e.get('link_wan')})", "disponibilidade")
        elif ev in ("dispositivo_suspeito", "rbac_negado", "mfa_falha", "login_bloqueado"):
            add(e["ts"], s, ev, json.dumps({k: v for k, v in e.items() if k not in ("ts", "servico", "host", "nivel", "evento")},
                                           ensure_ascii=False), "deteccao", ip, u)

# 2) PostgreSQL (consultas do usuário com privilégios do legado)
pg = os.path.join(IT, "postgresql.log")
if os.path.exists(pg):
    for l in open(pg, errors="replace"):
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) UTC \[\d+\] (\S*)@(\S*) (\S*) (\w+):\s+(.*)$", l)
        if m and m.group(2) == "aurora_owner" and SQLI.search(m.group(6)):
            cat = "sqli_alteracao" if re.search(r"update\s+agendamento", m.group(6), re.I) else "sqli_extracao" \
                if "union" in m.group(6).lower() else "sqli_teste"
            add(m.group(1).replace(" ", "T") + "Z", "postgres", "db_" + m.group(5).lower(), m.group(6), cat, m.group(4))

# 3) Mosquitto (falhas de mTLS)
mq = os.path.join(IT, "mosquitto.log")
if os.path.exists(mq):
    for l in open(mq, errors="replace"):
        m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)([+-]\d\d)(\d\d): (.*(?:did not return a certificate|verify failed|revoked|unknown ca).*)$", l)
        if m:
            add(f"{m.group(1)}{m.group(2)}:{m.group(3)}", "mosquitto", "mtls_recusado", m.group(4), "mtls")

# 4) referência do red team (phishing não deixa rastro na infraestrutura da vítima no lab)
for f in glob.glob(f"{DIR}/referencia_red_team/diario_atacante.txt"):
    for l in open(f):
        if "Phishing" in l:
            add(l.split(" | ")[0].strip(), "red_team (referência)", "phishing", l.split(" | ", 1)[1].strip(), "phishing")

linhas.sort(key=lambda x: x["ts_utc"])
with open(f"{DIR}/linha_do_tempo.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(linhas[0]) if linhas else ["ts_utc"], delimiter=";")
    w.writeheader()
    w.writerows(linhas)
with open(f"{DIR}/linha_do_tempo.md", "w") as f:
    f.write("# Linha do tempo consolidada - INC-VA-0712 (reprodução em laboratório)\n\n")
    f.write("Horários normalizados em UTC (coluna BRT = America/Sao_Paulo, UTC-3).\n\n")
    f.write("| # | UTC | BRT | Fonte | Evento | IP | Usuário | ATT&CK | Descrição |\n|---|---|---|---|---|---|---|---|---|\n")
    for i, x in enumerate(linhas, 1):
        d = x["descricao"].replace("|", "\\|")
        f.write(f"| {i} | {x['ts_utc']} | {x['ts_brt']} | {x['fonte']} | {x['evento']} | {x['ip_origem']} | "
                f"{x['usuario']} | {x['tecnica_attack']} | {d} |\n")
print(f"linha do tempo: {len(linhas)} eventos -> {DIR}/linha_do_tempo.md")

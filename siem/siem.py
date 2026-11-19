#!/usr/bin/env python3
"""SIEM leve da Vila Aurora (RT-12, RT-13) + disparo do SOAR (RT-15).

Coleta centralizada: lê (tail) todas as fontes de log, normaliza para JSON com
horário UTC e grava em /logs/central/eventos.jsonl. Fontes:
  - aplicações (borda, sensores, API, painéis, VPN legada): /logs/*.jsonl
  - broker MQTT (Mosquitto): /mosquitto-log/mosquitto.log
  - banco PostgreSQL (log_statement=all): /pglogs/*.log
  - VPN WireGuard: monitor de handshakes (wg show dump) -> /logs/vpn-wireguard.jsonl
  - sistema operacional do gateway: iptables (contadores de bloqueio) e uptime
Regras (mínimo exigido + extra):
  R1 login VPN anômalo        R2 padrão de SQL Injection
  R3 dispositivo sem certificado válido     R4 comando de atuador fora do horário/perfil
  R5 (extra) dispositivo com comportamento suspeito -> isolamento
"""
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

import psycopg2

from common.aurora_log import log, agora_utc
from soar import soar

LOGS = "/logs"
CENTRAL = "/logs/central"
FONTES_EXTRA = {"mosquitto": "/mosquitto-log/mosquitto.log"}
PG_DIR = "/pglogs"
IGNORAR = {"siem.jsonl", "soar.jsonl"}
VPN_IPS_CONHECIDOS = set(os.environ.get("VPN_IPS_CONHECIDOS", "172.31.0.20,172.31.0.2,172.31.0.1").split(","))
HORARIO_VPN = tuple(int(x) for x in os.environ.get("HORARIO_VPN", "6-22").split("-"))
DEDUP_S = 120
os.makedirs(CENTRAL, exist_ok=True)

SQLI = re.compile(r"('|%27)\s*(or|and)\s|union(\s|\+|%20)+(all(\s|\+)+)?select|;\s*(update|delete|insert|drop|alter)\b|"
                  r"--|/\*|pg_sleep|information_schema|\bselect\b.+\bfrom\b.+usuarios", re.I)
MOSQ_TLS = re.compile(r"(certificate revoked|peer did not return a certificate|certificate verify failed|"
                      r"unknown ca|bad certificate|certificate expired|no certificate returned)", re.I)
MOSQ_CLIENTE = re.compile(r"Client connection from ([0-9.]+) failed|from ([0-9.]+) failed")

OFFSETS = f"{CENTRAL}/offsets.json"
try:
    offsets = json.load(open(OFFSETS))   # retoma de onde parou após reinício (sem realertar)
except Exception:
    offsets = {}
dedup = {}
peers_hs = {}


def ts_local_hora(ts):
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return d.astimezone().hour
    except Exception:
        return datetime.now().hour


def seg_desde(ts):
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return round((datetime.now(timezone.utc) - d).total_seconds(), 3)
    except Exception:
        return None


def gravar_central(ev):
    with open(f"{CENTRAL}/eventos.jsonl", "a") as f:
        f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")


def ler_novas(caminho):
    try:
        tam = os.path.getsize(caminho)
    except OSError:
        return []
    pos = offsets.get(caminho, 0)
    if tam < pos:
        pos = 0
    if tam == pos:
        return []
    with open(caminho, "r", errors="replace") as f:
        f.seek(pos)
        dados = f.read()
    ult = dados.rfind("\n")
    if ult < 0:
        return []
    offsets[caminho] = pos + ult + 1
    return dados[:ult].splitlines()


def norm_mosquitto(l):
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}): (.*)$", l)
    if m:
        ts = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S%z").astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return {"ts": ts, "servico": "mosquitto", "evento": "mqtt_log", "mensagem": m.group(2)}
    return {"ts": agora_utc(), "servico": "mosquitto", "evento": "mqtt_log", "mensagem": l}


def norm_pg(l):
    m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) UTC \[(\d+)\] (\S*)@(\S*) (\S*) (\w+):\s+(.*)$", l)
    if not m:
        return None
    ts = m.group(1).replace(" ", "T") + "Z"
    return {"ts": ts, "servico": "postgres", "evento": "db_log", "pid": m.group(2), "db_usuario": m.group(3),
            "banco": m.group(4), "cliente": m.group(5), "nivel_pg": m.group(6), "mensagem": m.group(7)[:1000]}


def coletar():
    evs = []
    for n in sorted(os.listdir(LOGS)):
        if n.endswith(".jsonl") and n not in IGNORAR:
            for l in ler_novas(os.path.join(LOGS, n)):
                try:
                    evs.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
    for l in ler_novas(FONTES_EXTRA["mosquitto"]):
        evs.append(norm_mosquitto(l))
    if os.path.isdir(PG_DIR):
        for n in sorted(os.listdir(PG_DIR)):
            if n.endswith(".log"):
                for l in ler_novas(os.path.join(PG_DIR, n)):
                    e = norm_pg(l)
                    if e:
                        evs.append(e)
    for e in evs:
        e["_coletado_em"] = agora_utc()
        gravar_central(e)
    if evs:
        tmp = OFFSETS + ".tmp"
        json.dump(offsets, open(tmp, "w"))
        os.replace(tmp, OFFSETS)
    return evs


def monitor_wireguard():
    """Gera eventos de login na VPN WireGuard a partir dos handshakes."""
    try:
        peers = json.load(open("/segredos/wg/peers.json"))
        out = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return
    for linha in out.strip().splitlines()[1:]:
        c = linha.split("\t")
        if len(c) < 8:
            continue
        pub, endpoint, hs = c[0], c[2], int(c[4])
        if hs and peers_hs.get(pub) != hs:
            novo = pub not in peers_hs or peers_hs[pub] == 0
            peers_hs[pub] = hs
            ip = endpoint.rsplit(":", 1)[0] if endpoint != "(none)" else None
            reg = {"ts": datetime.fromtimestamp(hs, timezone.utc).isoformat().replace("+00:00", "Z"),
                   "servico": "vpn-wireguard", "nivel": "info", "evento": "vpn_login", "tipo_vpn": "wireguard",
                   "peer": peers.get(pub, {}).get("nome", "desconhecido"), "usuario": peers.get(pub, {}).get("nome"),
                   "ip_origem": ip, "sucesso": True, "mfa": "chave+TOTP no painel", "primeiro_handshake": novo}
            with open(f"{LOGS}/vpn-wireguard.jsonl", "a") as f:
                f.write(json.dumps(reg) + "\n")


def alerta(regra, sev, resumo, ev, chave, respostas):
    k = (regra, chave)
    if time.time() - dedup.get(k, 0) < DEDUP_S:
        return
    dedup[k] = time.time()
    t_det = agora_utc()
    mttd = seg_desde(ev.get("ts", t_det))
    acoes = []
    for fn in respostas:
        try:
            acoes.append(fn())
        except Exception as e:
            acoes.append({"acao": getattr(fn, "__name__", "?"), "ok": False, "erro": str(e)[:200], "ts": agora_utc()})
    mttr = seg_desde(ev.get("ts", t_det))
    resumo_resp = "; ".join(a.get("acao", "?") + ("" if a.get("ok") else " (FALHOU)") for a in acoes) or "notificação"
    retro = mttd is not None and mttd > 600   # evento antigo processado em atraso (backlog)
    reg = {"ts": agora_utc(), "retroativo": retro, "regra": regra, "severidade": sev, "resumo": resumo, "ts_evento": ev.get("ts"),
           "ts_deteccao": t_det, "mttd_s": mttd, "mttr_s": mttr if acoes else None, "fonte": ev.get("servico"),
           "evento": {k2: v for k2, v in ev.items() if not k2.startswith("_")}, "respostas": acoes}
    with open(f"{CENTRAL}/alertas.jsonl", "a") as f:
        f.write(json.dumps(reg, ensure_ascii=False, default=str) + "\n")
    log("siem_alerta", "critical" if sev == "alta" else "warning", regra=regra, resumo=resumo, mttd_s=mttd,
        respostas=resumo_resp)
    try:
        with psycopg2.connect(host="postgres", dbname="aurora", user="siem_app",
                              password=os.environ["SIEM_APP_PASSWORD"], connect_timeout=5) as c, c.cursor() as cur:
            cur.execute("INSERT INTO alertas (regra, severidade, resumo, detalhe, ts_evento, resposta) "
                        "VALUES (%s,%s,%s,%s,%s,%s)", (regra, sev, resumo, json.dumps(reg, default=str),
                                                       ev.get("ts"), resumo_resp))
    except Exception as e:
        log("siem_erro_db", "error", erro=str(e)[:200])


def avaliar(ev):
    s, e = ev.get("servico", ""), ev.get("evento", "")
    ip = ev.get("ip_origem")

    # R1 - login VPN anômalo: IP fora da lista conhecida ou fora do horário (06h-22h)
    if e == "vpn_login" and ev.get("sucesso"):
        h = ts_local_hora(ev["ts"])
        fora_h = not (HORARIO_VPN[0] <= h < HORARIO_VPN[1])
        ip_novo = ip not in VPN_IPS_CONHECIDOS
        if ip_novo or fora_h:
            motivo = ("IP desconhecido " if ip_novo else "") + ("fora do horário" if fora_h else "")
            resp = [lambda: soar.encerrar_sessao_vpn(usuario=ev.get("usuario") if ev.get("tipo_vpn") == "legada_senha" else None,
                                                     peer_nome=ev.get("peer"), motivo=motivo)]
            if ip_novo and ip:
                resp.append(lambda: soar.bloquear_ip(ip, "R1 VPN anômala"))
            alerta("R1_vpn_login_anomalo", "alta", f"Login VPN ({ev.get('tipo_vpn')}) de {ip} usuário "
                   f"{ev.get('usuario')}: {motivo.strip()}", ev, (ip, ev.get("usuario")), resp)
    if e == "vpn_login" and not ev.get("sucesso"):
        pass

    # R2 - SQL Injection (painel legado, WAF do painel seguro, requisições HTTP e log do banco)
    texto = None
    if e == "legado_consulta":
        texto = ev.get("busca", "")
    elif e == "waf_bloqueio":
        texto = ev.get("valor", "")
    elif e == "http_request":
        texto = ev.get("query", "")
    elif s == "postgres" and (("syntax error" in ev.get("mensagem", "")) or
                              (ev.get("db_usuario") == "aurora_owner" and SQLI.search(ev.get("mensagem", "")))):
        texto = ev.get("mensagem", "")
    if texto and SQLI.search(requests_unquote(texto)):
        resp = [lambda: soar.bloquear_ip(ip, "R2 SQL Injection")] if ip else []
        alerta("R2_sql_injection", "alta", f"Padrão de SQL Injection em {s} (origem {ip or ev.get('cliente')})",
               ev, (ip or s,), resp)

    # R3 - dispositivo sem certificado válido (falha de handshake mTLS no broker)
    if s == "mosquitto" and MOSQ_TLS.search(ev.get("mensagem", "")):
        m = MOSQ_CLIENTE.search(ev.get("mensagem", ""))
        alerta("R3_dispositivo_sem_certificado_valido", "media",
               f"Conexão MQTT recusada por certificado ausente/inválido/revogado: {ev.get('mensagem')[:120]}",
               ev, (m.group(1) if m else "tls",), [])

    # R4 - atuador fora do horário ou do perfil
    if e in ("agendamento_fora_perfil", "atuador_comando_fora_horario") or \
            (e == "atuador_comando" and ev.get("acao") == "ligar" and not (6 <= ts_local_hora(ev["ts"]) < 22)):
        alerta("R4_atuador_fora_do_perfil", "alta",
               f"Comando/agendamento de {ev.get('alvo')} fora do perfil: {ev.get('motivo') or ev.get('acao')}",
               ev, (ev.get("alvo"),),
               [lambda: soar.modo_seguro(ev.get("alvo") or "escola-bomba-01", "R4 agendamento/comando fora do perfil"),
                lambda: soar.solicitar_aprovacao("desligar_bomba", ev.get("alvo") or "escola-bomba-01",
                                                 "SOAR sugere desligar a bomba até revisão (R4)")])

    # R5 - dispositivo com comportamento suspeito -> isolar (revoga cert + ACL)
    if e == "dispositivo_suspeito":
        cn = ev.get("dispositivo")
        alerta("R5_dispositivo_suspeito", "alta", f"Dispositivo {cn} com comportamento anômalo (taxa/valores)",
               ev, (cn,), [lambda: soar.isolar_dispositivo(cn, "R5 comportamento suspeito")])


def requests_unquote(s):
    from urllib.parse import unquote_plus
    return unquote_plus(s)


def main():
    log("siem_iniciado", fontes=["/logs/*.jsonl", "mosquitto", "postgres", "wireguard"],
        regras=["R1", "R2", "R3", "R4", "R5"])
    ultimo_wg = 0
    while True:
        if time.time() - ultimo_wg > 3:
            monitor_wireguard()
            ultimo_wg = time.time()
        for ev in coletar():
            try:
                avaliar(ev)
            except Exception as ex:
                log("siem_erro_regra", "error", erro=str(ex)[:300], evento=ev.get("evento"))
        time.sleep(1)


if __name__ == "__main__":
    main()

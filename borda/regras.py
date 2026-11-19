#!/usr/bin/env python3
"""Nó de BORDA autônomo (RT-01, RT-02).

- Assina o broker MQTT local (mTLS, CN=borda-regras).
- Aplica REGRAS LOCAIS que não dependem da nuvem: alarme da câmara fria, alarme
  de alagamento, intertravamento da bomba (nível mínimo) e perfil seguro de horário.
- Store-and-forward: toda leitura vai para um buffer SQLite (outbox) e é enviada à
  nuvem pelo túnel WireGuard quando o link existe; ao voltar, faz RECONCILIAÇÃO
  (pergunta à nuvem quais sequências faltam e reenvia).
- Busca agendamento da bomba e comandos aprovados na nuvem (modelo "pull": a
  nuvem nunca abre conexão para a borda). Comandos de ALTO impacto só são
  executados se vierem com aprovação humana registrada.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

import paho.mqtt.client as mqtt
import requests

from common.aurora_log import log, agora_utc

BORDA = os.environ.get("BORDA_ID", "borda-vila")
NUVEM = os.environ.get("NUVEM_URL", "http://10.10.0.1:9000")
DB = os.environ.get("BORDA_DB", "/data/borda.db")
PKI = os.environ.get("PKI_DISP", "/pki/dispositivos/borda-regras")
SYNC = float(os.environ.get("SYNC_INTERVALO", "5"))
PSEUDO_KEY = os.environ.get("PSEUDO_KEY", "")

# ---- Parâmetros das regras locais (perfil seguro) ----
CAMARA_MIN, CAMARA_MAX = 2.0, 8.0          # faixa segura de vacinas (°C)
NIVEL_MIN = 20.0                            # intertravamento: abaixo disso a bomba NÃO liga
ALAGAMENTO_ALERTA = 30.0                    # cm
PERFIL_BOMBA = ("06:00", "22:00")           # horário permitido para a bomba
JANELA_MAX_H = 4                            # duração máxima de uma janela de bombeamento
AGENDA_FABRICA = [("06:30", "08:30"), ("16:00", "18:00")]

# Tópico -> CN (a ACL do broker garante que só aquele CN escreve no tópico)
TOPICO_CN = {
    "vila/escola/agua/nivel": "escola-nivel-01", "vila/escola/bomba/estado": "escola-bomba-01",
    "vila/ubs/camarafria/temp": "ubs-camarafria-01", "vila/abrigo/alagamento": "abrigo-alagamento-01",
    "vila/abrigo/porta/estado": "abrigo-porta-01", "vila/abrigo/porta/acesso": "abrigo-porta-01",
    "vila/centro/energia": "centro-energia-01", "vila/horta/solo/umidade": "horta-umidade-01",
}

lock = threading.Lock()
st = {"nivel": None, "temp": None, "agua": None, "bomba_ligada": None, "alarme_camara": False,
      "alarme_alag": False, "modo_seguro": False, "agenda": list(AGENDA_FABRICA), "link": None,
      "offline_desde": None, "offline_total_s": 0.0, "quedas": 0, "alarmes_locais": 0,
      "camara_fora_desde": None, "inicio": time.time(), "ultima_sync_ok": None}
taxa = defaultdict(lambda: deque(maxlen=200))
suspeitos_reportados = {}  # CN -> último aviso (s)


def db():
    c = sqlite3.connect(DB, timeout=10, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = db()
    c.execute("CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, topico TEXT,"
              " payload TEXT, enviado INTEGER DEFAULT 0, gerado_offline INTEGER DEFAULT 0)")
    c.execute("CREATE INDEX IF NOT EXISTS ix_env ON outbox(enviado)")
    c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
    r = c.execute("SELECT v FROM kv WHERE k='agenda'").fetchone()
    if r:
        st["agenda"] = [tuple(x) for x in json.loads(r[0])]
    r = c.execute("SELECT v FROM kv WHERE k='modo_seguro'").fetchone()
    if r:
        st["modo_seguro"] = r[0] == "1"
    c.close()


def kv_set(k, v):
    c = db()
    c.execute("INSERT INTO kv VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    c.close()


def guardar(topico, payload):
    c = db()
    c.execute("INSERT INTO outbox (ts, topico, payload, gerado_offline) VALUES (?,?,?,?)",
              (agora_utc(), topico, json.dumps(payload), 0 if st["link"] else 1))
    c.close()


def hm(s):
    h, m = s.split(":")[:2]
    return int(h) * 60 + int(m)


def agora_min():
    t = datetime.now()
    return t.hour * 60 + t.minute


# ---------------------------------------------------------------- MQTT
cli = None


def publicar(topico, dados):
    if cli:
        cli.publish(topico, json.dumps(dict(dados, ts=agora_utc(), origem="borda-regras")), qos=1)


def alarme_local(tipo, msg, **extra):
    """Alerta gerado e entregue NA BORDA (sirene/painel local), sem depender da nuvem."""
    st["alarmes_locais"] += 1
    reg = log("alarme_local", "critical", tipo=tipo, mensagem=msg, link_wan=st["link"], **extra)
    publicar("vila/alertas/local", {"tipo": tipo, "mensagem": msg, **extra})
    guardar("vila/alertas/local", reg)


def on_connect(c, u, f, rc, p=None):
    if rc == 0:
        log("borda_mqtt_conectada")
        c.subscribe("vila/#", qos=1)
    else:
        log("borda_mqtt_recusada", "error", rc=str(rc))


def on_message(c, u, msg):
    topico = msg.topic
    if topico.startswith("vila/alertas"):
        return
    try:
        dados = json.loads(msg.payload)
    except Exception:
        dados = {"bruto": msg.payload[:200].decode(errors="replace")}
    cn = TOPICO_CN.get(topico)
    if topico == "vila/abrigo/porta/acesso" and "cracha" in dados:
        # pseudonimização na origem (LGPD): o número do crachá não sai da borda
        dados["cracha_pseudo"] = hmac.new(PSEUDO_KEY.encode(), dados.pop("cracha").encode(),
                                          hashlib.sha256).hexdigest()[:16]
    with lock:
        if cn:
            verificar_comportamento(cn, topico, dados)
        regras(topico, dados)
    if not topico.endswith("/cmd"):
        guardar(topico, dados)


def verificar_comportamento(cn, topico, dados):
    agora = time.time()
    taxa[cn].append(agora)
    recentes = sum(1 for t in taxa[cn] if agora - t < 5)
    impossivel = any(isinstance(v, (int, float)) and (v > 1000 or v < -100) for k, v in dados.items()
                     if k.endswith(("_pct", "_c", "_cm")))
    if (recentes > 25 or impossivel) and agora - suspeitos_reportados.get(cn, 0) > 120:
        suspeitos_reportados[cn] = agora
        log("dispositivo_suspeito", "warning", dispositivo=cn, topico=topico,
            msgs_ultimos_5s=recentes, valor_impossivel=impossivel)


def regras(topico, d):
    if topico == "vila/ubs/camarafria/temp" and "temp_c" in d:
        t = d["temp_c"]
        st["temp"] = t
        fora = t < CAMARA_MIN or t > CAMARA_MAX
        if fora and not st["alarme_camara"]:
            st["alarme_camara"] = True
            st["camara_fora_desde"] = time.time()
            alarme_local("camara_fria", f"Câmara fria da UBS fora da faixa segura: {t} °C", temp_c=t)
        elif not fora and st["alarme_camara"]:
            st["alarme_camara"] = False
            dur = round(time.time() - (st["camara_fora_desde"] or time.time()), 1)
            log("alarme_local_normalizado", tipo="camara_fria", temp_c=t, duracao_s=dur)
    elif topico == "vila/abrigo/alagamento" and "agua_cm" in d:
        a = d["agua_cm"]
        st["agua"] = a
        if a >= ALAGAMENTO_ALERTA and not st["alarme_alag"]:
            st["alarme_alag"] = True
            alarme_local("alagamento", f"Água no abrigo: {a} cm - acionar Defesa Civil", agua_cm=a)
        elif a < ALAGAMENTO_ALERTA * 0.5 and st["alarme_alag"]:
            st["alarme_alag"] = False
            log("alarme_local_normalizado", tipo="alagamento", agua_cm=a)
    elif topico == "vila/escola/agua/nivel" and "nivel_pct" in d:
        st["nivel"] = d["nivel_pct"]
    elif topico == "vila/escola/bomba/estado" and "ligada" in d:
        st["bomba_ligada"] = d["ligada"]


# ------------------------------------------------------------ BOMBA
def agenda_valida(janelas):
    """Perfil seguro: janelas dentro de 06:00-22:00 e com no máximo 4 h."""
    pi, pf = hm(PERFIL_BOMBA[0]), hm(PERFIL_BOMBA[1])
    for ini, fim in janelas:
        a, b = hm(ini), hm(fim)
        if not (pi <= a < b <= pf) or (b - a) > JANELA_MAX_H * 60:
            return False, f"janela {ini}-{fim} fora do perfil {PERFIL_BOMBA[0]}-{PERFIL_BOMBA[1]} / máx {JANELA_MAX_H}h"
    return True, ""


def controle_bomba():
    ultimo_envio = 0
    while True:
        time.sleep(3)
        with lock:
            m = agora_min()
            agenda = AGENDA_FABRICA if st["modo_seguro"] else st["agenda"]
            na_janela = any(hm(a) <= m < hm(b) for a, b in agenda)
            nivel_ok = st["nivel"] is None or st["nivel"] >= NIVEL_MIN
            desejado = na_janela and nivel_ok
            if na_janela and not nivel_ok and st["bomba_ligada"]:
                log("intertravamento_bomba", "warning", nivel_pct=st["nivel"],
                    mensagem="nível abaixo do mínimo - bomba desligada pela regra local")
            mudou = desejado != st["bomba_ligada"]
        if mudou or time.time() - ultimo_envio > 30:
            publicar("vila/escola/bomba/cmd", {"acao": "ligar" if desejado else "desligar",
                                               "motivo": "agenda" if desejado else "fora_agenda_ou_intertravamento"})
            if mudou:
                log("atuador_comando", alvo="escola-bomba-01", acao="ligar" if desejado else "desligar",
                    origem="regra_local", nivel_pct=st["nivel"], modo_seguro=st["modo_seguro"])
            ultimo_envio = time.time()


# --------------------------------------------------------- SINCRONIA
def set_link(ok):
    agora = time.time()
    if ok and st["link"] is not True:
        if st["offline_desde"]:
            dur = agora - st["offline_desde"]
            st["offline_total_s"] += dur
            c = db()
            pend = c.execute("SELECT count(*) FROM outbox WHERE enviado=0").fetchone()[0]
            c.close()
            log("wan_link_voltou", offline_s=round(dur, 1), pendentes=pend)
        else:
            log("wan_link_ok")
            st["link"] = True
            return True
        st["offline_desde"] = None
    elif not ok and st["link"] is None:
        st["link"] = False          # inicialização: nuvem ainda subindo (não conta como queda)
        log("wan_aguardando_nuvem")
        return False
    elif not ok and st["link"] is not False:
        st["offline_desde"] = agora
        st["quedas"] += 1
        log("wan_link_caiu", "warning", mensagem="sem nuvem - operando em modo autônomo local")
    reconectou = ok and st["link"] is False
    st["link"] = ok
    return reconectou


def enviar_lote(s):
    c = db()
    rows = c.execute("SELECT seq, ts, topico, payload FROM outbox WHERE enviado=0 ORDER BY seq LIMIT 1000").fetchall()
    if not rows:
        c.close()
        return 0
    itens = [{"seq": r[0], "ts": r[1], "topico": r[2], "payload": json.loads(r[3])} for r in rows]
    resp = s.post(f"{NUVEM}/api/telemetria", json={"borda": BORDA, "itens": itens}, timeout=10)
    resp.raise_for_status()
    aceitos = resp.json()["confirmados"]
    c.executemany("UPDATE outbox SET enviado=1 WHERE seq=?", [(x,) for x in aceitos])
    c.close()
    return len(aceitos)


def reconciliar(s):
    c = db()
    max_local = c.execute("SELECT coalesce(max(seq),0) FROM outbox WHERE enviado=1").fetchone()[0]
    r = s.get(f"{NUVEM}/api/reconciliar", params={"borda": BORDA, "ate": max_local}, timeout=10).json()
    faltam = r.get("faltantes", [])
    if faltam:
        c.executemany("UPDATE outbox SET enviado=0 WHERE seq=?", [(x,) for x in faltam])
    c.close()
    log("reconciliacao", max_seq_local=max_local, nuvem_total=r.get("total"), faltantes=len(faltam))


def aplicar_agenda(s):
    r = s.get(f"{NUVEM}/api/agendamento", params={"espaco": "escola"}, timeout=10)
    janelas = [tuple(x) for x in r.json()["janelas"]]
    if janelas == st["agenda"]:
        return
    ok, motivo = agenda_valida(janelas)
    if not ok:
        if st.get("agenda_rejeitada") != janelas:
            st["agenda_rejeitada"] = janelas
            log("agendamento_fora_perfil", "critical", alvo="escola-bomba-01", recebido=janelas,
                mantido=st["agenda"], motivo=motivo,
                mensagem="agendamento remoto REJEITADO pela borda (possível adulteração na nuvem)")
        return
    with lock:
        st["agenda"] = janelas
    kv_set("agenda", json.dumps(janelas))
    log("agendamento_atualizado", janelas=janelas)


def executar_comando(cmd):
    acao, risco = cmd["acao"], cmd["risco"]
    if risco == "alto" and not cmd.get("aprovado_por"):
        return "recusado_borda", "alto impacto sem aprovação humana"
    with lock:
        if acao == "modo_seguro":
            st["modo_seguro"] = True
            kv_set("modo_seguro", "1")
        elif acao == "sair_modo_seguro":
            st["modo_seguro"] = False
            kv_set("modo_seguro", "0")
        elif acao == "desligar_bomba":
            st["agenda"] = []
            kv_set("agenda", "[]")
        elif acao == "travar_portas":
            publicar("vila/abrigo/porta/cmd", {"acao": "travar"})
        elif acao == "liberar_portas":
            publicar("vila/abrigo/porta/cmd", {"acao": "liberar"})
        elif acao == "ligar_bomba":
            m = agora_min()
            if not hm(PERFIL_BOMBA[0]) <= m < hm(PERFIL_BOMBA[1]):
                log("atuador_comando_fora_horario", "critical", alvo=cmd["alvo"], acao=acao,
                    solicitado_por=cmd.get("solicitado_por"))
                return "recusado_borda", "fora do horário permitido"
        else:
            return "recusado_borda", "ação desconhecida"
    log("comando_remoto_executado", id=cmd["id"], acao=acao, risco=risco, aprovado_por=cmd.get("aprovado_por"),
        solicitado_por=cmd.get("solicitado_por"))
    return "executado", "ok"


def aplicar_comandos(s):
    for cmd in s.get(f"{NUVEM}/api/comandos", params={"borda": BORDA}, timeout=10).json()["comandos"]:
        status, res = executar_comando(cmd)
        if status != "executado":
            log("comando_remoto_recusado", "warning", id=cmd["id"], acao=cmd["acao"], motivo=res)
        s.post(f"{NUVEM}/api/comandos/{cmd['id']}/resultado", json={"status": status, "resultado": res}, timeout=10)


def status():
    c = db()
    tot, env, off = c.execute("SELECT count(*), coalesce(sum(enviado),0), coalesce(sum(gerado_offline),0) FROM outbox").fetchone()
    c.close()
    offline = st["offline_total_s"] + (time.time() - st["offline_desde"] if st["offline_desde"] else 0)
    s = {"ts": agora_utc(), "borda": BORDA, "link_wan": st["link"], "gerados": tot, "enviados": env,
         "pendentes": tot - env, "gerados_offline": off, "quedas_wan": st["quedas"],
         "offline_total_s": round(offline, 1), "uptime_s": round(time.time() - st["inicio"], 1),
         "alarmes_locais": st["alarmes_locais"], "modo_seguro": st["modo_seguro"], "agenda": st["agenda"],
         "nivel_pct": st["nivel"], "temp_camara_c": st["temp"], "bomba_ligada": st["bomba_ligada"]}
    tmp = "/data/status.json.tmp"
    json.dump(s, open(tmp, "w"), ensure_ascii=False, indent=1)
    os.replace(tmp, "/data/status.json")
    return s


def sincronizador():
    s = requests.Session()
    ultimo_status = 0
    while True:
        try:
            s.get(f"{NUVEM}/api/saude", timeout=3).raise_for_status()
            if set_link(True):
                reconciliar(s)
            while enviar_lote(s) >= 1000:
                pass
            aplicar_agenda(s)
            aplicar_comandos(s)
            st["ultima_sync_ok"] = time.time()
        except requests.RequestException:
            set_link(False)
        except Exception as e:
            log("sync_erro", "error", erro=str(e)[:300])
        if time.time() - ultimo_status > 60:
            log("borda_status", **status())
            ultimo_status = time.time()
        else:
            status()
        time.sleep(SYNC)


def main():
    global cli
    init_db()
    cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="borda-regras")
    cli.tls_set(ca_certs=f"{PKI}/ca.crt", certfile=f"{PKI}/cliente.crt", keyfile=f"{PKI}/cliente.key",
                cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    cli.on_connect = on_connect
    cli.on_message = on_message
    cli.reconnect_delay_set(1, 10)
    while True:
        try:
            cli.connect(os.environ.get("MQTT_HOST", "mosquitto"), 8883, keepalive=20)
            break
        except Exception as e:
            log("borda_mqtt_aguardando", "warning", erro=str(e))
            time.sleep(3)
    cli.loop_start()
    threading.Thread(target=controle_bomba, daemon=True).start()
    threading.Thread(target=sincronizador, daemon=True).start()
    log("borda_iniciada", borda=BORDA, agenda=st["agenda"], modo_seguro=st["modo_seguro"])
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()

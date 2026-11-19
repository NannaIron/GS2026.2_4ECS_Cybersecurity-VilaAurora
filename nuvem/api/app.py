"""API de ingestão da NUVEM (só acessível pelo túnel WireGuard, segmento das bordas).

A identidade da borda vem da chave WireGuard (IP do túnel), não de senha compartilhada.
Usuário de banco: ingest_app (privilégio mínimo).
"""
import ipaddress
import json
import os

import psycopg2
import psycopg2.extras
from flask import Flask, abort, jsonify, request

from common.aurora_log import log

app = Flask(__name__)
BORDAS = {"10.10.1.2": "borda-vila"}   # IP no túnel -> identidade da borda
SEGMENTO_BORDAS = ipaddress.ip_network("10.10.1.0/24")


def conn():
    return psycopg2.connect(host="postgres", dbname="aurora", user="ingest_app",
                            password=os.environ["INGEST_APP_PASSWORD"], connect_timeout=5)


def borda_autorizada():
    ip = request.remote_addr
    if ipaddress.ip_address(ip) not in SEGMENTO_BORDAS or ip not in BORDAS:
        log("api_acesso_negado", "warning", ip_origem=ip, caminho=request.path)
        abort(403)
    nome = BORDAS[ip]
    pedida = (request.get_json(silent=True) or {}).get("borda") or request.args.get("borda")
    if pedida and pedida != nome:
        log("api_identidade_divergente", "warning", ip_origem=ip, borda_declarada=pedida, borda_real=nome)
        abort(403)
    return nome


@app.get("/api/saude")
def saude():
    return {"ok": True}


@app.post("/api/telemetria")
def telemetria():
    borda = borda_autorizada()
    itens = request.get_json()["itens"]
    confirmados = []
    with conn() as c, c.cursor() as cur:
        for it in itens:
            cur.execute("INSERT INTO telemetria (borda, seq, ts, topico, payload) VALUES (%s,%s,%s,%s,%s) "
                        "ON CONFLICT (borda, seq) DO NOTHING",
                        (borda, int(it["seq"]), it["ts"], it["topico"][:120], json.dumps(it["payload"])))
            p = it["payload"]
            if it["topico"] == "vila/abrigo/porta/acesso" and cur.rowcount == 1 and "cracha_pseudo" in p:
                cur.execute("INSERT INTO acessos (ts, espaco, porta, cracha_pseudo, perfil, resultado) "
                            "VALUES (%s::timestamptz AT TIME ZONE 'America/Sao_Paulo','abrigo','entrada',%s,'voluntario',%s)",
                            (it["ts"], p["cracha_pseudo"], p.get("resultado", "liberado")))
            confirmados.append(int(it["seq"]))
    return {"confirmados": confirmados}


@app.get("/api/reconciliar")
def reconciliar():
    borda = borda_autorizada()
    ate = int(request.args.get("ate", 0))
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT count(*), coalesce(max(seq),0) FROM telemetria WHERE borda=%s", (borda,))
        total, mx = cur.fetchone()
        cur.execute("SELECT s FROM generate_series(1, %s) s WHERE NOT EXISTS "
                    "(SELECT 1 FROM telemetria t WHERE t.borda=%s AND t.seq=s) LIMIT 20000", (ate, borda))
        faltantes = [r[0] for r in cur.fetchall()]
    return {"total": total, "max_seq": mx, "faltantes": faltantes}


@app.get("/api/agendamento")
def agendamento():
    borda_autorizada()
    espaco = request.args.get("espaco", "escola")
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT to_char(hora_inicio,'HH24:MI'), to_char(hora_fim,'HH24:MI') FROM agendamento_bomba "
                    "WHERE espaco=%s AND ativo ORDER BY hora_inicio", (espaco,))
        return {"janelas": [list(r) for r in cur.fetchall()]}


@app.get("/api/comandos")
def comandos():
    borda = borda_autorizada()
    with conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # a borda só recebe comandos aprovados (baixo risco = aprovação automática do SOAR)
        cur.execute("SELECT id, acao, alvo, risco, solicitado_por, aprovado_por FROM comandos_borda "
                    "WHERE borda=%s AND status='aprovado' ORDER BY id", (borda,))
        return {"comandos": cur.fetchall()}


@app.post("/api/comandos/<int:cid>/resultado")
def resultado(cid):
    borda = borda_autorizada()
    r = request.get_json()
    status = r["status"] if r["status"] in ("executado", "recusado_borda") else "recusado_borda"
    with conn() as c, c.cursor() as cur:
        cur.execute("UPDATE comandos_borda SET status=%s, executado_em=now(), resultado=%s WHERE id=%s AND borda=%s",
                    (status, str(r.get("resultado"))[:200], cid, borda))
    log("comando_resultado", id=cid, status=status, resultado=r.get("resultado"))
    return {"ok": True}

"""Painel de supervisão SEGURO (versão corrigida) - RT-08, RT-09, RT-15, RT-21.

Correções em relação ao painel legado (painel/legado/app.py):
  1. Consultas 100% parametrizadas (psycopg2 %s) - causa raiz do SQL Injection.
  2. Validação de entrada no servidor (lista de permissões, regex, tamanho, datas).
  3. Usuário de banco painel_app com privilégio mínimo (sem acesso a e-mail/telefone).
  4. Mensagens de erro genéricas (detalhe só no log, com código de referência).
  5. MFA TOTP obrigatório + RBAC (operador, técnico, coordenação, auditor).
  6. Camada adicional: mini-WAF com assinaturas de SQLi (defesa em profundidade).
  7. Ações de ALTO impacto vão para fila de aprovação humana (coordenação + MFA de novo).
Só escuta em 10.10.0.1:8443 (túnel WireGuard, segmento de operadores).
"""
import functools
import os
import re
import secrets
import time
import uuid
from datetime import date, datetime

import psycopg2
import psycopg2.extras
import pyotp
from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from common.aurora_log import log

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  PERMANENT_SESSION_LIFETIME=1800, MAX_CONTENT_LENGTH=64 * 1024)
WAF_ATIVO = os.environ.get("WAF_ATIVO", "1") == "1"

PERFIS = ("operador", "tecnico", "coordenacao", "auditor")
NOME_PERFIL = {"operador": "Operador(a)", "tecnico": "Técnico(a)", "coordenacao": "Coordenação",
               "auditor": "Auditor(a)"}
ESPACOS = {"escola": "Escola Municipal", "ubs": "UBS", "abrigo": "Abrigo de Emergência",
           "centro": "Centro Comunitário", "horta": "Horta e Cozinha Solidária"}
ACOES = {  # ação -> (risco, descrição em linguagem simples)
    "modo_seguro": ("baixo", "Colocar a bomba em modo seguro (só agenda de fábrica)"),
    "sair_modo_seguro": ("baixo", "Tirar a bomba do modo seguro"),
    "travar_portas": ("baixo", "Travar as portas do abrigo"),
    "desligar_bomba": ("alto", "DESLIGAR a bomba da escola"),
    "liberar_portas": ("alto", "LIBERAR todas as portas do abrigo"),
    "ligar_bomba": ("alto", "LIGAR a bomba fora da agenda"),
}
RE_PORTA = re.compile(r"^[a-z\-]{0,20}$")
RE_CRACHA = re.compile(r"^[a-f0-9]{0,16}$")
RE_HORA = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
# Assinaturas do mini-WAF (camada ADICIONAL; a correção real é a parametrização)
WAF = re.compile(r"('|\")\s*(or|and|union|;)|union\s+(all\s+)?select|;\s*(update|delete|insert|drop|alter)\b|"
                 r"--|/\*|\bpg_sleep\b|\bsleep\(|information_schema|\bselect\b.+\bfrom\b", re.I)

falhas_login = {}
ultimo_totp = {}


# ------------------------------------------------------------------ infra
def db():
    if "db" not in g:
        g.db = psycopg2.connect(host="postgres", dbname="aurora", user="painel_app",
                                password=os.environ["PAINEL_APP_PASSWORD"], connect_timeout=5,
                                options="-c timezone=America/Sao_Paulo")
    return g.db


@app.teardown_appcontext
def fechar(exc):
    c = g.pop("db", None)
    if c:
        c.close()


def q(sql, args=None, um=False, commit=False):
    with db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, args)  # SEMPRE parâmetros separados do SQL
        r = (cur.fetchone() if um else cur.fetchall()) if cur.description else None
    if commit:
        db().commit()
    return r


def auditar(acao, detalhe=""):
    q("INSERT INTO auditoria (usuario, acao, detalhe, ip) VALUES (%s,%s,%s,%s)",
      (session.get("usuario"), acao, detalhe[:500], request.remote_addr), commit=True)


@app.before_request
def antes():
    g.rid = uuid.uuid4().hex[:12]
    if WAF_ATIVO:
        for k, v in list(request.args.items()) + list(request.form.items()):
            if k not in ("senha", "csrf") and WAF.search(v or ""):
                log("waf_bloqueio", "warning", ip_origem=request.remote_addr, usuario=session.get("usuario"),
                    caminho=request.path, parametro=k, valor=v[:200], rid=g.rid)
                return render_template("erro.html", msg="Pedido bloqueado por segurança.", rid=g.rid), 403
    if request.method == "POST" and request.endpoint not in ("static",):
        if request.form.get("csrf") != session.get("csrf"):
            abort(400)


@app.after_request
def depois(resp):
    resp.headers.update({
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=31536000", "Cache-Control": "no-store"})
    if request.endpoint != "static":
        log("http_request", ip_origem=request.remote_addr, usuario=session.get("usuario"), metodo=request.method,
            caminho=request.path, query=request.query_string.decode(errors="replace")[:300], status=resp.status_code,
            rid=getattr(g, "rid", None))
    return resp


@app.errorhandler(Exception)
def erro(e):
    codigo = getattr(e, "code", 500)
    if codigo == 500:
        log("erro_interno", "error", rid=g.rid, erro=repr(e)[:500], caminho=request.path)
    msgs = {400: "Dados inválidos. Confira os campos e tente de novo.", 403: "Você não tem permissão para isso.",
            404: "Página não encontrada.", 429: "Muitas tentativas. Aguarde alguns minutos."}
    return render_template("erro.html", msg=msgs.get(codigo, "Ocorreu um erro. Tente novamente."),
                           rid=g.rid), codigo if isinstance(codigo, int) else 500


@app.context_processor
def ctx():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return {"usuario": session.get("usuario"), "perfil": session.get("perfil"), "NOME_PERFIL": NOME_PERFIL,
            "csrf": session["csrf"]}


def requer(*perfis):
    def deco(f):
        @functools.wraps(f)
        def w(*a, **k):
            if not session.get("mfa_ok"):
                return redirect(url_for("login"))
            if perfis and session.get("perfil") not in perfis:
                log("rbac_negado", "warning", usuario=session.get("usuario"), perfil=session.get("perfil"),
                    caminho=request.path, ip_origem=request.remote_addr)
                abort(403)
            return f(*a, **k)
        return w
    return deco


# ------------------------------------------------------------------ login + MFA
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    user = request.form.get("usuario", "")[:40]
    chave = (user, request.remote_addr)
    f = [t for t in falhas_login.get(chave, []) if time.time() - t < 900]
    if len(f) >= 5:
        log("login_bloqueado", "warning", usuario=user, ip_origem=request.remote_addr)
        abort(429)
    u = q("SELECT login, perfil, senha_hash, ativo FROM usuarios WHERE login=%s", (user,), um=True)
    if not u or not u["ativo"] or u["perfil"] not in PERFIS or \
            not check_password_hash(u["senha_hash"], request.form.get("senha", "")):
        falhas_login[chave] = f + [time.time()]
        log("login_falha", "warning", usuario=user, ip_origem=request.remote_addr)
        return render_template("login.html", erro="Usuário ou senha incorretos."), 401
    session.clear()
    session["pre_mfa"] = u["login"]
    return redirect(url_for("mfa"))


def totp_ok(login, codigo):
    u = q("SELECT totp_secret FROM usuarios WHERE login=%s", (login,), um=True)
    if not u or not u["totp_secret"] or not re.fullmatch(r"\d{6}", codigo or ""):
        return False
    t = pyotp.TOTP(u["totp_secret"])
    if not t.verify(codigo, valid_window=1):
        return False
    passo = int(time.time() // 30)
    if ultimo_totp.get(login) == (codigo, passo) or ultimo_totp.get(login, ("", 0))[0] == codigo:
        return False  # impede reutilização do mesmo código (replay)
    ultimo_totp[login] = (codigo, passo)
    return True


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    login_ = session.get("pre_mfa")
    if not login_:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("mfa.html")
    if not totp_ok(login_, request.form.get("codigo", "")):
        log("mfa_falha", "warning", usuario=login_, ip_origem=request.remote_addr)
        return render_template("mfa.html", erro="Código inválido ou já usado."), 401
    u = q("SELECT login, nome, perfil FROM usuarios WHERE login=%s", (login_,), um=True)
    session.clear()
    session.update(usuario=u["login"], nome=u["nome"], perfil=u["perfil"], mfa_ok=True,
                   csrf=secrets.token_urlsafe(24))
    log("login_sucesso", usuario=u["login"], perfil=u["perfil"], ip_origem=request.remote_addr, mfa=True)
    auditar("login", "senha + TOTP")
    return redirect(url_for("inicio"))


@app.post("/sair")
def sair():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ telas
@app.get("/")
@requer()
def inicio():
    leituras = q("SELECT DISTINCT ON (topico) topico, ts, payload FROM telemetria "
                 "WHERE topico NOT LIKE 'vila/alertas%' ORDER BY topico, seq DESC")
    alertas = q("SELECT ts, regra, severidade, resumo, resposta FROM alertas ORDER BY id DESC LIMIT 15")
    locais = q("SELECT ts, payload FROM telemetria WHERE topico='vila/alertas/local' ORDER BY seq DESC LIMIT 10")
    return render_template("inicio.html", leituras=leituras, alertas=alertas, locais=locais)


@app.get("/acessos")
@requer("coordenacao", "auditor")
def acessos():
    a = request.args
    espaco, porta, cracha = a.get("espaco", ""), a.get("porta", ""), a.get("cracha", "")
    busca = a.get("busca", "")
    de, ate = a.get("de", ""), a.get("ate", "")
    # ---- validação no servidor (lista de permissões + formato + tamanho)
    if espaco and espaco not in ESPACOS:
        abort(400)
    if not RE_PORTA.fullmatch(porta) or not RE_CRACHA.fullmatch(cracha) or len(busca) > 40:
        abort(400)
    try:
        d_de = date.fromisoformat(de) if de else date(2000, 1, 1)
        d_ate = date.fromisoformat(ate) if ate else date(2100, 1, 1)
    except ValueError:
        abort(400)
    termo = "%" + busca.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    linhas = q("SELECT ts, espaco, porta, cracha_pseudo, perfil, resultado FROM acessos "
               "WHERE (%s = '' OR espaco = %s) AND porta LIKE %s AND cracha_pseudo LIKE %s "
               "AND (porta ILIKE %s OR perfil ILIKE %s OR resultado ILIKE %s) "
               "AND ts::date BETWEEN %s AND %s ORDER BY ts DESC LIMIT 100",
               (espaco, espaco, (porta or "") + "%", (cracha or "") + "%", termo, termo, termo, d_de, d_ate))
    auditar("consulta_acessos", f"espaco={espaco} porta={porta} cracha={cracha} busca={busca}")
    return render_template("acessos.html", linhas=linhas, ESPACOS=ESPACOS, f=a)


@app.route("/agendamento", methods=["GET", "POST"])
@requer()
def agendamento():
    msg = None
    if request.method == "POST":
        if session["perfil"] != "coordenacao":
            abort(403)
        try:
            jid = int(request.form["id"])
        except (KeyError, ValueError):
            abort(400)
        ini, fim = request.form.get("inicio", ""), request.form.get("fim", "")
        if not (RE_HORA.fullmatch(ini) and RE_HORA.fullmatch(fim)):
            abort(400)
        a, b = int(ini[:2]) * 60 + int(ini[3:]), int(fim[:2]) * 60 + int(fim[3:])
        if not (360 <= a < b <= 1320) or b - a > 240:
            msg = "Horário recusado: a bomba só pode funcionar entre 06:00 e 22:00, até 4 horas seguidas."
        else:
            q("UPDATE agendamento_bomba SET hora_inicio=%s, hora_fim=%s, atualizado_em=now(), atualizado_por=%s "
              "WHERE id=%s", (ini, fim, session["usuario"], jid), commit=True)
            auditar("agendamento_alterado", f"id={jid} {ini}-{fim}")
            msg = "Agendamento salvo."
    linhas = q("SELECT id, espaco, to_char(hora_inicio,'HH24:MI') ini, to_char(hora_fim,'HH24:MI') fim, ativo, "
               "atualizado_em, atualizado_por FROM agendamento_bomba ORDER BY espaco, hora_inicio")
    return render_template("agendamento.html", linhas=linhas, msg=msg)


@app.route("/comandos", methods=["GET", "POST"])
@requer()
def comandos():
    msg = None
    if request.method == "POST":
        if session["perfil"] not in ("tecnico", "coordenacao"):
            abort(403)
        acao = request.form.get("acao", "")
        if acao not in ACOES:
            abort(400)
        risco = ACOES[acao][0]
        status = "aprovado" if risco == "baixo" else "pendente"
        alvo = "abrigo-porta-01" if "portas" in acao else "escola-bomba-01"
        q("INSERT INTO comandos_borda (acao, alvo, risco, status, solicitado_por, motivo, aprovado_por, aprovado_em) "
          "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
          (acao, alvo, risco, status, session["usuario"], request.form.get("motivo", "")[:200],
           "automatico-baixo-risco" if risco == "baixo" else None, datetime.now() if risco == "baixo" else None),
          commit=True)
        auditar("comando_solicitado", f"{acao} risco={risco} status={status}")
        msg = ("Comando enviado à borda." if risco == "baixo" else
               "Ação de ALTO impacto: aguardando aprovação de outra pessoa da coordenação.")
    linhas = q("SELECT * FROM comandos_borda ORDER BY id DESC LIMIT 30")
    return render_template("comandos.html", linhas=linhas, ACOES=ACOES, msg=msg)


@app.post("/comandos/<int:cid>/decidir")
@requer("coordenacao")
def decidir(cid):
    c = q("SELECT * FROM comandos_borda WHERE id=%s", (cid,), um=True)
    if not c or c["status"] != "pendente":
        abort(404)
    if c["solicitado_por"] == session["usuario"]:
        return render_template("erro.html", msg="Quem pediu não pode aprovar o próprio pedido.", rid=g.rid), 403
    if not totp_ok(session["usuario"], request.form.get("codigo", "")):  # step-up MFA
        return render_template("erro.html", msg="Confirme com um código MFA novo para decidir.", rid=g.rid), 401
    decisao = "aprovado" if request.form.get("decisao") == "aprovar" else "rejeitado"
    q("UPDATE comandos_borda SET status=%s, aprovado_por=%s, aprovado_em=now() WHERE id=%s",
      (decisao, session["usuario"], cid), commit=True)
    log("aprovacao_humana", usuario=session["usuario"], comando=cid, acao=c["acao"], decisao=decisao)
    auditar("comando_" + decisao, f"id={cid} {c['acao']}")
    return redirect(url_for("comandos"))


@app.get("/auditoria")
@requer("auditor", "coordenacao")
def auditoria():
    return render_template("auditoria.html",
                           linhas=q("SELECT ts, usuario, acao, detalhe, ip FROM auditoria ORDER BY id DESC LIMIT 200"))

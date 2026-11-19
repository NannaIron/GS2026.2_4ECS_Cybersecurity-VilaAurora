"""Simulação da "VPN legada" do incidente: portal de acesso remoto com SÓ usuário e
senha (sem MFA), exposto na "internet" (rede seg_wan). Depois do login, encaminha
tudo para o painel legado. Usado apenas para reproduzir o INC-VA-0712.

Registra os logins (fonte de evidência para a regra 'VPN anômala') e respeita a
lista de bloqueio do SOAR (/soar/bloqueios.json): IPs bloqueados e sessões encerradas.
"""
import json
import os
import secrets

import requests
from flask import Flask, Response, make_response, request
from werkzeug.security import check_password_hash

from common.aurora_log import log

app = Flask(__name__)
SESSOES = {}
USUARIOS = {u["login"]: u for u in json.load(open("/segredos/usuarios.json")) if u["perfil"] != "voluntario"}
BLOQ = "/soar/bloqueios.json"


def bloqueios():
    try:
        return json.load(open(BLOQ))
    except Exception:
        return {"ips": [], "usuarios": []}


@app.before_request
def checar_bloqueio():
    b = bloqueios()
    if request.remote_addr in b.get("ips", []):
        log("vpn_legada_ip_bloqueado", "warning", ip_origem=request.remote_addr)
        return Response("Acesso bloqueado", 403)
    tok = request.cookies.get("vpn")
    if tok in SESSOES and SESSOES[tok] in b.get("usuarios", []):
        log("vpn_legada_sessao_encerrada", "warning", usuario=SESSOES.pop(tok), ip_origem=request.remote_addr)
        return Response("Sessão encerrada pela equipe de segurança", 401)


@app.route("/vpn/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return ("<form method=post>Usuário <input name=usuario> Senha <input name=senha type=password>"
                "<button>Conectar VPN</button></form>")
    u, s = request.form.get("usuario", ""), request.form.get("senha", "")
    ok = u in USUARIOS and USUARIOS[u]["senha"] == s   # só senha, sem MFA (falha do legado)
    log("vpn_login", "info" if ok else "warning", tipo_vpn="legada_senha", usuario=u,
        ip_origem=request.remote_addr, sucesso=ok, mfa=False)
    if not ok:
        return Response("Falha na autenticação", 401)
    tok = secrets.token_hex(16)
    SESSOES[tok] = u
    r = make_response("VPN conectada. Painel disponível em /")
    r.set_cookie("vpn", tok, httponly=True)
    return r


@app.route("/", defaults={"p": ""})
@app.route("/<path:p>")
def proxy(p):
    tok = request.cookies.get("vpn")
    if tok not in SESSOES:
        return Response("Conecte-se em /vpn/login", 401)
    r = requests.get(f"http://painel-legado:5000/{p}", params=request.args,
                     headers={"X-Forwarded-For": request.remote_addr, "X-Usuario-VPN": SESSOES[tok]}, timeout=30)
    return Response(r.content, r.status_code, content_type=r.headers.get("content-type"))

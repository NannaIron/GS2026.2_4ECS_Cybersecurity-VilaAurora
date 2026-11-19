#!/usr/bin/env python3
"""Reteste do painel SEGURO, executado no container 'operador' (cliente WireGuard).
Verifica: MFA, RBAC, validação de entrada, WAF, ausência de SQL Injection, fila de
aprovação humana com MFA de novo (step-up). Gera JSON em /resultados.

uso: python3 /app/testes/teste_painel.py [--sem-waf]
"""
import json
import re
import sys
import time
from datetime import datetime

import pyotp
import requests
import urllib3

BASE = "https://10.10.0.1:8443"
CA = "/pki/ca.crt"   # o painel usa certificado da CA da Vila Aurora (SAN IP 10.10.0.1)
US = {u["login"]: u for u in json.load(open("/segredos/usuarios.json"))}
SEM_WAF = "--sem-waf" in sys.argv
res = {"inicio": datetime.now().astimezone().isoformat(), "waf_ativo_esperado": not SEM_WAF, "testes": []}
usados = {}


def ok(nome, cond, detalhe=""):
    res["testes"].append({"teste": nome, "passou": bool(cond), "detalhe": detalhe})
    print(f"[{'OK ' if cond else 'FALHOU'}] {nome} {detalhe}")


def csrf(s, url):
    r = s.get(url, verify=CA, allow_redirects=True)
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    return m.group(1) if m else ""


def codigo_novo(login):
    t = pyotp.TOTP(US[login]["totp"])
    while True:
        c = t.now()
        if usados.get(login) != c:
            usados[login] = c
            return c
        time.sleep(2)


def entrar(login, codigo=None):
    s = requests.Session()
    tok = csrf(s, f"{BASE}/login")
    r = s.post(f"{BASE}/login", data={"usuario": login, "senha": US[login]["senha"], "csrf": tok}, verify=CA,
               allow_redirects=False)
    if r.status_code != 302:
        return s, r
    tok = csrf(s, f"{BASE}/mfa")
    r = s.post(f"{BASE}/mfa", data={"codigo": codigo or codigo_novo(login), "csrf": tok}, verify=CA,
               allow_redirects=False)
    return s, r


# 1) Autenticação
s = requests.Session()
tok = csrf(s, f"{BASE}/login")
r = s.post(f"{BASE}/login", data={"usuario": "aud.helena", "senha": "errada", "csrf": tok}, verify=CA)
ok("senha errada é recusada", r.status_code == 401, f"HTTP {r.status_code}")
s, r = entrar("aud.helena", codigo="000000")
ok("senha certa + TOTP errado é recusado (MFA)", r.status_code == 401, f"HTTP {r.status_code}")
r = requests.get(f"{BASE}/", verify=CA, allow_redirects=False)
ok("sem login, painel redireciona para /login", r.status_code == 302 and "/login" in r.headers.get("Location", ""))
aud, r = entrar("aud.helena")
ok("auditor entra com senha + TOTP", r.status_code == 302, f"HTTP {r.status_code}")

# 2) RBAC
r = aud.get(f"{BASE}/acessos", verify=CA)
ok("auditor pode ver histórico de acessos", r.status_code == 200, f"HTTP {r.status_code}")
op, _ = entrar("op.joao")
r = op.get(f"{BASE}/acessos", verify=CA)
ok("operador NÃO pode ver histórico de acessos (RBAC)", r.status_code == 403, f"HTTP {r.status_code}")
r = op.post(f"{BASE}/comandos", data={"acao": "modo_seguro", "csrf": csrf(op, f"{BASE}/comandos")}, verify=CA)
ok("operador NÃO pode enviar comandos (RBAC)", r.status_code == 403, f"HTTP {r.status_code}")

# 3) SQL Injection - mesmos payloads do incidente
normal = aud.get(f"{BASE}/acessos", params={"busca": "entrada"}, verify=CA)
n_normal = int(re.search(r"(\d+) registro", normal.text).group(1))
ok("busca legítima funciona", normal.status_code == 200 and n_normal > 0, f"{n_normal} registros")
PAYLOADS = ["'", "' OR '1'='1", "zzz' UNION SELECT login, nome, email, telefone, senha_md5_legado FROM usuarios -- ",
            "zzz'; UPDATE agendamento_bomba SET hora_inicio='00:00', hora_fim='23:59' WHERE espaco='escola'; -- ",
            "x' AND pg_sleep(5) IS NULL -- "]
for p in PAYLOADS:
    t0 = time.time()
    r = aud.get(f"{BASE}/acessos", params={"busca": p}, verify=CA)
    dt = time.time() - t0
    vazou = "@vilaaurora.example" in r.text or "senha" in r.text.lower() and "md5" in r.text.lower()
    erro_sql = re.search(r"syntax error|psycopg2|Traceback|SELECT ", r.text) is not None
    m = re.search(r"(\d+) registro", r.text)
    cond = r.status_code in (200, 400, 403) and not vazou and not erro_sql and dt < 4
    camada = "WAF" if r.status_code == 403 else ("validação" if r.status_code == 400 else "parametrização")
    ok(f"SQLi neutralizado [{p[:40]}]", cond, f"HTTP {r.status_code} ({camada}), "
       f"{m.group(1) if m else '-'} registros, {dt:.2f}s, vazou={vazou}, erro_sql_exposto={erro_sql}")
r = aud.get(f"{BASE}/acessos", params={"cracha": "' OR 1=1 --"}, verify=CA)
ok("campo crachá com formato inválido -> 400/403 (validação no servidor)", r.status_code in (400, 403), f"HTTP {r.status_code}")
r = aud.get(f"{BASE}/acessos", params={"de": "2026-13-45"}, verify=CA)
ok("data inválida -> 400 com mensagem genérica", r.status_code == 400 and "Traceback" not in r.text, f"HTTP {r.status_code}")

# 4) Ação de alto impacto exige aprovação humana + step-up MFA, por outra pessoa
tec, _ = entrar("tec.rafael")
tec.post(f"{BASE}/comandos", data={"acao": "liberar_portas", "motivo": "teste automatizado",
                                    "csrf": csrf(tec, f"{BASE}/comandos")}, verify=CA)
pag = tec.get(f"{BASE}/comandos", verify=CA).text
m = re.search(r"<tr><td>(\d+)</td><td>[^<]+</td><td>liberar_portas</td>\s*<td class=\"alto\">alto</td><td>pendente</td>", pag)
ok("técnico pede 'liberar portas' -> fica PENDENTE (não executa)", m is not None)
if m:
    cid = m.group(1)
    coord, _ = entrar("coord.marina")
    r = coord.post(f"{BASE}/comandos/{cid}/decidir", data={"decisao": "aprovar", "codigo": "123456",
                                                           "csrf": csrf(coord, f"{BASE}/comandos")}, verify=CA)
    ok("aprovação sem código MFA novo é recusada", r.status_code == 401, f"HTTP {r.status_code}")
    print("   aguardando próximo código TOTP para o step-up MFA (até 30 s)...")
    r = coord.post(f"{BASE}/comandos/{cid}/decidir", data={"decisao": "rejeitar", "codigo": codigo_novo("coord.marina"),
                                                           "csrf": csrf(coord, f"{BASE}/comandos")}, verify=CA,
                   allow_redirects=False)
    ok("coordenação decide com MFA de novo (rejeitou o pedido de teste)", r.status_code == 302, f"HTTP {r.status_code}")

# 5) Cabeçalhos de segurança
h = aud.get(f"{BASE}/", verify=CA).headers
ok("cabeçalhos CSP/HSTS/X-Frame-Options presentes",
   all(k in h for k in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options")))

res["fim"] = datetime.now().astimezone().isoformat()
res["passaram"] = sum(t["passou"] for t in res["testes"])
res["total"] = len(res["testes"])
nome = f"/resultados/teste-painel-{'sem-waf' if SEM_WAF else 'com-waf'}-{datetime.now():%Y%m%d-%H%M%S}.json"
json.dump(res, open(nome, "w"), ensure_ascii=False, indent=2)
print(f"\n{res['passaram']}/{res['total']} testes passaram -> {nome}")

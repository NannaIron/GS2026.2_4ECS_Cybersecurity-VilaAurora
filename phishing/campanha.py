#!/usr/bin/env python3
"""Campanha de phishing SIMULADO no Gophish, 100% automatizada e só com contas FICTÍCIAS.

1. cria perfil SMTP (Mailpit), grupo de alvos fictícios, modelo de e-mail e landing page
   (NÃO captura senhas: capture_passwords=false);
2. dispara a campanha;
3. simula o comportamento dos alvos fictícios lendo os e-mails no Mailpit
   (abrir / clicar / submeter / reportar), com semente fixa;
4. lê as métricas do próprio Gophish e salva em /resultados/phishing-metricas-*.json

uso (via make phishing-campanha): roda num container na rede seg_phishing.
"""
import json
import os
import random
import re
import sys
import time
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings()
GP = "https://va-gophish:3333/api"
MP = "http://va-mailpit:8025/api/v1"
KEY = os.environ["GOPHISH_API_KEY"]
H = {"Authorization": f"Bearer {KEY}"}
SEED = int(os.environ.get("SEMENTE", "2026"))
# Perfis de comportamento dos alvos fictícios (probabilidades) - só para exercitar as métricas
COMPORTAMENTO = {"coord.marina": (1.0, 0.9, 0.7, 0.1), "op.joao": (0.9, 0.5, 0.2, 0.3),
                 "tec.rafael": (0.8, 0.2, 0.0, 0.8), "aud.helena": (0.9, 0.1, 0.0, 0.9)}


def api(m, p, **kw):
    r = requests.request(m, GP + p, headers=H, verify=False, timeout=20, **kw)
    if r.status_code >= 300:
        raise SystemExit(f"Gophish {m} {p}: {r.status_code} {r.text[:300]}")
    return r.json()


def nome(base):
    return f"{base} {datetime.now():%Y%m%d-%H%M%S}"


requests.delete(f"{MP}/messages", timeout=10)  # caixa limpa: só mensagens desta campanha
smtp = api("POST", "/smtp/", json={"name": nome("Mailpit lab"), "host": "va-mailpit:1025",
                                   "from_address": "ti@prefeitura-serraclara.example.com",
                                   "ignore_cert_errors": True, "interface_type": "SMTP"})
alvos = [{"first_name": l.split(",")[0], "last_name": l.split(",")[1], "email": l.split(",")[2], "position": l.split(",")[3]}
         for l in open("/app/phishing/alvos_ficticios.csv").read().strip().splitlines()[1:]]
grupo = api("POST", "/groups/", json={"name": nome("Equipe ficticia"), "targets": alvos})
tpl = api("POST", "/templates/", json={"name": nome("Atualizacao obrigatoria (INC-VA-0712)"),
                                       "subject": "URGENTE: atualização obrigatória do acesso ao painel",
                                       "html": open("/app/phishing/modelo_email.html").read()})
pagina = api("POST", "/pages/", json={"name": nome("Portal falso"), "capture_credentials": True,
                                      "capture_passwords": False,
                                      "html": "<html><body><h1>Atualização de acesso</h1><form method='post'>"
                                              "<input name='usuario'><input name='senha' type='password'>"
                                              "<button>Atualizar</button></form></body></html>",
                                      "redirect_url": "http://va-gophish/treinamento"})
camp = api("POST", "/campaigns/", json={"name": nome("GS Vila Aurora - phishing simulado"), "template": {"name": tpl["name"]},
                                        "page": {"name": pagina["name"]}, "smtp": {"name": smtp["name"]},
                                        "url": "http://va-gophish", "groups": [{"name": grupo["name"]}]})
cid = camp["id"]
print(f"campanha {cid} criada; aguardando envio...")
time.sleep(15)

rnd = random.Random(SEED)
msgs = requests.get(f"{MP}/messages", params={"limit": 50}, timeout=10).json()["messages"]
acoes = []
for m in msgs:
    para = m["To"][0]["Address"]
    login = para.split("@")[0]
    if login not in COMPORTAMENTO:
        continue
    corpo = requests.get(f"{MP}/message/{m['ID']}", timeout=10).json()["HTML"]
    url = re.search(r'href=["\'](http://va-gophish[^"\']+)["\']', corpo)
    trk = re.search(r'src=["\'](http://va-gophish/track[^"\']+)["\']', corpo)
    if not url:
        continue
    p_abre, p_clica, p_submete, p_reporta = COMPORTAMENTO[login]
    rid = re.search(r"rid=([^&\"]+)", url.group(1)).group(1)
    a = {"alvo": login}
    if trk and rnd.random() < p_abre:
        requests.get(trk.group(1).replace("&amp;", "&"), timeout=10); a["abriu"] = True
        if rnd.random() < p_clica:
            requests.get(url.group(1), timeout=10); a["clicou"] = True
            if rnd.random() < p_submete:
                # dado FALSO: nunca credencial real; e o Gophish não guarda senha (capture_passwords=false)
                requests.post(url.group(1), data={"usuario": "conta.ficticia", "senha": "nao-e-senha"}, timeout=10)
                a["submeteu"] = True
    if rnd.random() < p_reporta:
        requests.get(f"http://va-gophish/report?rid={rid}", timeout=10); a["reportou"] = True
    acoes.append(a)
time.sleep(3)
res = api("GET", f"/campaigns/{cid}/summary")
st = res["stats"]
n = max(st["total"], 1)
saida = {"campanha": res["name"], "gerado_em": datetime.now().astimezone().isoformat(timespec="seconds"),
         "alvos": st["total"], "enviados": st["sent"], "abertos": st["opened"], "cliques": st["clicked"],
         "dados_submetidos": st["submitted_data"], "reportados": st["email_reported"],
         "taxas_pct": {"abertura": round(100 * st["opened"] / n, 1), "clique": round(100 * st["clicked"] / n, 1),
                       "submissao": round(100 * st["submitted_data"] / n, 1),
                       "reporte": round(100 * st["email_reported"] / n, 1)},
         "comportamento_simulado": acoes,
         "observacao": "alvos FICTÍCIOS da equipe; comportamento simulado com semente fixa; métricas lidas do Gophish"}
os.makedirs("/resultados", exist_ok=True)
arq = f"/resultados/phishing-metricas-{datetime.now():%Y%m%d-%H%M%S}.json"
json.dump(saida, open(arq, "w"), ensure_ascii=False, indent=2)
print(json.dumps(saida, ensure_ascii=False, indent=2))
print("salvo em", arq)

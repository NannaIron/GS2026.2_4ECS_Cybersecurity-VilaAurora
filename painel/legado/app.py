"""Painel de supervisão LEGADO - VULNERÁVEL DE PROPÓSITO (reprodução do INC-VA-0712).

NUNCA use este código fora do laboratório isolado. Falhas intencionais:
  - busca do "histórico de acessos" monta o SQL por CONCATENAÇÃO de string;
  - conexão com o SUPERUSUÁRIO do banco (autocommit, permite consultas empilhadas);
  - mensagens de erro detalhadas (vazam o SQL e a estrutura do banco);
  - não tem login próprio: confia em quem passou pela "VPN legada" (só senha).
"""
import os
import traceback

import psycopg2
from flask import Flask, request

from common.aurora_log import log

app = Flask(__name__)

PAGINA = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Painel Legado</title></head>
<body style="font-family:sans-serif"><h1>Painel Vila Aurora (LEGADO)</h1>
<p><a href="/acessos">Histórico de acessos</a> | <a href="/bomba">Bomba</a></p>{corpo}</body></html>"""


def conn():
    c = psycopg2.connect(host="postgres", dbname="aurora", user="aurora_owner",
                         password=os.environ["POSTGRES_PASSWORD"])
    c.autocommit = True
    return c


@app.get("/")
def inicio():
    return PAGINA.format(corpo="<p>Bem-vindo(a).</p>")


@app.get("/acessos")
def acessos():
    busca = request.args.get("busca", "")
    # VULNERÁVEL: entrada do usuário concatenada direto no SQL
    sql = ("SELECT ts::text, espaco, porta, cracha_pseudo, resultado FROM acessos "
           "WHERE porta LIKE '%" + busca + "%' ORDER BY ts DESC LIMIT 50")
    log("legado_consulta", ip_origem=request.headers.get("X-Forwarded-For", request.remote_addr),
        usuario=request.headers.get("X-Usuario-VPN"), busca=busca, sql=sql)
    try:
        c = conn()
        cur = c.cursor()
        cur.execute(sql)
        linhas = cur.fetchall()
        c.close()
    except Exception as e:
        # VULNERÁVEL: erro detalhado devolvido ao usuário
        return PAGINA.format(corpo=f"<h2>Erro no banco</h2><pre>{e}\n{sql}\n{traceback.format_exc()}</pre>"), 500
    tabela = "".join(f"<tr>{''.join(f'<td>{x}</td>' for x in l)}</tr>" for l in linhas)
    return PAGINA.format(corpo=f"""<form><label>Buscar porta <input name="busca" value=""></label>
        <button>Buscar</button></form><table border=1>{tabela}</table>""")


@app.get("/bomba")
def bomba():
    c = conn()
    cur = c.cursor()
    cur.execute("SELECT espaco, hora_inicio::text, hora_fim::text, atualizado_por FROM agendamento_bomba")
    linhas = cur.fetchall()
    c.close()
    return PAGINA.format(corpo="<table border=1>" + "".join(
        f"<tr>{''.join(f'<td>{x}</td>' for x in l)}</tr>" for l in linhas) + "</table>")

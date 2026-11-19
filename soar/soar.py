"""SOAR-lite: respostas automatizadas da Vila Aurora (RT-15).

BAIXO risco (automático): isolar dispositivo, revogar certificado, encerrar sessão VPN,
bloquear IP, colocar atuador em modo seguro.
ALTO impacto (desligar bomba, liberar portas): NUNCA automático -> cria pedido
'pendente' que só a coordenação aprova no painel, com MFA de novo.
"""
import json
import os
import subprocess
import sys
import threading

import psycopg2

from common.aurora_log import log, agora_utc

BLOQ = os.environ.get("SOAR_BLOQUEIOS", "/soar/bloqueios.json")
PEERS = os.environ.get("WG_PEERS", "/segredos/wg/peers.json")
_lock = threading.Lock()
sys.path.insert(0, "/app/scripts")


def _db():
    return psycopg2.connect(host="postgres", dbname="aurora", user="siem_app",
                            password=os.environ["SIEM_APP_PASSWORD"], connect_timeout=5)


def _bloq():
    try:
        return json.load(open(BLOQ))
    except Exception:
        return {"ips": [], "usuarios": [], "peers": []}


def _salvar(b):
    os.makedirs(os.path.dirname(BLOQ), exist_ok=True)
    tmp = BLOQ + ".tmp"
    json.dump(b, open(tmp, "w"), indent=2)
    os.replace(tmp, BLOQ)


def _registro(acao, ok, **k):
    return log("soar_acao", "warning", acao=acao, sucesso=ok, risco="baixo", automatica=True, **k)


def em_excecao(ip):
    """Janela de pentest autorizado (ex.: reteste do SQLi): detecta, mas não bloqueia."""
    try:
        exc = json.load(open(os.path.join(os.path.dirname(BLOQ), "excecoes.json")))
        import time
        return ip in exc.get("ips", []) and time.time() < exc.get("expira_em", 0)
    except Exception:
        return False


def em_observacao():
    """Modo observação (só para demonstrar o LEGADO como era: sem resposta automática).
    O SIEM continua detectando e registrando; as ações ficam marcadas como NÃO executadas."""
    try:
        import time
        return time.time() < json.load(open(os.path.join(os.path.dirname(BLOQ), "observacao.json")))["expira_em"]
    except Exception:
        return False


def _obs(acao, **k):
    log("soar_modo_observacao", "warning", acao=acao, **k)
    return {"acao": f"{acao}(modo observação: NÃO executada)", "ts": agora_utc(), "ok": True, **k}


def bloquear_ip(ip, motivo):
    if em_observacao():
        return _obs("bloquear_ip", ip=ip)
    if em_excecao(ip):
        log("soar_excecao_pentest", "warning", ip=ip, motivo=motivo)
        return {"acao": "bloquear_ip(exceção: pentest autorizado)", "ip": ip, "ts": agora_utc(), "ok": True}
    with _lock:
        b = _bloq()
        if ip in b["ips"]:
            return {"acao": "bloquear_ip", "ip": ip, "ts": agora_utc(), "ok": True, "ja_bloqueado": True}
        b["ips"].append(ip)
        _salvar(b)
    r = subprocess.run(["iptables", "-A", "BLOQUEIO_SOAR", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
    _registro("bloquear_ip", True, ip=ip, motivo=motivo, iptables_ok=r.returncode == 0)
    return {"acao": "bloquear_ip", "ip": ip, "ts": agora_utc(), "ok": True}


def encerrar_sessao_vpn(usuario=None, peer_nome=None, motivo=""):
    if em_observacao():
        return _obs("encerrar_sessao_vpn", usuario=usuario, peer=peer_nome)
    ok = True
    with _lock:
        b = _bloq()
        if usuario and usuario not in b["usuarios"]:
            b["usuarios"].append(usuario)
        _salvar(b)
    if peer_nome:
        peers = json.load(open(PEERS))
        for pub, p in peers.items():
            if p["nome"] == peer_nome:
                r = subprocess.run(["wg", "set", "wg0", "peer", pub, "remove"], capture_output=True, text=True)
                ok = r.returncode == 0
    _registro("encerrar_sessao_vpn", ok, usuario=usuario, peer=peer_nome, motivo=motivo)
    return {"acao": "encerrar_sessao_vpn", "usuario": usuario, "peer": peer_nome, "ts": agora_utc(), "ok": ok}


def isolar_dispositivo(cn, motivo):
    """Revoga o certificado (CRL) e tira o CN da ACL; o broker recarrega e derruba a sessão."""
    import pki  # scripts/pki.py
    try:
        if cn in pki.isolados():
            return {"acao": "isolar_dispositivo", "cn": cn, "ts": agora_utc(), "ok": True, "ja_isolado": True}
        pki.isolar(cn)
        ok = True
    except SystemExit as e:
        ok = False
        log("soar_erro", "error", acao="isolar_dispositivo", cn=cn, erro=str(e)[:300])
    _registro("isolar_dispositivo+revogar_certificado", ok, dispositivo=cn, motivo=motivo)
    return {"acao": "isolar_dispositivo+revogar_certificado", "cn": cn, "ts": agora_utc(), "ok": ok}


def modo_seguro(alvo, motivo):
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT id FROM comandos_borda WHERE acao='modo_seguro' AND status='aprovado' AND alvo=%s", (alvo,))
        if not cur.fetchone():
            cur.execute("INSERT INTO comandos_borda (acao, alvo, risco, status, solicitado_por, motivo, aprovado_por, "
                        "aprovado_em) VALUES ('modo_seguro', %s, 'baixo', 'aprovado', 'soar', %s, "
                        "'automatico-baixo-risco', now())", (alvo, motivo[:200]))
    _registro("modo_seguro_atuador", True, alvo=alvo, motivo=motivo)
    return {"acao": "modo_seguro_atuador", "alvo": alvo, "ts": agora_utc(), "ok": True}


def solicitar_aprovacao(acao, alvo, motivo):
    """Ação de ALTO impacto: só cria o pedido. Execução depende de decisão humana."""
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT id FROM comandos_borda WHERE acao=%s AND status='pendente'", (acao,))
        if cur.fetchone():
            return {"acao": f"pedido_aprovacao:{acao}", "ts": agora_utc(), "ok": True, "ja_pendente": True}
        cur.execute("INSERT INTO comandos_borda (acao, alvo, risco, status, solicitado_por, motivo) "
                    "VALUES (%s, %s, 'alto', 'pendente', 'soar', %s) RETURNING id", (acao, alvo, motivo[:200]))
        cid = cur.fetchone()[0]
    log("soar_pedido_aprovacao_humana", "warning", acao=acao, alvo=alvo, comando=cid, risco="alto", motivo=motivo)
    return {"acao": f"pedido_aprovacao:{acao}", "comando": cid, "ts": agora_utc(), "ok": True}

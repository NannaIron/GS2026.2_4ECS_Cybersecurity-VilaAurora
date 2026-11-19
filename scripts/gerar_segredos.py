#!/usr/bin/env python3
"""Gera TODOS os segredos do laboratório no momento do setup (nada disso vai para o Git):

  .env                      senhas do banco, chave de sessão, chave de pseudonimização
  segredos/usuarios.json    contas fictícias dos operadores (senha + semente TOTP)
  segredos/seed.sql         carga sintética do banco (usuários, histórico de acessos)
  segredos/wg/*.conf        configurações WireGuard (nuvem, borda, operadores)

Todos os dados pessoais são SINTÉTICOS (LGPD). Roda dentro do container.
"""
import hashlib
import hmac
import json
import os
import random
import secrets
import subprocess
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash
import pyotp

REPO = os.environ.get("REPO", "/repo")
SEG = os.path.join(REPO, "segredos")
WG = os.path.join(SEG, "wg")
HOST_UID = int(os.environ.get("HOST_UID", "0"))
HOST_GID = int(os.environ.get("HOST_GID", "0"))

NUVEM_WAN_IP = "172.31.0.10"


def senha(n=20):
    return secrets.token_urlsafe(n)


def gerar_env():
    p = os.path.join(REPO, ".env")
    if os.path.exists(p):
        print("[segredos] .env já existe, mantendo")
        return dict(l.strip().split("=", 1) for l in open(p) if "=" in l and not l.startswith("#"))
    env = {
        "HOST_UID": str(HOST_UID), "HOST_GID": str(HOST_GID),
        "POSTGRES_PASSWORD": senha(),          # superusuário (só o painel LEGADO usa - de propósito)
        "PAINEL_APP_PASSWORD": senha(),        # painel seguro: privilégio mínimo
        "INGEST_APP_PASSWORD": senha(),        # API de ingestão da borda
        "SIEM_APP_PASSWORD": senha(),          # SIEM/SOAR
        "FLASK_SECRET": secrets.token_hex(32),
        "PSEUDO_KEY": secrets.token_hex(32),   # HMAC para pseudonimizar crachás
        "TZ": "America/Sao_Paulo",
    }
    with open(p, "w") as f:
        f.write("# GERADO por scripts/setup.sh - NÃO VERSIONAR\n")
        for k, v in env.items():
            f.write(f"{k}={v}\n")
    print("[segredos] .env gerado")
    return env


USUARIOS_OPERADORES = [
    # login, nome (fictício), perfil
    ("coord.marina", "Marina Coordenadora (FICTÍCIA)", "coordenacao"),
    ("op.joao", "João Operador (FICTÍCIO)", "operador"),
    ("tec.rafael", "Rafael Técnico (FICTÍCIO)", "tecnico"),
    ("aud.helena", "Helena Auditora (FICTÍCIA)", "auditor"),
]
NOMES = ["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fábio", "Gabriela", "Hugo", "Iara", "Jorge",
         "Kátia", "Leandro", "Mirela", "Nilton", "Olívia", "Paulo", "Quitéria", "Renato", "Sílvia", "Tadeu"]
SOBRENOMES = ["Silvério", "Aurora", "Serraclara", "Fictício", "Exemplo", "Teste", "Sintético", "Modelo"]


def gerar_usuarios(env):
    p = os.path.join(SEG, "usuarios.json")
    if os.path.exists(p):
        print("[segredos] usuarios.json já existe, mantendo")
        return json.load(open(p))
    rnd = random.Random(712)
    us = []
    for login, nome, perfil in USUARIOS_OPERADORES:
        us.append({"login": login, "nome": nome, "perfil": perfil, "senha": senha(12),
                   "totp": pyotp.random_base32(), "email": f"{login}@vilaaurora.example",
                   "telefone": f"(11) 90000-{rnd.randint(1000, 9999)}"})
    # voluntários e moradores sintéticos (não têm acesso ao painel; são o alvo do vazamento)
    for i in range(20):
        n = f"{rnd.choice(NOMES)} {rnd.choice(SOBRENOMES)}"
        login = f"vol.{i:02d}"
        us.append({"login": login, "nome": n + " (FICTÍCIO)", "perfil": "voluntario", "senha": senha(12),
                   "totp": None, "email": f"{login}@vilaaurora.example",
                   "telefone": f"(11) 90000-{rnd.randint(1000, 9999)}"})
    json.dump(us, open(p, "w"), ensure_ascii=False, indent=2)
    print("[segredos] usuarios.json gerado (contas fictícias)")
    return us


def pseudo(key, cracha):
    return hmac.new(key.encode(), cracha.encode(), hashlib.sha256).hexdigest()[:16]


def q(s):
    return "NULL" if s is None else "'" + str(s).replace("'", "''") + "'"


def gerar_seed(env, us):
    rnd = random.Random(99639)
    L = ["-- GERADO por scripts/gerar_segredos.py - dados 100% sintéticos", "BEGIN;"]
    for u in us:
        md5 = hashlib.md5(u["senha"].encode()).hexdigest()  # legado: MD5 sem sal (vulnerável, de propósito)
        L.append("INSERT INTO usuarios (login,nome,email,telefone,perfil,senha_hash,senha_md5_legado,totp_secret,ativo) "
                 f"VALUES ({q(u['login'])},{q(u['nome'])},{q(u['email'])},{q(u['telefone'])},{q(u['perfil'])},"
                 f"{q(generate_password_hash(u['senha'], method='pbkdf2:sha256:600000'))},{q(md5)},{q(u['totp'])},true);")
    espacos = {"escola": ["portao", "cozinha"], "ubs": ["entrada", "camara-fria"], "abrigo": ["entrada", "deposito"],
               "centro": ["entrada", "sala-tecnica"], "horta": ["portao"]}
    inicio = datetime.now() - timedelta(days=30)
    for i in range(300):
        esp = rnd.choice(list(espacos))
        porta = rnd.choice(espacos[esp])
        ts = inicio + timedelta(minutes=rnd.randint(0, 30 * 24 * 60))
        cracha = f"CRACHA-{rnd.randint(1, 40):04d}"
        perfil = rnd.choice(["voluntario", "voluntario", "tecnico", "saude", "operador"])
        res = "negado" if rnd.random() < 0.06 else "liberado"
        L.append("INSERT INTO acessos (ts,espaco,porta,cracha_pseudo,perfil,resultado) VALUES "
                 f"({q(ts.isoformat(timespec='seconds'))},{q(esp)},{q(porta)},{q(pseudo(env['PSEUDO_KEY'], cracha))},"
                 f"{q(perfil)},{q(res)});")
    L.append("COMMIT;")
    open(os.path.join(SEG, "seed.sql"), "w").write("\n".join(L) + "\n")
    print("[segredos] seed.sql gerado")


def wg_par(nome):
    k = os.path.join(WG, f"{nome}.key")
    if not os.path.exists(k):
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
        open(k, "w").write(priv + "\n")
    priv = open(k).read().strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub


def psk(nome):
    p = os.path.join(WG, f"{nome}.psk")
    if not os.path.exists(p):
        open(p, "w").write(subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True).stdout)
    return open(p).read().strip()


def gerar_wg():
    os.makedirs(WG, exist_ok=True)
    n_priv, n_pub = wg_par("nuvem")
    # pares: nome, IP no túnel (segmento), endpoint visto do par
    pares = [("borda-vila", "10.10.1.2", f"{NUVEM_WAN_IP}:51820"),       # segmento BORDAS 10.10.1.0/24
             ("operador-lab", "10.10.2.11", f"{NUVEM_WAN_IP}:51820"),    # segmento OPERADORES 10.10.2.0/24
             ("operador-host", "10.10.2.10", "127.0.0.1:51820")]         # notebook do host (wg-quick)
    nuvem = ["# Gerado - servidor WireGuard da nuvem (ChaCha20-Poly1305 / Curve25519 + PSK)",
             "[Interface]", f"PrivateKey = {n_priv}", "ListenPort = 51820", ""]
    peers_json = {}
    for nome, ip, endpoint in pares:
        priv, pub = wg_par(nome)
        k = psk(nome)
        nuvem += [f"# {nome}", "[Peer]", f"PublicKey = {pub}", f"PresharedKey = {k}", f"AllowedIPs = {ip}/32", ""]
        peers_json[pub] = {"nome": nome, "ip": ip}
        cli = ["# Gerado - cliente WireGuard: " + nome, "[Interface]", f"PrivateKey = {priv}", f"Address = {ip}/32", "",
               "[Peer]", f"PublicKey = {n_pub}", f"PresharedKey = {k}", f"Endpoint = {endpoint}",
               "AllowedIPs = 10.10.0.1/32", "PersistentKeepalive = 15", ""]
        open(os.path.join(WG, f"{nome}.conf"), "w").write("\n".join(cli))
    open(os.path.join(WG, "nuvem.conf"), "w").write("\n".join(nuvem))
    json.dump(peers_json, open(os.path.join(WG, "peers.json"), "w"), indent=2)
    print("[segredos] chaves e configurações WireGuard geradas")


def gerar_dkim():
    d = os.path.join(SEG, "dkim")
    os.makedirs(d, exist_ok=True)
    k = os.path.join(d, "s1.key")
    if not os.path.exists(k):
        subprocess.run(["openssl", "genrsa", "-out", k, "2048"], check=True, capture_output=True)
    pub = subprocess.run(["openssl", "rsa", "-in", k, "-pubout", "-outform", "DER"], check=True,
                         capture_output=True).stdout
    import base64
    rec = f's1._domainkey.vilaaurora.example. IN TXT "v=DKIM1; k=rsa; p={base64.b64encode(pub).decode()}"\n'
    open(os.path.join(d, "s1._domainkey.txt"), "w").write(rec)
    print("[segredos] chave DKIM (seletor s1) gerada")


def main():
    os.makedirs(SEG, exist_ok=True)
    gerar_dkim()
    env = gerar_env()
    us = gerar_usuarios(env)
    gerar_seed(env, us)
    gerar_wg()
    for raiz, dirs, arqs in os.walk(SEG):
        for n in dirs + arqs:
            os.chown(os.path.join(raiz, n), HOST_UID, HOST_GID)
    os.chown(os.path.join(REPO, ".env"), HOST_UID, HOST_GID)
    for raiz, _, arqs in os.walk(WG):
        for a in arqs:
            os.chmod(os.path.join(raiz, a), 0o600)


if __name__ == "__main__":
    main()

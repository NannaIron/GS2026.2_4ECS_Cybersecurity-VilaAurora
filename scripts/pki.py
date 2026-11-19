#!/usr/bin/env python3
"""PKI própria da Vila Aurora (OpenSSL): CA, certificados X.509 por dispositivo,
revogação (CRL), rotação e ACL do broker MQTT.

Roda dentro do container (make pki-...), nunca precisa de OpenSSL no host.
Uso:
  python3 scripts/pki.py init                 # cria CA + certificados de todos os dispositivos
  python3 scripts/pki.py emitir <CN>          # emite (ou reemite) certificado para um CN
  python3 scripts/pki.py revogar <CN> [motivo]# revoga o certificado atual e publica nova CRL
  python3 scripts/pki.py rotacionar <CN>      # emite novo par de chaves e revoga o antigo
  python3 scripts/pki.py isolar <CN>          # revoga + remove o CN da ACL (isolamento)
  python3 scripts/pki.py reabilitar <CN>      # após investigação: novo certificado + volta à ACL
  python3 scripts/pki.py listar               # mostra o index da CA (V=válido, R=revogado)
"""
import os
import shutil
import subprocess
import sys

BASE = os.environ.get("PKI_DIR", "/repo/pki")
CA = os.path.join(BASE, "ca")
BROKER = os.path.join(BASE, "broker")
DISP = os.path.join(BASE, "dispositivos")
HOST_UID = int(os.environ.get("HOST_UID", "0"))
HOST_GID = int(os.environ.get("HOST_GID", "0"))
MOSQ_GID = 1883  # grupo do usuário mosquitto na imagem eclipse-mosquitto

# Um certificado por dispositivo (RT-04: proibido segredo compartilhado).
# CN -> lista de (permissão, tópico) usada para gerar a ACL do broker.
DISPOSITIVOS = {
    "escola-nivel-01":      [("write", "vila/escola/agua/nivel"), ("read", "vila/escola/bomba/estado")],
    "escola-bomba-01":      [("read", "vila/escola/bomba/cmd"), ("write", "vila/escola/bomba/estado")],
    "ubs-camarafria-01":    [("write", "vila/ubs/camarafria/temp")],
    "abrigo-alagamento-01": [("write", "vila/abrigo/alagamento")],
    "abrigo-porta-01":      [("read", "vila/abrigo/porta/cmd"), ("write", "vila/abrigo/porta/estado"),
                             ("write", "vila/abrigo/porta/acesso")],
    "centro-energia-01":    [("write", "vila/centro/energia")],
    "horta-umidade-01":     [("write", "vila/horta/solo/umidade")],
    # serviço de regras locais do nó de borda
    "borda-regras":         [("readwrite", "vila/#")],
    # usado só pelos testes de mTLS (pode ser revogado à vontade)
    "teste-dispositivo-01": [("write", "vila/teste/#")],
}

OPENSSL_CNF = """
[ ca ]
default_ca = aurora_ca
[ aurora_ca ]
dir               = $ENV::PKI_CA_DIR
database          = $dir/index.txt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
new_certs_dir     = $dir/emitidos
certificate       = $dir/ca.crt
private_key       = $dir/ca.key
default_md        = sha256
default_days      = 365
default_crl_days  = 7
policy            = politica
unique_subject    = no
copy_extensions   = copy
[ politica ]
commonName        = supplied
organizationName  = optional
organizationalUnitName = optional
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = placeholder
[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_disp ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_servidor ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def sh(*args, **kw):
    r = subprocess.run(list(args), capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise SystemExit(f"[pki] falhou: {' '.join(args)}\n{r.stderr}")
    return r.stdout


os.environ["PKI_CA_DIR"] = CA   # o openssl.cnf usa caminho relativo ao ambiente (funciona no host e no SIEM)


def cnf():
    p = os.path.join(CA, "openssl.cnf")
    if os.path.isdir(CA):
        with open(p, "w") as f:
            f.write(OPENSSL_CNF)
    return p


def ajustar_permissoes():
    """Arquivos ficam do usuário do host; chave do broker legível pelo grupo mosquitto."""
    for raiz, dirs, arqs in os.walk(BASE):
        for n in dirs + arqs:
            p = os.path.join(raiz, n)
            try:
                os.chown(p, HOST_UID, HOST_GID)
            except OSError:
                pass
            if n.endswith(".key"):
                os.chmod(p, 0o600)
    bk = os.path.join(BROKER, "broker.key")
    if os.path.exists(bk):
        os.chown(bk, HOST_UID, MOSQ_GID)
        os.chmod(bk, 0o640)


def init():
    if os.path.exists(os.path.join(CA, "ca.key")):
        print("[pki] CA já existe, mantendo (apague pki/ para recriar).")
    else:
        os.makedirs(os.path.join(CA, "emitidos"), exist_ok=True)
        open(os.path.join(CA, "index.txt"), "w").close()
        with open(os.path.join(CA, "serial"), "w") as f:
            f.write("1000\n")
        with open(os.path.join(CA, "crlnumber"), "w") as f:
            f.write("1000\n")
        # CA com curva elíptica P-256 (ECDSA), validade de 3 anos
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{CA}/ca.key")
        sh("openssl", "req", "-x509", "-new", "-key", f"{CA}/ca.key", "-sha256", "-days", "1095",
           "-subj", "/O=Rede Comunitaria Vila Aurora (FICTICIA)/CN=Vila Aurora CA Raiz",
           "-config", cnf(), "-extensions", "v3_ca", "-out", f"{CA}/ca.crt")
        print("[pki] CA criada.")
    os.makedirs(BROKER, exist_ok=True)
    os.makedirs(DISP, exist_ok=True)
    shutil.copy(f"{CA}/ca.crt", f"{BROKER}/ca.crt")
    servidor("broker", "mqtt.borda.vilaaurora.example", ["DNS:mosquitto", "DNS:mqtt.borda.vilaaurora.example"],
             BROKER)
    servidor("painel", "painel.vilaaurora.example",
             ["DNS:painel.vilaaurora.example", "IP:10.10.0.1"], os.path.join(BASE, "painel"))
    for cn in DISPOSITIVOS:
        if not os.path.exists(os.path.join(DISP, cn, "cliente.crt")):
            emitir(cn, publicar=False)
    gerar_crl()
    gerar_acl()
    ajustar_permissoes()


def servidor(nome, cn, sans, destino):
    os.makedirs(destino, exist_ok=True)
    crt = os.path.join(destino, f"{nome}.crt")
    if os.path.exists(crt):
        return
    key = os.path.join(destino, f"{nome}.key")
    csr = os.path.join(destino, f"{nome}.csr")
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    sh("openssl", "req", "-new", "-key", key, "-subj", f"/O=Vila Aurora/CN={cn}",
       "-addext", "subjectAltName=" + ",".join(sans), "-out", csr)
    sh("openssl", "ca", "-batch", "-config", cnf(), "-extensions", "v3_servidor", "-days", "365",
       "-in", csr, "-out", crt, "-notext")
    os.remove(csr)
    shutil.copy(f"{CA}/ca.crt", os.path.join(destino, "ca.crt"))
    print(f"[pki] certificado de servidor emitido: {cn}")


def serial_atual(cn):
    crt = os.path.join(DISP, cn, "cliente.crt")
    if not os.path.exists(crt):
        return None
    return sh("openssl", "x509", "-in", crt, "-noout", "-serial").strip().split("=")[1]


def emitir(cn, publicar=True):
    d = os.path.join(DISP, cn)
    os.makedirs(d, exist_ok=True)
    key, csr, crt = f"{d}/cliente.key.novo", f"{d}/cliente.csr", f"{d}/cliente.crt.novo"
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    sh("openssl", "req", "-new", "-key", key, "-subj", f"/O=Vila Aurora/OU=dispositivos/CN={cn}", "-out", csr)
    sh("openssl", "ca", "-batch", "-config", cnf(), "-extensions", "v3_disp", "-days", "90",
       "-in", csr, "-out", crt, "-notext")
    os.remove(csr)
    os.replace(key, f"{d}/cliente.key")
    os.replace(crt, f"{d}/cliente.crt")
    shutil.copy(f"{CA}/ca.crt", f"{d}/ca.crt")
    print(f"[pki] certificado emitido para {cn} (serial {serial_atual(cn)}, validade 90 dias)")
    if publicar:
        ajustar_permissoes()


def revogar(cn, motivo="keyCompromise", serial=None):
    serial = serial or serial_atual(cn)
    if not serial:
        raise SystemExit(f"[pki] {cn} não tem certificado")
    arq = os.path.join(CA, "emitidos", f"{serial}.pem")
    r = subprocess.run(["openssl", "ca", "-config", cnf(), "-revoke", arq, "-crl_reason", motivo],
                       capture_output=True, text=True)
    if r.returncode != 0 and "Already revoked" not in r.stderr + r.stdout:
        raise SystemExit(r.stderr)
    gerar_crl()
    ajustar_permissoes()
    print(f"[pki] {cn} serial {serial} REVOGADO ({motivo}); CRL publicada")


def rotacionar(cn):
    antigo = serial_atual(cn)
    emitir(cn, publicar=False)
    if antigo:
        revogar(cn, "superseded", serial=antigo)
    print(f"[pki] rotação concluída para {cn}: {antigo} -> {serial_atual(cn)}")


def isolar(cn):
    with open(os.path.join(BASE, "isolados.txt"), "a") as f:
        f.write(cn + "\n")
    gerar_acl()
    revogar(cn, "keyCompromise")


def reabilitar(cn):
    """Depois da investigação: volta o CN para a ACL com um certificado NOVO (o antigo segue revogado)."""
    if cn not in isolados():
        raise SystemExit(f"[pki] {cn} não está isolado. Isolados agora: {', '.join(sorted(isolados())) or 'nenhum'}")
    p = os.path.join(BASE, "isolados.txt")
    restantes = [x for x in isolados() if x != cn]
    open(p, "w").write("\n".join(restantes) + ("\n" if restantes else ""))
    rotacionar(cn)   # certificado novo; o anterior fica revogado
    gerar_acl()
    ajustar_permissoes()
    print(f"[pki] {cn} reabilitado com novo certificado (serial {serial_atual(cn)})")


def isolados():
    p = os.path.join(BASE, "isolados.txt")
    return set(open(p).read().split()) if os.path.exists(p) else set()


def gerar_crl():
    sh("openssl", "ca", "-config", cnf(), "-gencrl", "-out", f"{BROKER}/crl.pem.novo")
    # broker usa CA + CRL concatenados? Não: Mosquitto aceita crlfile separado.
    os.replace(f"{BROKER}/crl.pem.novo", f"{BROKER}/crl.pem")


def gerar_acl():
    iso = isolados()
    linhas = ["# Gerado por scripts/pki.py - ACL por identidade (CN do certificado)",
              "# Dispositivos isolados pelo SOAR não aparecem aqui."]
    for cn, regras in DISPOSITIVOS.items():
        if cn in iso:
            linhas.append(f"# {cn}: ISOLADO")
            continue
        linhas.append(f"user {cn}")
        linhas += [f"topic {perm} {top}" for perm, top in regras]
        linhas.append("")
    os.makedirs(BROKER, exist_ok=True)
    with open(f"{BROKER}/acl.novo", "w") as f:
        f.write("\n".join(linhas) + "\n")
    os.replace(f"{BROKER}/acl.novo", f"{BROKER}/acl")


def listar():
    print(open(os.path.join(CA, "index.txt")).read())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd, args = sys.argv[1], sys.argv[2:]
    {"init": init, "emitir": emitir, "revogar": revogar, "rotacionar": rotacionar,
     "isolar": isolar, "reabilitar": reabilitar, "listar": listar, "crl": gerar_crl, "acl": gerar_acl}[cmd](*args)

"""Cliente mínimo do painel seguro (login com senha + TOTP) usado pelos testes."""
import json
import re

import pyotp
import requests

BASE = "https://10.10.0.1:8443"
CA = "/pki/ca.crt"
US = {u["login"]: u for u in json.load(open("/segredos/usuarios.json"))}


def entrar(login):
    s = requests.Session()
    tok = re.search(r'name="csrf" value="([^"]+)"', s.get(f"{BASE}/login", verify=CA).text).group(1)
    s.post(f"{BASE}/login", data={"usuario": login, "senha": US[login]["senha"], "csrf": tok}, verify=CA)
    tok = re.search(r'name="csrf" value="([^"]+)"', s.get(f"{BASE}/mfa", verify=CA).text).group(1)
    s.post(f"{BASE}/mfa", data={"codigo": pyotp.TOTP(US[login]["totp"]).now(), "csrf": tok}, verify=CA)
    return s

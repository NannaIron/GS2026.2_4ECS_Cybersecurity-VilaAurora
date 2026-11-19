#!/usr/bin/env python3
"""Mostra o código TOTP atual de uma conta FICTÍCIA do laboratório (substitui o app autenticador
na demonstração). Também imprime a URI otpauth:// para cadastrar no Google Authenticator/Aegis.
uso: python3 scripts/totp.py coord.marina"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import time

login = sys.argv[1] if len(sys.argv) > 1 else "coord.marina"
u = {x["login"]: x for x in json.load(open("segredos/usuarios.json"))}[login]
seg = u["totp"]
k = base64.b32decode(seg + "=" * (-len(seg) % 8))
h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = h[-1] & 15
cod = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"usuário: {login}  perfil: {u['perfil']}  senha: {u['senha']}")
print(f"código TOTP agora: {cod:06d}  (válido por mais {30 - int(time.time()) % 30}s)")
print(f"otpauth://totp/VilaAurora:{login}?secret={seg}&issuer=VilaAurora")

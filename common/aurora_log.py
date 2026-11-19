"""Log estruturado (JSON Lines) comum a todos os serviços da Vila Aurora.

Cada evento vai para stdout (docker logs) e para /logs/<servico>.jsonl, um volume
coletado pelo SIEM. Os horários são ISO 8601 em UTC com milissegundos, para que a
linha do tempo forense não dependa do fuso de cada máquina (relógio vem do host,
sincronizado por NTP - ver README).
"""
import json
import os
import socket
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
LOG_DIR = os.environ.get("LOG_DIR", "/logs")
SERVICO = os.environ.get("SERVICO", "desconhecido")


def agora_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento: str, nivel: str = "info", **campos):
    reg = {"ts": agora_utc(), "servico": SERVICO, "host": socket.gethostname(),
           "nivel": nivel, "evento": evento}
    reg.update(campos)
    linha = json.dumps(reg, ensure_ascii=False, default=str)
    with _lock:
        print(linha, flush=True)
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(os.path.join(LOG_DIR, f"{SERVICO}.jsonl"), "a", encoding="utf-8") as f:
                f.write(linha + "\n")
        except OSError:
            pass
    return reg

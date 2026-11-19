#!/usr/bin/env python3
"""Métricas do RT-22: disponibilidade, MTTD, MTTR, operação autônoma, perda na
reconciliação e consumo (CPU, memória, banda, energia estimada) do nó de borda.
Usa só a biblioteca padrão do Python + docker CLI.
uso: python3 scripts/metricas.py [segundos_de_amostragem=60]
"""
import glob
import json
import re
import statistics as stt
import subprocess
import sys
import time
from datetime import datetime, timezone

JANELA = int(sys.argv[1]) if len(sys.argv) > 1 else 60
CONT = ["va-borda", "va-mosquitto", "va-sensores", "va-nuvem-gw", "va-painel-seguro", "va-nuvem-api",
        "va-siem", "va-postgres"]
TS = datetime.now().strftime("%Y%m%d-%H%M%S")


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout.strip()


def mib(s):
    m = re.match(r"([\d.]+)\s*([KMG]i?B|B)", s)
    if not m:
        return 0.0
    v, u = float(m.group(1)), m.group(2)
    return v * {"B": 1 / 2 ** 20, "KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}.get(u, 1)


def wg_bytes():
    out = sh("docker exec va-borda wg show wg0 transfer")
    p = out.split()
    return (int(p[1]), int(p[2])) if len(p) >= 3 else (0, 0)


def iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


print(f"== Amostrando consumo por {JANELA}s ...")
amostras = {c: [] for c in CONT}
rx0, tx0 = wg_bytes()
t0 = time.time()
while time.time() - t0 < JANELA:
    for l in sh("docker stats --no-stream --format '{{json .}}' " + " ".join(CONT)).splitlines():
        d = json.loads(l)
        amostras[d["Name"]].append((float(d["CPUPerc"].rstrip("%")), mib(d["MemUsage"].split("/")[0])))
    time.sleep(3)
rx1, tx1 = wg_bytes()
dt = time.time() - t0
consumo = {}
for c, a in amostras.items():
    if a:
        consumo[c] = {"cpu_pct_media": round(stt.mean(x[0] for x in a), 2), "cpu_pct_max": round(max(x[0] for x in a), 2),
                      "mem_mib_media": round(stt.mean(x[1] for x in a), 1), "amostras": len(a)}
borda_cpu = consumo.get("va-borda", {}).get("cpu_pct_media", 0) + consumo.get("va-mosquitto", {}).get("cpu_pct_media", 0)
# Energia: modelo linear de um Raspberry Pi 4 (2,7 W ocioso, 6,4 W com 4 núcleos a 100%) - ESTIMATIVA
energia_w = 2.7 + (6.4 - 2.7) * min(borda_cpu / 400, 1)
banda = {"tunel_wg_tx_kbps": round((tx1 - tx0) * 8 / dt / 1000, 2), "tunel_wg_rx_kbps": round((rx1 - rx0) * 8 / dt / 1000, 2),
         "tx_mb_por_dia_projetado": round((tx1 - tx0) / dt * 86400 / 1e6, 1)}

# ---- disponibilidade do link e operação autônoma (logs da borda)
evs = [json.loads(l) for l in sh("docker exec va-siem cat /logs/borda.jsonl").splitlines() if l.startswith("{")]
ini, fim = iso(evs[0]["ts"]), datetime.now(timezone.utc)
off, caiu = 0.0, None
quedas = 0
for e in evs:
    if e["evento"] == "wan_link_caiu" and caiu is None:
        caiu, quedas = iso(e["ts"]), quedas + 1
    elif e["evento"] in ("wan_link_voltou", "wan_link_ok") and caiu:
        off += (iso(e["ts"]) - caiu).total_seconds()
        caiu = None
if caiu:
    off += (fim - caiu).total_seconds()
total = (fim - ini).total_seconds()
alarmes_offline = sum(1 for e in evs if e["evento"] == "alarme_local" and e.get("link_wan") is False)
reiniciou = sh("docker inspect -f '{{.RestartCount}}' va-borda")
# disponibilidade das funções locais: a borda processou leituras em todos os minutos da janela?
minutos = {e["ts"][:16] for e in evs if e["evento"] in ("borda_status",)} or set()
st = json.loads(sh("docker exec va-borda cat /data/status.json"))

# ---- MTTD / MTTR (alertas do SIEM)
alertas = [a for a in (json.loads(l) for l in sh("docker exec va-siem cat /logs/central/alertas.jsonl").splitlines()
                       if l.startswith("{")) if not a.get("retroativo")]
por_regra = {}
for a in alertas:
    r = por_regra.setdefault(a["regra"], {"n": 0, "mttd": [], "mttr": []})
    r["n"] += 1
    if a.get("mttd_s") is not None:
        r["mttd"].append(a["mttd_s"])
    if a.get("mttr_s") is not None:
        r["mttr"].append(a["mttr_s"])
mt = {k: {"alertas": v["n"], "mttd_medio_s": round(stt.mean(v["mttd"]), 3) if v["mttd"] else None,
          "mttr_medio_s": round(stt.mean(v["mttr"]), 3) if v["mttr"] else None} for k, v in por_regra.items()}
todos_d = [a["mttd_s"] for a in alertas if a.get("mttd_s") is not None]
todos_r = [a["mttr_s"] for a in alertas if a.get("mttr_s") is not None]

caos = sorted(glob.glob("resultados/caos-*/resultado.json"))
caos_res = json.load(open(caos[-1])) if caos else None

res = {
    "gerado_em": datetime.now().astimezone().isoformat(timespec="seconds"),
    "janela_observacao_h": round(total / 3600, 2),
    "disponibilidade": {
        "link_nuvem_pct": round(100 * (1 - off / total), 3) if total else None,
        "quedas_wan": quedas, "tempo_offline_s": round(off, 1),
        "funcoes_locais_borda_pct": 100.0 if reiniciou == "0" else f"ver RestartCount={reiniciou}",
        "obs": "funções locais = regras/alarmes/bomba na borda; seguem ativas sem a nuvem (ver teste de caos)"},
    "deteccao_resposta": {"alertas_total": len(alertas), "mttd_medio_s": round(stt.mean(todos_d), 3) if todos_d else None,
                          "mttr_medio_s_respostas_automaticas": round(stt.mean(todos_r), 3) if todos_r else None,
                          "por_regra": mt,
                          "obs": "MTTD = detecção - evento; MTTR = contenção automática concluída - evento. "
                                 "Ações de alto impacto dependem do tempo de decisão humana (não incluídas)."},
    "continuidade": {"ultimo_teste_caos": caos_res, "alarmes_locais_sem_internet_total": alarmes_offline,
                     "buffer_pendente_agora": st["pendentes"], "mensagens_geradas_total": st["gerados"]},
    "consumo": consumo,
    "borda_estimada": {"cpu_pct_borda+broker": round(borda_cpu, 2), "energia_w_estimada_rpi4": round(energia_w, 2),
                       "energia_kwh_mes_estimada": round(energia_w * 24 * 30 / 1000, 2), **banda,
                       "obs": "CPU/memória medidas com docker stats; energia é ESTIMATIVA por modelo linear do Raspberry Pi 4"},
}
nome = f"resultados/metricas-{TS}.json"
json.dump(res, open(nome, "w"), ensure_ascii=False, indent=2)
print(json.dumps(res, ensure_ascii=False, indent=2))
print(f"\nSalvo em {nome}")

#!/usr/bin/env python3
"""Teste de CAOS controlado (RT-23): derruba o link WAN da borda por N minutos.

O "link WAN" é a conexão do container va-borda com a rede seg_wan (por onde passa o
túnel WireGuard). Durante a queda, provoca uma falha na câmara fria da UBS para
mostrar o alarme LOCAL funcionando sem internet. Ao final reconecta, espera a
sincronização e mede a perda de dados na reconciliação.

uso: python3 scripts/caos.py [minutos=30]   (ex.: 2 para ensaio rápido)
"""
import csv
import json
import subprocess
import sys
import time
from datetime import datetime, timezone

MIN = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
DUR = MIN * 60
TS = datetime.now().strftime("%Y%m%d-%H%M%S")
OUT = f"resultados/caos-{TS}"


def sh(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"falhou: {cmd}\n{r.stderr}")
    return r.stdout.strip()


def status():
    return json.loads(sh("docker exec va-borda cat /data/status.json"))


def max_seq():
    return int(sh("docker exec va-borda sqlite3 /data/borda.db 'select coalesce(max(seq),0) from outbox'"))


def nuvem_count(a, b):
    return int(sh(f"docker exec va-postgres psql -U aurora_owner -d aurora -tAc "
                  f"\"select count(*) from telemetria where borda='borda-vila' and seq > {a} and seq <= {b}\""))


def stats():
    linhas = sh("docker stats --no-stream --format '{{json .}}' va-borda va-mosquitto va-sensores").splitlines()
    return {json.loads(l)["Name"]: json.loads(l) for l in linhas}


def agora():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main():
    sh(f"mkdir -p {OUT}")
    print(f"== Teste de caos: queda da WAN por {MIN} min (início {agora()})")
    s0 = status()
    if not s0["link_wan"]:
        raise SystemExit("A borda já está sem link; rode 'make up' e espere sincronizar.")
    seq_antes = max_seq()
    t_ini = time.time()
    sh("docker network disconnect vila-aurora_seg_wan va-borda")
    print(f"[{agora()}] WAN DERRUBADA (seq local={seq_antes})")
    falha_on = min(60, DUR * 0.2)
    falha_off = min(falha_on + 120, DUR * 0.6)
    amostras = []
    falha_ativa = falha_feita = False
    while time.time() - t_ini < DUR:
        dt = time.time() - t_ini
        if not falha_ativa and not falha_feita and dt >= falha_on:
            sh("docker exec va-sensores touch /tmp/sim/camara_quente")
            falha_ativa = True
            print(f"[{agora()}] falha injetada: câmara fria esquentando (sem internet)")
        if falha_ativa and dt >= falha_off:
            sh("docker exec va-sensores rm -f /tmp/sim/camara_quente")
            falha_ativa, falha_feita = False, True
            print(f"[{agora()}] falha removida: câmara fria voltando à faixa")
        st = status()
        stt = stats()
        amostras.append({"t_s": round(dt), "ts": agora(), "link_wan": st["link_wan"], "gerados": st["gerados"],
                         "pendentes": st["pendentes"], "alarmes_locais": st["alarmes_locais"],
                         "temp_camara_c": st["temp_camara_c"], "nivel_pct": st["nivel_pct"],
                         "bomba_ligada": st["bomba_ligada"],
                         "borda_cpu": stt.get("va-borda", {}).get("CPUPerc"),
                         "borda_mem": stt.get("va-borda", {}).get("MemUsage"),
                         "mosquitto_cpu": stt.get("va-mosquitto", {}).get("CPUPerc"),
                         "mosquitto_mem": stt.get("va-mosquitto", {}).get("MemUsage")})
        a = amostras[-1]
        print(f"  t={a['t_s']:>5}s link={a['link_wan']} pendentes={a['pendentes']} alarmes_locais={a['alarmes_locais']} "
              f"temp={a['temp_camara_c']} cpu_borda={a['borda_cpu']}")
        time.sleep(min(30, max(5, DUR / 20)))
    sh("docker exec va-sensores rm -f /tmp/sim/camara_quente", check=False)
    seq_fim_queda = max_seq()
    sh("docker network connect --ip 172.31.0.2 vila-aurora_seg_wan va-borda")
    t_volta = time.time()
    print(f"[{agora()}] WAN RESTABELECIDA (seq local={seq_fim_queda}); aguardando sincronizar...")
    while True:
        st = status()
        if st["link_wan"] and st["pendentes"] == 0:
            break
        if time.time() - t_volta > 900:
            print("!! timeout aguardando sincronização")
            break
        time.sleep(2)
    t_sync = time.time() - t_volta
    time.sleep(6)
    esperado = seq_fim_queda - seq_antes
    recebidos = nuvem_count(seq_antes, seq_fim_queda)
    alarmes = sh("docker exec va-siem sh -c \"grep -h '\\\"alarme_local' /logs/borda.jsonl | tail -n 20\"", check=False)
    ini_utc = datetime.fromtimestamp(t_ini, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    alarmes_offline = [a for a in (json.loads(l) for l in alarmes.splitlines() if l.strip())
                       if a.get("link_wan") is False and a["ts"] >= ini_utc]
    res = {
        "inicio": datetime.fromtimestamp(t_ini).astimezone().isoformat(timespec="seconds"),
        "duracao_queda_min": round((t_volta - t_ini) / 60, 2),
        "mensagens_geradas_durante_queda": esperado,
        "mensagens_recebidas_na_nuvem_apos_reconciliacao": recebidos,
        "perda_mensagens": esperado - recebidos,
        "perda_pct": round(100 * (esperado - recebidos) / esperado, 4) if esperado else 0,
        "tempo_para_sincronizar_s": round(t_sync, 1),
        "alarmes_locais_disparados_sem_internet": len(alarmes_offline),
        "exemplo_alarme_local": alarmes_offline[0] if alarmes_offline else None,
        "pico_pendentes": max(a["pendentes"] for a in amostras),
        "operacao_autonoma_s": round(t_volta - t_ini, 1),
    }
    json.dump(res, open(f"{OUT}/resultado.json", "w"), ensure_ascii=False, indent=2)
    with open(f"{OUT}/amostras.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(amostras[0]))
        w.writeheader()
        w.writerows(amostras)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    print(f"\nResultados: {OUT}/resultado.json e {OUT}/amostras.csv")


if __name__ == "__main__":
    main()

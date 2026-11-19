#!/usr/bin/env python3
"""Mostra os alertas do SIEM (e as respostas do SOAR) de forma legível.
uso: docker exec va-siem cat /logs/central/alertas.jsonl | python3 scripts/ver_alertas.py [N]"""
import json
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
linhas = sys.stdin.read().strip().splitlines()[-n:]
for l in linhas:
    a = json.loads(l)
    print(f"[{a['regra']}] ({a['severidade']}) {a['resumo'][:120]}")
    mttr = f"{a['mttr_s']}s" if a.get('mttr_s') is not None else "n/a (sem resposta automática)"
    print(f"    evento={a['ts_evento']}  detectado={a['ts_deteccao']}  MTTD={a['mttd_s']}s  MTTR={mttr}")
    for r in a["respostas"]:
        print(f"    -> SOAR: {r.get('acao')} {'OK' if r.get('ok') else 'FALHOU'} "
              f"{ {k: v for k, v in r.items() if k not in ('acao', 'ok', 'ts')} }")
if not linhas:
    print("(nenhum alerta ainda)")

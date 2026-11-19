#!/usr/bin/env python3
"""IA DEFENSIVA (RT-16): detecção de anomalias na telemetria com Isolation Forest.

- Gera telemetria SINTÉTICA de 30 dias (amostra a cada 5 min) da escola (nível,
  bomba), UBS (câmara fria) e centro (energia), com sazonalidade diária e ruído.
- Injeta anomalias ROTULADAS, inspiradas no INC-VA-0712:
    A1 bomba ligada de madrugada esvaziando o reservatório (agendamento adulterado)
    A2 câmara fria saindo da faixa 2-8 °C (falha/abertura de porta)
    A3 sensor adulterado/travado (valor constante ou impossível)
    A4 pico anormal de carga elétrica à noite
- Treina de forma NÃO SUPERVISIONADA nos primeiros 60% (dados sem rótulo, que
  podem conter anomalias - como na vida real) e mede, nos 40% finais (teste):
  precisão, revocação, F1, taxa de falsos positivos e revocação por tipo.
  Os rótulos só são usados para AVALIAR, nunca para treinar.
Resultado: /resultados/ia-metricas.json   (seed fixa = reprodutível)
"""
import json
import os
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

rng = np.random.default_rng(42)
PASSO_MIN = 5
N = 30 * 24 * 60 // PASSO_MIN
OUT = os.environ.get("OUT_DIR", "/resultados")


def gerar(n, rng):
    t = np.arange(n)
    hora = (t * PASSO_MIN / 60) % 24
    na_agenda = ((hora >= 6.5) & (hora < 8.5)) | ((hora >= 16) & (hora < 18))
    bomba = na_agenda.astype(float)
    nivel = np.empty(n)
    nivel[0] = 70
    for i in range(1, n):
        nivel[i] = np.clip(nivel[i - 1] + (-2.2 if bomba[i] else 0.55) + rng.normal(0, 0.3), 5, 100)
    temp = 5 + 0.6 * np.sin(2 * np.pi * hora / 24) + rng.normal(0, 0.25, n)
    solar = np.clip(1500 * (1 - np.abs(hora - 12) / 6), 0, None) + rng.normal(0, 40, n)
    carga = 600 + 150 * ((hora > 7) & (hora < 21)) + rng.normal(0, 60, n)
    return hora, bomba, nivel, temp, solar, carga


def features(hora, bomba, nivel, temp, solar, carga):
    d_nivel = np.diff(nivel, prepend=nivel[0])
    d_temp = np.diff(temp, prepend=temp[0])
    var_temp = np.array([temp[max(0, i - 6):i + 1].std() for i in range(len(temp))])
    hs, hc = np.sin(2 * np.pi * hora / 24), np.cos(2 * np.pi * hora / 24)
    # interações bomba x hora: permitem ao modelo aprender "QUANDO" a bomba costuma ligar
    return np.column_stack([hs, hc, bomba, bomba * hs, bomba * hc, nivel, d_nivel,
                            temp, d_temp, var_temp, solar, carga])


hora, bomba, nivel, temp, solar, carga = gerar(N, rng)
rot = np.zeros(N, dtype=int)
tipo = np.array([""] * N, dtype=object)
evento = np.full(N, -1)
corte = int(N * 0.6)  # 60% treino (sem anomalias), 40% teste (com anomalias)
inicios = rng.choice(np.arange(300, N - 50), size=80, replace=False)
for k, i0 in enumerate(sorted(inicios)):
    tp = ["A1", "A2", "A3", "A4"][k % 4]
    if tp == "A1":   # bomba ligada às ~02h, nível despencando
        dia0 = i0 - int(((hora[i0] - 2) % 24) * 60 / PASSO_MIN)
        idx = np.arange(dia0, dia0 + 12)
        idx = idx[(idx > 0) & (idx < N)]
        bomba[idx] = 1
        for j in idx:
            nivel[j] = max(5, nivel[j - 1] - 2.2)
    elif tp == "A2":
        idx = np.arange(i0, i0 + 10)
        temp[idx] = temp[idx] + np.linspace(2.5, 7, len(idx))
    elif tp == "A3":
        idx = np.arange(i0, i0 + 8)
        temp[idx] = 5.0          # sensor travado (variância zero)
        nivel[idx] = 999 if k % 8 == 2 else nivel[idx[0]]
    else:
        idx = np.arange(i0, i0 + 6)
        carga[idx] = carga[idx] + rng.uniform(1500, 2500)
    rot[idx] = 1
    tipo[idx] = tp
    evento[idx] = k

X = features(hora, bomba, nivel, temp, solar, carga)
Xtr, Xte, yte, tte = X[:corte], X[corte:], rot[corte:], tipo[corte:]
CONTAMINACAO = 0.05   # hipótese operacional: ~5% das janelas merecem triagem
modelo = IsolationForest(n_estimators=300, contamination=CONTAMINACAO, random_state=42).fit(Xtr)  # sem rótulos
pred = (modelo.predict(Xte) == -1).astype(int)
tn, fp, fn, tp_ = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
ete = evento[corte:]
ev_ids = [e for e in np.unique(ete) if e >= 0]
ev_det = {int(e): bool(pred[ete == e].any()) for e in ev_ids}
por_tipo = {t: round(float(pred[tte == t].mean()), 3) for t in ["A1", "A2", "A3", "A4"] if (tte == t).any()}
res = {
    "gerado_em": datetime.now().astimezone().isoformat(timespec="seconds"),
    "modelo": f"IsolationForest(n_estimators=300, contamination={CONTAMINACAO}, random_state=42)",
    "dados": {"amostras_total": int(N), "treino_normais": int(corte), "teste": int(len(yte)),
              "teste_anomalas": int(yte.sum()), "eventos_anomalos_total": 80,
              "taxa_real_anomalias_teste": round(float(yte.mean()), 4), "intervalo_min": PASSO_MIN,
              "observacao": "telemetria 100% sintética; treino sem rótulos (não supervisionado)"},
    "metricas_teste": {"precisao": round(float(precision_score(yte, pred)), 3),
                       "revocacao": round(float(recall_score(yte, pred)), 3),
                       "f1": round(float(f1_score(yte, pred)), 3),
                       "falsos_positivos": int(fp), "taxa_falsos_positivos": round(fp / (fp + tn), 4),
                       "verdadeiros_positivos": int(tp_), "falsos_negativos": int(fn), "verdadeiros_negativos": int(tn),
                       "falsos_positivos_por_dia": round(fp / (len(yte) * PASSO_MIN / 1440), 2)},
    "revocacao_por_tipo_janelas": por_tipo,
    "deteccao_por_evento": {"eventos_no_teste": len(ev_ids), "eventos_detectados": int(sum(ev_det.values())),
                            "revocacao_por_evento": round(sum(ev_det.values()) / len(ev_ids), 3),
                            "obs": "evento detectado = ao menos 1 janela do evento sinalizada (visão do SOC)"},
    "uso_no_soc": "alerta para triagem humana (não aciona atuadores). Falsos positivos medidos acima.",
}
os.makedirs(OUT, exist_ok=True)
json.dump(res, open(f"{OUT}/ia-metricas.json", "w"), ensure_ascii=False, indent=2)
print(json.dumps(res, ensure_ascii=False, indent=2))

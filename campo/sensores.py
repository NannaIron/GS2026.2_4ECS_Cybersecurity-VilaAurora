#!/usr/bin/env python3
"""Camada de CAMPO simulada: um cliente MQTT por dispositivo, cada um com o SEU
certificado X.509 (mTLS). Dados 100% sintéticos.

Falhas para demonstração (crie o arquivo dentro do container):
  /tmp/sim/camara_quente        -> câmara fria da UBS esquenta (alarme local)
  /tmp/sim/enchente             -> nível de água sobe no abrigo
  /tmp/sim/sensor_comprometido  -> sensor da horta passa a enviar lixo e tenta
                                   comandar a bomba (gatilho do SOAR "isolar")
"""
import json
import os
import random
import ssl
import threading
import time

import paho.mqtt.client as mqtt

from common.aurora_log import log, agora_utc

BROKER = os.environ.get("MQTT_HOST", "mosquitto")
PORTA = int(os.environ.get("MQTT_PORT", "8883"))
PKI = os.environ.get("PKI_DISP", "/pki/dispositivos")
INTERVALO = float(os.environ.get("SENSOR_INTERVALO", "2"))
SIM = "/tmp/sim"
os.makedirs(SIM, exist_ok=True)

estado = {"nivel": 70.0, "bomba_ligada": False, "temp": 5.0, "agua_abrigo": 0.0,
          "bateria": 80.0, "umidade": 45.0, "porta_travada": True}
rnd = random.Random()


def falha(nome):
    return os.path.exists(os.path.join(SIM, nome))


class Dispositivo(threading.Thread):
    assinaturas = []

    def __init__(self, cn):
        super().__init__(daemon=True, name=cn)
        self.cn = cn
        self.cli = None
        self.conectado = threading.Event()

    def conectar(self):
        d = os.path.join(PKI, self.cn)
        cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.cn, clean_session=True)
        # TLS 1.2+ com verificação do servidor pela CA do projeto + certificado do dispositivo
        cli.tls_set(ca_certs=f"{d}/ca.crt", certfile=f"{d}/cliente.crt", keyfile=f"{d}/cliente.key",
                    cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        cli.on_connect = self._on_connect
        cli.on_disconnect = self._on_disconnect
        cli.on_message = self._on_message
        cli.connect(BROKER, PORTA, keepalive=20)
        cli.loop_start()
        self.cli = cli

    def _on_connect(self, c, u, flags, rc, props=None):
        if rc == 0:
            self.conectado.set()
            log("dispositivo_conectado", dispositivo=self.cn)
            for t in self.assinaturas:
                c.subscribe(t, qos=1)
        else:
            log("dispositivo_conexao_recusada", "warning", dispositivo=self.cn, motivo=str(rc))

    def _on_disconnect(self, c, u, flags, rc, props=None):
        self.conectado.clear()

    def _on_message(self, c, u, msg):
        pass

    def pub(self, topico, dados, qos=1):
        dados = dict(dados, dispositivo=self.cn, ts=agora_utc())
        if self.cli and self.conectado.is_set():
            self.cli.publish(topico, json.dumps(dados), qos=qos)

    def passo(self):
        raise NotImplementedError

    def run(self):
        while True:
            try:
                if self.cli is None:
                    self.conectar()        # relê os arquivos de certificado (suporta rotação)
                    self.conectado.wait(5)
                if not self.conectado.is_set():
                    raise ConnectionError("sem conexão")
                self.passo()
                time.sleep(INTERVALO)
            except Exception as e:  # reconecta (broker reiniciado, cert revogado, etc.)
                log("dispositivo_erro_conexao", "warning", dispositivo=self.cn, erro=str(e)[:200])
                try:
                    if self.cli:
                        self.cli.loop_stop()
                        self.cli.disconnect()
                except Exception:
                    pass
                self.cli = None
                time.sleep(5)


class NivelEscola(Dispositivo):
    assinaturas = ["vila/escola/bomba/estado"]

    def _on_message(self, c, u, msg):
        try:
            estado["bomba_ligada"] = bool(json.loads(msg.payload)["ligada"])
        except Exception:
            pass

    def passo(self):
        # bomba de recalque ligada esvazia o reservatório; desligada, ele reabastece pela rede
        estado["nivel"] += -0.9 if estado["bomba_ligada"] else 0.25
        estado["nivel"] = max(0.0, min(100.0, estado["nivel"] + rnd.uniform(-0.1, 0.1)))
        self.pub("vila/escola/agua/nivel", {"nivel_pct": round(estado["nivel"], 2),
                                            "turbidez_ntu": round(rnd.uniform(0.3, 0.9), 2),
                                            "cloro_mg_l": round(rnd.uniform(0.6, 1.4), 2)})


class BombaEscola(Dispositivo):
    assinaturas = ["vila/escola/bomba/cmd"]
    n = 0

    def _on_message(self, c, u, msg):
        try:
            cmd = json.loads(msg.payload)
            estado["bomba_ligada"] = cmd.get("acao") == "ligar"
            log("atuador_comando_recebido", dispositivo=self.cn, acao=cmd.get("acao"), origem=cmd.get("origem"))
            self.pub("vila/escola/bomba/estado", {"ligada": estado["bomba_ligada"]})
        except Exception:
            pass

    def passo(self):
        self.n += 1
        if self.n % 5 == 0:
            self.pub("vila/escola/bomba/estado", {"ligada": estado["bomba_ligada"]})


class CamaraFria(Dispositivo):
    def passo(self):
        if falha("camara_quente"):
            estado["temp"] = min(14.0, estado["temp"] + 0.6)
        else:
            estado["temp"] += (5.0 - estado["temp"]) * 0.2 + rnd.uniform(-0.15, 0.15)
        self.pub("vila/ubs/camarafria/temp", {"temp_c": round(estado["temp"], 2)})


class Alagamento(Dispositivo):
    def passo(self):
        if falha("enchente"):
            estado["agua_abrigo"] = min(120.0, estado["agua_abrigo"] + 3)
        else:
            estado["agua_abrigo"] = max(0.0, estado["agua_abrigo"] - 2)
        self.pub("vila/abrigo/alagamento", {"agua_cm": round(estado["agua_abrigo"], 1)})


class PortaAbrigo(Dispositivo):
    assinaturas = ["vila/abrigo/porta/cmd"]
    n = 0

    def _on_message(self, c, u, msg):
        try:
            estado["porta_travada"] = json.loads(msg.payload).get("acao") != "liberar"
            self.pub("vila/abrigo/porta/estado", {"travada": estado["porta_travada"]})
        except Exception:
            pass

    def passo(self):
        self.n += 1
        if self.n % 15 == 0:  # evento de crachá (o pseudônimo é aplicado na borda)
            self.pub("vila/abrigo/porta/acesso", {"cracha": f"CRACHA-{rnd.randint(1, 40):04d}",
                                                  "resultado": "liberado"})


class Energia(Dispositivo):
    def passo(self):
        h = time.localtime().tm_hour
        solar = max(0.0, 1500 * (1 - abs(h - 12) / 6)) + rnd.uniform(-50, 50)
        carga = 600 + rnd.uniform(-80, 80)
        estado["bateria"] = max(5.0, min(100.0, estado["bateria"] + (solar - carga) / 20000))
        self.pub("vila/centro/energia", {"solar_w": round(max(solar, 0), 1), "carga_w": round(carga, 1),
                                          "bateria_pct": round(estado["bateria"], 2)})


class UmidadeHorta(Dispositivo):
    def passo(self):
        if falha("sensor_comprometido"):
            # comportamento malicioso: lixo em alta taxa + tentativa de comandar a bomba (ACL nega)
            for _ in range(10):
                self.pub("vila/horta/solo/umidade", {"umidade_pct": 9999})
            self.pub("vila/escola/bomba/cmd", {"acao": "ligar", "origem": "horta?"})
            return
        estado["umidade"] = max(10.0, min(90.0, estado["umidade"] + rnd.uniform(-0.5, 0.5)))
        self.pub("vila/horta/solo/umidade", {"umidade_pct": round(estado["umidade"], 2)})


if __name__ == "__main__":
    ds = [NivelEscola("escola-nivel-01"), BombaEscola("escola-bomba-01"), CamaraFria("ubs-camarafria-01"),
          Alagamento("abrigo-alagamento-01"), PortaAbrigo("abrigo-porta-01"), Energia("centro-energia-01"),
          UmidadeHorta("horta-umidade-01")]
    for d in ds:
        d.start()
        time.sleep(0.3)
    log("campo_iniciado", dispositivos=[d.cn for d in ds])
    while True:
        time.sleep(3600)

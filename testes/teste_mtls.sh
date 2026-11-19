#!/usr/bin/env bash
# Evidências de mTLS, ACL, revogação (CRL) e rotação de certificado (RT-04, RT-05).
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="resultados/teste-mtls-$(date +%Y%m%d-%H%M%S).txt"
CN=teste-dispositivo-01
PKI_RUN="docker run --rm -v $PWD:/repo -e HOST_UID=$(id -u) -e HOST_GID=$(id -g) vila-aurora/py:1.0 python3 /repo/scripts/pki.py"
cli() { # executa um cliente MQTT num container novo, dentro do segmento IoT
  docker run --rm --network vila-aurora_seg_iot -v "$PWD/pki/dispositivos/$CN:/c:ro" -v "$PWD/pki/broker/ca.crt:/ca.crt:ro" \
    vila-aurora/py:1.0 sh -c "$1" 2>&1
}
r() { echo "$*" | tee -a "$OUT"; }
r "# Teste mTLS / revogação / rotação - $(date -Iseconds)"

r ""; r "## 1) Cliente SEM certificado (esperado: RECUSADO)"
r "$(cli 'timeout 10 mosquitto_pub -h mosquitto -p 8883 --cafile /ca.crt -t vila/teste/x -m sem-cert; echo "rc=$?"')"

r ""; r "## 2) Cliente com certificado AUTOASSINADO de outra CA (esperado: RECUSADO)"
r "$(cli 'cd /tmp && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout k.pem -out c.pem -days 1 -subj /CN=escola-bomba-01 2>/dev/null && timeout 10 mosquitto_pub -h mosquitto -p 8883 --cafile /ca.crt --cert c.pem --key k.pem -t vila/teste/x -m falso; echo "rc=$?"')"

r ""; r "## 3) Dispositivo com certificado VÁLIDO da CA Vila Aurora (esperado: ACEITO)"
r "$(cli 'timeout 10 mosquitto_pub -h mosquitto -p 8883 --cafile /ca.crt --cert /c/cliente.crt --key /c/cliente.key -t vila/teste/x -m ok -q 1 -d | grep -E "CONNACK|PUBACK|Error"; echo "rc=$?"')"

r ""; r "## 4) ACL: dispositivo válido tentando publicar em tópico de OUTRO dispositivo (MQTT v5, esperado: não autorizado)"
r "$(cli 'timeout 10 mosquitto_pub -V 5 -h mosquitto -p 8883 --cafile /ca.crt --cert /c/cliente.crt --key /c/cliente.key -t vila/escola/bomba/cmd -m "{\"acao\":\"ligar\"}" -q 1 -d 2>&1 | grep -E "PUBACK|Not authorized|Error|rc"; echo "rc=$?"')"

r ""; r "## 5) REVOGAÇÃO: revogando $CN e publicando nova CRL"
SERIAL_ANTIGO=$(openssl x509 -in pki/dispositivos/$CN/cliente.crt -noout -serial 2>/dev/null || docker run --rm -v $PWD/pki:/pki vila-aurora/py:1.0 openssl x509 -in /pki/dispositivos/$CN/cliente.crt -noout -serial)
r "certificado atual: $SERIAL_ANTIGO"
r "$($PKI_RUN revogar $CN keyCompromise 2>&1)"
r "aguardando o broker recarregar a CRL (supervisor verifica a cada 2 s)..."; sleep 6
r "$(cli 'timeout 10 mosquitto_pub -h mosquitto -p 8883 --cafile /ca.crt --cert /c/cliente.crt --key /c/cliente.key -t vila/teste/x -m revogado; echo "rc=$?"')"
r "CRL publicada (trecho):"
r "$(docker run --rm -v $PWD/pki:/pki vila-aurora/py:1.0 openssl crl -in /pki/broker/crl.pem -noout -text | grep -E 'Serial Number|Reason Code' -A1 | head -12)"

r ""; r "## 6) ROTAÇÃO: emite novo par de chaves para $CN (e revoga o anterior)"
r "$($PKI_RUN rotacionar $CN 2>&1)"; sleep 6
r "$(cli 'timeout 10 mosquitto_pub -h mosquitto -p 8883 --cafile /ca.crt --cert /c/cliente.crt --key /c/cliente.key -t vila/teste/x -m rotacionado -q 1 -d | grep -E "CONNACK|PUBACK|Error"; echo "rc=$?"')"

r ""; r "## 7) Log do broker (fonte da regra R3 do SIEM)"
r "$(docker exec va-mosquitto grep -E 'OpenSSL|revoked|failed|Denied|not authori' /mosquitto/log/mosquitto.log | tail -8)"
echo; echo "Resultado salvo em $OUT"

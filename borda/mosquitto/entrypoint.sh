#!/bin/sh
# Supervisor do broker: reinicia o Mosquitto quando a CRL ou a ACL mudam
# (revogação/isolamento derrubam na hora as sessões existentes do dispositivo).
mkdir -p /mosquitto/log /mosquitto/data
chown -R mosquitto:mosquitto /mosquitto/log /mosquitto/data
assinatura() { cat /pki/crl.pem /pki/acl 2>/dev/null | md5sum | cut -d' ' -f1; }
while true; do
  ATUAL=$(assinatura)
  /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf &
  PID=$!
  while kill -0 $PID 2>/dev/null; do
    sleep 2
    if [ "$(assinatura)" != "$ATUAL" ]; then
      echo "$(date -Iseconds) supervisor: CRL/ACL alterada -> recarregando broker" | tee -a /mosquitto/log/mosquitto.log
      kill $PID; wait $PID 2>/dev/null
      break
    fi
  done
  sleep 1
done

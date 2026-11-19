# Perfil Wazuh (opcional) — **não testado de ponta a ponta**

O E2 cumpre RT-07 com o coletor leve em `siem/siem.py` (R1–R5).
Esta pasta espelha as mesmas ideias em `local_rules.xml` para quem quiser plugar um
Wazuh Manager depois do curso.

## Conteúdo

- `local_rules.xml` — regras decoders/rules de exemplo alinhadas a R1–R5
- Este README

## Como usaria (referência)

1. Instalar Wazuh Manager (VM ou container oficial) — **fora** do compose mínimo.
2. Copiar `local_rules.xml` para `/var/ossec/etc/rules/local_rules.xml` (ou include).
3. Encaminhar os JSONL de `/logs` (ou syslog) via Filebeat/agent.
4. Reiniciar o manager e validar alertas com os mesmos eventos sintéticos de `siem/testar_regras.py`.

> Status no protótipo entregue: **documentação apenas**. Não há serviço `wazuh` no `docker-compose.yml`.

# Modelo de ameaças — Rede Comunitária Vila Aurora (E2)

Mapeamento STRIDE simplificado alinhado ao incidente fictício **INC-VA-0712** e aos controles do protótipo.
Somente dados sintéticos; domínio `vilaaurora.example`.

## Ativos

| Ativo | Criticidade | Notas |
|---|---|---|
| Reservatório / bomba da escola | Alta | Agendamento adulterado esvazia a caixa → falta d'água |
| Câmara fria da UBS | Alta | Faixa 2–8 °C; alarme local na borda se WAN cair |
| Credenciais de voluntários/coordenação | Alta | Phishing + VPN fraca no cenário “antes” |
| Telemetria e logs | Média | Integridade forense (SHA-256 + cadeia de custódia) |
| Broker MQTT / identidade dos dispositivos | Alta | Certificados de cliente; CRL + ACL |

## STRIDE → cenários → controles

| STRIDE | Cenário (INC-VA-0712 / lab) | Controle no protótipo |
|---|---|---|
| **S**poofing | Login VPN só com senha roubada; dispositivo MQTT sem cert válido | WireGuard + painel com **MFA TOTP**; Mosquitto `require_certificate` + identidade=CN |
| **T**ampering | SQLi altera `agendamento_bomba` para 00:00–23:59 | Painel seguro: SQL parametrizado + validação; **borda rejeita** agendamento fora do perfil; intertravamento nível &lt;20% |
| **R**epudiation | Atacante nega ações | Logs JSON centralizados; auditoria no Postgres; coleta forense com timeline MITRE |
| **I**nformation disclosure | UNION SQLi vaza `usuarios` (e-mail/telefone) | Menor privilégio (`painel_app` sem colunas sensíveis); erros genéricos; WAF de apoio |
| **D**enial of service | Sensor “comprometido” inundando tópicos; link WAN instável | ACL por CN; SOAR isola (revoga + ACL); store-and-forward + caos RT-23 |
| **E**levation of privilege | Operador aprova próprio comando de alto impacto; superuser no legado | RBAC; aprovação só **coordenação** com step-up TOTP; requester ≠ aprovador; role `painel_app` sem DDL/DML perigoso |

## Regras SIEM (R1–R5) ↔ MITRE (exemplos)

| Regra | Detecção | Técnica (aprox.) | Resposta SOAR |
|---|---|---|---|
| R1 | Login VPN de IP fora da allowlist ou fora 06–22h | T1078 / T1133 | `bloquear_ip`, `encerrar_sessao_vpn` |
| R2 | Padrão SQLi em logs do painel/VPN | T1190 | `bloquear_ip` |
| R3 | Dispositivo sem certificado válido / CRL | T1040 / identity abuse | alerta (+ isolamento via R5/fluxo PKI) |
| R4 | Comando/agenda de atuador fora do perfil | T0831 / T1565 | `modo_seguro` + `solicitar_aprovacao` (desligar bomba) |
| R5 | Dispositivo suspeito (telemetria impossível) | T0813 / rogue device | `isolar_dispositivo` (revoga + ACL) |

## Confiança e residual

- Laboratório em Docker: segmentação real entre bridges, mas o host único é confiança compartilhada.
- Energia RT-22 é **estimativa** (modelo Pi 4); Gophish sem humanos reais → métricas de campanha são **simuladas** (seed fixa).
- Perfil Wazuh em `siem/wazuh/` é referência de regras; **não** foi exercitado de ponta a ponta neste E2 (o coletor leve cobre a rubrica).

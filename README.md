# Rede Comunitária Vila Aurora — Protótipo E2

**FIAP Global Solution 2026.2 — Cybersecurity**  
**Professor:** Carlos Eduardo de Siqueira  
**Turma:** 4ECS  

## Equipe

| Nome | RM |
|---|---|
| Giovanna Ferro Menis | 99639 |
| Alexandre Moreira da Silva Junior | 98621 |
| Luiz Fernando Della Colette Pombo Lema | 558735 |

> Identificação apenas por nomes e RMs. Não há número de grupo.

---

## O que é este repositório

Laboratório **100% local** (Docker Compose) que reproduz e corrige o incidente fictício **INC-VA-0712** da rede comunitária Vila Aurora: sensores IoT → borda com Mosquitto mTLS → túnel WireGuard → PostgreSQL e painéis Flask (legado vulnerável × seguro) → SIEM leve + SOAR-lite → forense, Isolation Forest, phishing simulado e teste de caos.

- Só dados **sintéticos** (voluntários `vol.00`–`vol.19`, domínio `vilaaurora.example`).
- **Nunca** há segredos reais no Git: certificados, chaves WG, senhas e TOTP são gerados em `make setup` e ficam em `.gitignore`.
- Pensado para notebook Arch Linux (Omarchy) com Docker — sem nuvem e sem hardware dedicado.

---

## Pré-requisitos (Arch Linux / Omarchy)

```bash
sudo pacman -S docker docker-compose docker-buildx make wireguard-tools
sudo systemctl enable --now docker
# Módulo WireGuard no kernel (geralmente já vem no linux recente):
sudo modprobe wireguard
lsmod | grep wireguard
# Relógio sincronizado (NTP) — importante para TOTP e CRL:
timedatectl status   # NTP deve estar ativo (systemd-timesyncd ou chrony)
```

Usuário no grupo `docker` (ou use `sudo` nos comandos Docker):

```bash
sudo usermod -aG docker "$USER"
# faça logout/login depois
```

Espaço em disco: ~2–3 GB para imagens e volumes.

---

## Arquitetura (segmentos)

```
sensores ──MQTT/mTLS──► mosquitto ──► borda ──WireGuard──► nuvem-gw
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     │                        ▼                        │
               seg_iot (internal)      seg_wan (172.31.0.0/24)    seg_admin (internal)
               172.31.10.0/24          borda .2 / nuvem .10       postgres .5
                                       operador .20 / atacante .66
                                       mailpit .25
```

| Rede Docker | Sub-rede | Tipo | Função |
|---|---|---|---|
| `seg_wan` | 172.31.0.0/24 | normal | “Internet” do lab: borda, nuvem-gw, operador, atacante, mailpit |
| `seg_iot` | 172.31.10.0/24 | **internal** | Broker MQTT + sensores + borda (sem saída à internet) |
| `seg_admin` | 172.31.20.0/24 | **internal** | PostgreSQL + nuvem-gw (admin) |
| `seg_legado` | 172.31.30.0/24 | internal | VPN legada + painel vulnerável (perfil `legado`) |
| `seg_phishing` | 172.31.40.0/24 | normal | Gophish / Mailpit (perfil `phishing`) |

**Túnel WireGuard:** nuvem `10.10.0.1/16`; borda `10.10.1.2`; operador-lab `10.10.2.11`; operador-host `10.10.2.10`.  
API de ingestão (`:9000`) e painel seguro (`:8443`) escutam **só** em `10.10.0.1` (via `network_mode: service:nuvem-gw`). Porta admin do Postgres **não** é publicada. WG UDP: `${WG_BIND:-127.0.0.1}:51820`.

---

## Mapa requisito → componente

| RT | Requisito (resumo) | Onde está |
|---|---|---|
| RT-01 | Sensores de campo via MQTT | `campo/sensores.py`, rede `seg_iot` |
| RT-02 | Edge: Mosquitto mTLS, CA, CRL, ACL, regras locais, SQLite store-and-forward | `borda/`, `scripts/pki.py`, `borda/regras.py` |
| RT-03 | Modo degradado / justificativa 4G | borda opera offline + outbox; ver nota abaixo |
| RT-04 | Túnel WireGuard segmentado | `common/wg_up.sh`, `scripts/gerar_segredos.py`, `scripts/vpn-host.sh` |
| RT-05 | PostgreSQL + papéis de menor privilégio | `nuvem/db/init/`, roles `painel_app` / `ingest_app` / `siem_app` |
| RT-06 | Painel vulnerável × painel seguro (parametrização, validação, MFA TOTP, RBAC, acessibilidade pt-BR) | `painel/legado`, `painel/seguro` |
| RT-07 | Coletor de logs + ≥4 regras de detecção | `siem/siem.py` (R1–R5); perfil Wazuh opcional em `siem/wazuh/` |
| RT-08 | SOAR-lite (baixo risco automático; alto impacto com aprovação humana) | `soar/soar.py`, aprovação no painel (coordenação + TOTP) |
| RT-09 | Reprodução INC-VA-0712 + coleta forense (SHA-256, cadeia, timeline) | `ataque/`, `scripts/attack-demo.sh`, `forense/` |
| RT-10 | SPF / DKIM / DMARC documentados | `phishing/dns/vilaaurora.zone`, `phishing/validar_dns.sh` |
| RT-11 | Campanha Gophish/Mailpit só em contas fictícias | `phishing/`, perfil `phishing` |
| RT-16 | Isolation Forest com métricas medidas | `ia/isolation_forest.py` → `resultados/ia-metricas.json` |
| RT-17 | LLM **não utilizado** | documentado abaixo (N/A) |
| RT-18 | Ameaças potencializadas por IA + controles | `phishing/README-phishing.md` |
| RT-22 | Métricas (disponibilidade, MTTD/MTTR, CPU/mem/banda/energia) | `scripts/metricas.py` |
| RT-23 | Teste de caos configurável + script de métricas | `scripts/caos.py` (`make chaos MIN=30`) |

**RT-03 (modo degradado / 4G):** na queda do link WAN a borda continua aplicando regras locais (intertravamento da bomba, perfil horário), gera alarme local (ex.: câmara fria) e guarda telemetria no SQLite; ao voltar, reconcilia sequências faltantes com a nuvem (`/api/reconciliar`). O protótipo simula o “último quilômetro” com Docker (disconnect da `seg_wan`); em campo real a mesma lógica caberia sobre um link 4G/LTE com franquia limitada — por isso o túnel é leve (WireGuard) e a borda evita subir dados desnecessários.

**RT-17:** nenhuma LLM é usada no pipeline de detecção, SOAR ou painel. A IA defensiva do E2 é **apenas** Isolation Forest (não supervisionado).

---

## Passo a passo (uma máquina limpa)

```bash
# 1) Clonar / extrair o projeto
cd ~/projetos   # ou onde preferir
tar xzf gs-vila-aurora.tar.gz && cd gs-vila-aurora
# (ou: git clone … && cd gs-vila-aurora)

# 2) Gerar segredos, PKI e contas fictícias (1×)
make setup
# → cria .env, segredos/, pki/  (fora do Git)

# 3) Subir a arquitetura segura
make up
# aguarde ~20 s
make status

# 4) (Opcional) Abrir o painel neste PC via VPN de operador
make vpn-host-up
# navegador: https://10.10.0.1:8443
# login: coord.marina / senha em segredos/usuarios.json
make totp U=coord.marina   # código MFA do momento

# 5) Demonstrações principais
make attack-demo           # ANTES: INC-VA-0712 no legado
make alertas               # MTTD / ações SOAR
make fix-demo              # DEPOIS: painel seguro + segmentação + sqlmap
make test-mtls             # mTLS / ACL / CRL / rotação
make test-regras           # 11/11 casos sintéticos das regras
make forensics             # coleta INC-VA-0712 + cadeia de custódia
make verificar             # confere SHA-256
make chaos MIN=30          # RT-23 (padrão 30 min; ensaio: make chaos-ensaio)
make metrics               # RT-22
make ia                    # Isolation Forest
make phishing-up && make phishing-campanha   # RT-10/11 (só fictício)

# 6) Encerrar
make vpn-host-down
make down                  # para containers, mantém volumes
# make limpar              # APAGA volumes, pki, segredos, resultados
```

Contas fictícias (senha em `segredos/usuarios.json` após o setup):

| Login | Papel RBAC |
|---|---|
| `coord.marina` | coordenação (aprova comandos de alto impacto) |
| `op.joao` | operador |
| `tec.rafael` | técnico |
| `aud.helena` | auditor |

---

## Roteiro de demonstração para o vídeo

Grave (ou capture tela) na ordem abaixo. Cada item cobre critérios típicos C1–C9 da rubrica.

| # | Critério | O que mostrar / capturar | Comando |
|---|---|---|---|
| C1 | Sensores + borda mTLS | Sensores publicando; `make test-mtls` (sem cert / CA falsa / válido / ACL / revogado / rotação) | `make test-mtls` |
| C2 | Store-and-forward + reconciliação | Durante/após o caos: `status.json` com pendentes, depois sync e perda 0 | `make chaos-ensaio` ou `MIN=30` |
| C3 | Segmentação + WireGuard | `make test-seg` (atacante bloqueado; operador só no painel; IoT sem internet) | `make test-seg` |
| C4 | Painel legado × seguro | `make attack-demo` (SQLi + bomba 00:00–23:59 rejeitada na borda) → `make fix-demo` (19/19, sqlmap “not injectable”) | `attack-demo` + `fix-demo` |
| C5 | MFA TOTP + RBAC | Login no painel seguro; `make totp`; papéis distintos (auditor vê auditoria; só coordenação aprova) | `vpn-host-up` + navegador |
| C6 | SIEM (≥4 regras) + SOAR | `make alertas` após o ataque: R1/R2/R4; bloqueio IP / modo seguro automáticos; `desligar_bomba` pendente de aprovação | `attack-demo` + `alertas` |
| C7 | Forense INC-VA-0712 | Pasta `evidencias/INC-VA-0712-*` com SHA256SUMS, cadeia CSV, timeline; `make verificar` = INTEGRIDADE OK | `make forensics` |
| C8 | IA Isolation Forest + anti-phishing | `resultados/ia-metricas.json` (precisão/revocação/FP); DNS SPF/DKIM/DMARC + campanha Gophish (só fictícios) | `make ia` + `phishing-campanha` |
| C9 | Caos 30 min + métricas RT-22 | Relatório `resultados/caos-*` e `resultados/metricas-*.json` (disponibilidade, MTTD/MTTR, CPU/mem, banda WG, energia estimada) | `make chaos` + `make metrics` |

**Sugestão de falas:** (1) “Antes”: VPN fraca + painel concatenando SQL → dump e adulteração da bomba; borda ainda barra o agendamento fora do perfil. (2) “Detecção”: SIEM em &lt;1 s; SOAR bloqueia IP e pede aprovação humana para desligar. (3) “Depois”: painel parametrizado, MFA, menor privilégio, sqlmap limpo, segmentos fechados.

---

## Uso de IA

| Uso | Ferramenta | Onde entra no E2 |
|---|---|---|
| Geração / apoio ao código e documentação do protótipo | Assistente de código (Cursor / Grok Bot) | scaffolding Docker, scripts, README, revisão de testes |
| Detecção defensiva no protótipo | **Isolation Forest** (scikit-learn) — **não** é LLM | `ia/isolation_forest.py` (RT-16) |
| LLM no produto (chatbot, classificação generativa, etc.) | — | **Não utilizado** (RT-17 N/A) |

> Preencher no E3 (relatório) o detalhamento pedido pela disciplina (prompts relevantes, o que foi aceito/revisado pela equipe, e declaração de responsabilidade pelos resultados).

---

## Contas, segredos e `.gitignore`

`make setup` gera:

- `.env` — senhas Postgres / Flask / papéis
- `segredos/usuarios.json` — logins + seeds TOTP
- `segredos/seed.sql` — hashes PBKDF2 (+ coluna legada MD5 só no painel vulnerável)
- `segredos/wg/*.conf` — peers WireGuard
- `segredos/dkim/` — chave DKIM de laboratório
- `pki/` — CA, certificados de dispositivos, CRL, ACL do Mosquitto

Nada disso entra no Git (veja `.gitignore`). Para regenerar: `make limpar && make setup && make up`.

---

## Troubleshooting

| Sintoma | Causa comum | Correção |
|---|---|---|
| Containers não se falam / DNS Docker falha | `FORWARD` DROP (iptables legado) | Em alguns hosts: `sudo iptables-legacy -P FORWARD ACCEPT` (ou garantir regras do Docker) |
| Painel/API “sumiram” após recriar só o `nuvem-gw` | Serviços com `network_mode: service:nuvem-gw` ficam órfãos | `make up` (sobe o conjunto de novo). Em testes use `docker compose up -d --no-deps painel-seguro` |
| TOTP rejeitado | Relógio do host fora do NTP | `timedatectl` / sincronizar hora |
| `evidencias/` não apaga | Coleta deixa itens somente leitura | `chmod -R u+w evidencias && rm -rf evidencias/INC-*` |
| Porta 51820 em uso | Outro WireGuard / compose antigo | `make down`; ajuste `WG_BIND` no `.env` |
| `make setup` sem imagem | Build ainda não rodou | O setup faz `docker build`; precisa de rede para puxar `alpine:3.22` na 1ª vez |

---

## Estrutura do repositório (visão)

```
gs-vila-aurora/
├── Makefile                 # atalhos one-command
├── docker-compose.yml
├── docker/py/               # imagem vila-aurora/py:1.0
├── common/                  # log JSON, wg_up.sh
├── campo/                   # sensores MQTT
├── borda/                   # mosquitto + regras + entrypoint
├── nuvem/                   # gw, api, schema Postgres
├── painel/seguro|legado|vpn_legada/
├── siem/                    # coletor + regras; wazuh/ (opcional, não testado)
├── soar/                    # respostas automáticas / aprovação
├── ataque/                  # script INC-VA-0712
├── forense/                 # coleta, timeline, verificar
├── ia/                      # Isolation Forest
├── phishing/                # DNS, Gophish, alvos fictícios
├── testes/                  # mTLS, segmentação, painel, sqlmap
├── scripts/                 # setup, caos, métricas, attack/fix-demo, PKI
├── docs/                    # modelo de ameaças (STRIDE)
├── pki/ segredos/ .env      # GERADOS (ignorados pelo Git)
├── resultados/ evidencias/  # saídas de demo (ignoradas)
└── README.md
```

---

## Licença e ética

Uso estritamente acadêmico / laboratorial. Campanha de phishing **somente** contra contas `@vilaaurora.example` criadas pela equipe (Lei 12.737/2012). Não publicar a VPN nem o painel legado em interfaces públicas.

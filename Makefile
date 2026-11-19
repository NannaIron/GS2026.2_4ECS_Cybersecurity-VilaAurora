# Rede Comunitária Vila Aurora - atalhos do protótipo (GS 2026.2 Cybersecurity)
# Uso: make <alvo>.  Veja README.md para o passo a passo completo.
SHELL := /bin/bash
MIN ?= 30
CN ?= teste-dispositivo-01
PKI := docker run --rm -v $(CURDIR):/repo -e HOST_UID=$$(id -u) -e HOST_GID=$$(id -g) vila-aurora/py:1.0 python3 /repo/scripts/pki.py

.PHONY: help setup up down status logs alertas attack-demo attack-sqlmap fix-demo test-mtls test-seg test-regras \
        revogar rotacionar reabilitar listar-certs chaos chaos-ensaio forensics verificar metrics ia phishing-up phishing-campanha \
        vpn-host-up vpn-host-down totp esquentar-camara normalizar-camara comprometer-sensor painel-demo limpar

help:           ## lista os comandos
	@grep -E '^[a-z-]+:.*##' Makefile | awk -F':.*## ' '{printf "  make %-20s %s\n", $$1, $$2}'

setup:          ## 1x: gera certificados, chaves WireGuard, senhas e contas fictícias
	bash scripts/setup.sh

up:             ## sobe a arquitetura segura (campo, borda, VPN, nuvem, SIEM)
	docker compose up -d --build
	@echo "Aguarde ~20 s e rode: make status"

down:           ## para tudo (mantém dados)
	docker compose --profile legado --profile phishing down

status:         ## situação dos containers e da borda
	@docker compose ps --format 'table {{.Name}}\t{{.Status}}'
	@echo; docker exec va-borda cat /data/status.json

logs:           ## acompanha os logs centralizados (Ctrl+C para sair)
	docker exec va-siem tail -f /logs/central/eventos.jsonl

alertas:        ## alertas do SIEM e respostas do SOAR
	@docker exec va-siem cat /logs/central/alertas.jsonl | python3 scripts/ver_alertas.py 30

attack-demo:    ## ANTES: reproduz o INC-VA-0712 no legado (phishing -> VPN -> SQLi -> bomba)
	bash scripts/attack-demo.sh

attack-sqlmap:  ## igual ao attack-demo, mas também roda o sqlmap contra o painel legado
	bash scripts/attack-demo.sh --sqlmap

fix-demo:       ## DEPOIS: reteste do SQLi no painel seguro + segmentação + menor privilégio
	bash scripts/fix-demo.sh

test-mtls:      ## mTLS: sem certificado, CA falsa, válido, ACL, revogação e rotação
	bash testes/teste_mtls.sh

test-seg:       ## VPN e segmentação (atacante, operador, borda, IoT) + privilégio do banco
	bash testes/teste_segmentacao.sh

test-regras:    ## teste unitário das 5 regras do SIEM com eventos sintéticos (inclui 02:14)
	docker run --rm -e TZ=America/Sao_Paulo vila-aurora/py:1.0 python3 /app/siem/testar_regras.py

revogar:        ## revoga o certificado de um dispositivo: make revogar CN=horta-umidade-01
	$(PKI) revogar $(CN)

rotacionar:     ## rotaciona o certificado de um dispositivo: make rotacionar CN=escola-nivel-01
	$(PKI) rotacionar $(CN)

reabilitar:     ## após investigar, devolve o dispositivo isolado com certificado novo: make reabilitar CN=horta-umidade-01
	docker exec va-sensores rm -f /tmp/sim/sensor_comprometido
	$(PKI) reabilitar $(CN)

listar-certs:   ## lista certificados emitidos (V=válido, R=revogado)
	$(PKI) listar

esquentar-camara: ## simula falha da câmara fria da UBS (alarme local)
	docker exec va-sensores touch /tmp/sim/camara_quente

normalizar-camara: ## volta a câmara fria ao normal
	docker exec va-sensores rm -f /tmp/sim/camara_quente

comprometer-sensor: ## sensor da horta passa a se comportar mal -> SOAR isola (revoga cert)
	docker exec va-sensores touch /tmp/sim/sensor_comprometido

chaos:          ## teste de caos: derruba a WAN da borda por MIN minutos (padrão 30)
	python3 scripts/caos.py $(MIN)

chaos-ensaio:   ## ensaio rápido do caos (2 minutos)
	python3 scripts/caos.py 2

forensics:      ## coleta forense: hashes SHA-256, cadeia de custódia e linha do tempo
	bash forense/coletar.sh "$${PERITO:-$$(whoami)}"

verificar:      ## confere integridade da última coleta forense
	bash forense/verificar.sh $$(ls -d evidencias/INC-VA-0712-* | tail -1)

metrics:        ## métricas RT-22 (disponibilidade, MTTD, MTTR, CPU, memória, banda, energia)
	python3 scripts/metricas.py 60

ia:             ## Isolation Forest na telemetria sintética (precisão, revocação, FP)
	docker run --rm -v $(CURDIR)/resultados:/resultados vila-aurora/py:1.0 python3 /app/ia/isolation_forest.py

phishing-up:    ## sobe Gophish (127.0.0.1:3333) + Mailpit (127.0.0.1:8025)
	docker compose --profile phishing up -d mailpit gophish
	@docker logs va-gophish 2>&1 | grep -i password || true

phishing-campanha: ## roda a campanha simulada (só contas fictícias) e salva as métricas
	bash phishing/rodar_campanha.sh

vpn-host-up:    ## conecta ESTE PC à VPN como operador (abre o painel em https://10.10.0.1:8443)
	bash scripts/vpn-host.sh up

vpn-host-down:  ## desconecta a VPN do host
	bash scripts/vpn-host.sh down

totp:           ## código TOTP atual de uma conta fictícia: make totp U=coord.marina
	@python3 scripts/totp.py $${U:-coord.marina}

limpar:         ## APAGA tudo (containers, volumes, segredos, certificados, resultados)
	docker compose --profile legado --profile phishing down -v --remove-orphans
	docker run --rm -v $(CURDIR):/repo alpine sh -c 'rm -rf /repo/pki/* /repo/segredos/* /repo/.env /repo/evidencias/INC-* /repo/resultados/*-*'

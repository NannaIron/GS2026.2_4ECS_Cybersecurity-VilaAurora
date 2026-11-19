# Rede Comunitária Vila Aurora — Protótipo (E2)

**FIAP — Global Solution 2026.2 — Cybersecurity**
**Professor:** Carlos Eduardo de Siqueira
**Turma:** 4ECS

| Integrante | RM |
|---|---|
| Giovanna Ferro Menis | 99639 |
| Alexandre Moreira da Silva Junior | 98621 |
| Luiz Fernando Della Colette Pombo Lema | 558735 |

---

## 1. Introdução

Este repositório contém o protótipo de segurança da Rede Comunitária Vila Aurora. O laboratório roda inteiro em Docker, em um único computador, e reproduz o incidente fictício **INC-VA-0712**: um voluntário cai em um phishing, o atacante entra pela VPN antiga só com senha, explora uma injeção de SQL no painel legado, vaza o cadastro e altera o agendamento da bomba d'água da escola.

Em seguida, o mesmo cenário é repetido contra a arquitetura corrigida, mostrando a detecção, a resposta e o que deixou de funcionar para o atacante.

## 2. Objetivos e escopo

O protótipo cobre:

- sensores de campo publicando via MQTT;
- borda com Mosquitto em mTLS (CA própria, CRL, rotação de certificados e ACL por dispositivo), regras locais e fila SQLite para operar sem internet;
- túnel WireGuard entre borda, operadores e nuvem;
- PostgreSQL e dois painéis Flask: o legado (vulnerável) e o seguro (consultas parametrizadas, validação, MFA TOTP, RBAC e menor privilégio no banco);
- coletor de logs com 5 regras de detecção e SOAR simplificado (ações de baixo risco automáticas e ações de alto impacto com aprovação humana);
- coleta forense com SHA-256, cadeia de custódia e linha do tempo;
- detecção de anomalias com Isolation Forest;
- SPF, DKIM e DMARC documentados e campanha de phishing com Gophish e Mailpit;
- teste de caos (queda do link da borda) e script de métricas.

Fora do escopo: hardware real, nuvem pública e qualquer dado real. Todas as contas, e-mails e registros são **sintéticos** (domínio `vilaaurora.example`). Nenhum segredo fica no Git: certificados, chaves, senhas e sementes TOTP são gerados localmente pelo `make setup`.

## 3. Pré-requisitos e instalação

O projeto foi desenvolvido e testado **apenas em Linux**. A opção Windows está descrita como alternativa, mas não foi testada.

### 3.1 Linux

É preciso ter:

- Docker Engine com os plugins **compose** e **buildx**;
- `make`, `git` e `wireguard-tools`;
- módulo WireGuard no kernel (já vem nos kernels atuais);
- relógio sincronizado por NTP (o TOTP e a CRL dependem da hora certa).

A forma recomendada de instalar o Docker é seguir a documentação oficial da sua distribuição: <https://docs.docker.com/engine/install/>. Os demais pacotes saem do gerenciador da distro, por exemplo:

```bash
# Debian/Ubuntu
sudo apt install make git wireguard-tools
# Fedora
sudo dnf install make git wireguard-tools
# (use o equivalente no gerenciador da sua distro)
```

Depois:

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"     # faça logout/login depois
sudo modprobe wireguard
timedatectl status                  # "System clock synchronized: yes"
```

**Se os containers não se comunicarem** (por exemplo, a borda não alcança a nuvem e o `make status` mostra o link caído), o host pode estar com a política `FORWARD` do iptables legado em `DROP`. Para liberar:

```bash
sudo iptables-legacy -P FORWARD ACCEPT
```

### 3.2 Windows (não testado)

1. Instale o **Docker Desktop** com o backend **WSL2** ativado.
2. Instale uma distro Linux no WSL (por exemplo, `wsl --install -d Ubuntu`) e, em *Settings → Resources → WSL integration*, habilite o Docker para ela.
3. Dentro da distro WSL, instale `make`, `git` e `wireguard-tools`.
4. Faça o clone **dentro do sistema de arquivos do WSL** (por exemplo, `~/gs-vila-aurora`), e não em `/mnt/c/...`, e rode todos os comandos `make` e `bash` pelo terminal da distro.

Limitações conhecidas: o projeto só foi testado em Linux. O `make vpn-host-up` depende de WireGuard funcionando dentro do WSL (kernel do WSL2 com o módulo e permissão de `sudo` na distro); se não funcionar, o painel ainda pode ser testado pelos scripts automáticos (`make fix-demo`), que acessam pelo container do operador.

## 4. Arquitetura

```
sensores ──MQTT/mTLS──► mosquitto ──► borda ══WireGuard══► nuvem-gw ──► API / painel seguro / SIEM
 (seg_iot)               (seg_iot)    (seg_wan)            (seg_wan)        │
                                                                            ▼
                                                                    PostgreSQL (seg_admin)
```

| Rede Docker | Sub-rede | Tipo | Quem está nela |
|---|---|---|---|
| `seg_wan` | 172.31.0.0/24 | normal | borda (.2), nuvem-gw (.10), operador (.20), mailpit (.25), VPN legada (.30), atacante (.66) |
| `seg_iot` | 172.31.10.0/24 | interna | mosquitto (.5), borda (.2), sensores (.10) |
| `seg_admin` | 172.31.20.0/24 | interna | PostgreSQL (.5), nuvem-gw (.10) |
| `seg_legado` | 172.31.30.0/24 | interna | VPN legada e painel legado (perfil `legado`) |
| `seg_phishing` | 172.31.40.0/24 | normal | Gophish e Mailpit (perfil `phishing`) |

Endereços do túnel WireGuard: nuvem `10.10.0.1`, borda `10.10.1.2`, operador do laboratório `10.10.2.11` e operador no host `10.10.2.10`.

A API de ingestão (porta 9000) e o painel seguro (porta 8443) só escutam no IP do túnel `10.10.0.1`. O firewall do gateway libera a 9000 só para bordas e a 8443 só para operadores. O banco não tem porta publicada. No host, só a porta UDP 51820 do WireGuard é publicada, e por padrão em `127.0.0.1`.

## 5. Mapa requisito → componente

| RT | Requisito (resumo) | Onde está |
|---|---|---|
| RT-01 | Sensores via MQTT | `campo/sensores.py` |
| RT-02 | Borda com mTLS, CA, CRL, rotação, regras locais e store-and-forward | `borda/`, `scripts/pki.py` |
| RT-03 | Modo degradado sem internet | `borda/regras.py` (ver observação abaixo) |
| RT-04 | Túnel WireGuard e segmentação | `common/wg_up.sh`, `nuvem/gw/`, `docker-compose.yml` |
| RT-05 | Banco com menor privilégio | `nuvem/db/init/` (papéis `painel_app`, `ingest_app`, `siem_app`) |
| RT-06 | Painel legado × painel seguro | `painel/legado/`, `painel/seguro/` |
| RT-07 | Coleta de logs e regras de detecção | `siem/siem.py` (R1–R5); perfil Wazuh opcional em `siem/wazuh/` |
| RT-08 | SOAR com aprovação humana para alto impacto | `soar/soar.py` e tela de comandos do painel seguro |
| RT-09 | Reprodução do INC-VA-0712 e forense | `ataque/`, `scripts/attack-demo.sh`, `forense/` |
| RT-10 | SPF, DKIM e DMARC | `phishing/dns/`, `phishing/validar_dns.sh` |
| RT-11 | Phishing simulado só com contas fictícias | `phishing/` |
| RT-16 | IA defensiva com métricas | `ia/isolation_forest.py` |
| RT-17 | Uso de LLM | **não se aplica**: nenhum LLM é usado no protótipo |
| RT-18 | Ameaças potencializadas por IA | `phishing/README-phishing.md` |
| RT-22 | Métricas de disponibilidade, MTTD, MTTR e consumo | `scripts/metricas.py` |
| RT-23 | Teste de caos | `scripts/caos.py` |

**Observação sobre o RT-03:** quando o link cai, a borda continua aplicando as regras locais (intertravamento da bomba com nível abaixo de 20% e janela de horário permitida), dispara alarmes locais (como a câmara fria da UBS) e guarda a telemetria no SQLite. Quando o link volta, envia o que ficou pendente e a nuvem confere as sequências faltantes. No laboratório, a queda é simulada desconectando a borda da rede `seg_wan`. Em campo, a mesma lógica serve para um link 4G com franquia limitada, por isso o túnel usa WireGuard (leve) e a borda envia só o necessário.

## 6. Passo a passo

### 6.1 Preparar e subir o ambiente

```bash
git clone <url-do-repositorio> gs-vila-aurora    # ou: tar xzf gs-vila-aurora.tar.gz
cd gs-vila-aurora
make setup      # 1 vez: gera .env, certificados, chaves WireGuard e contas fictícias
make up         # sobe a arquitetura segura
make status     # aguarde ~20 s; "link_wan": true indica borda conectada
```

Só se quiser começar do zero (apaga certificados, senhas, volumes e resultados):

```bash
make limpar && make setup && make up
```

### 6.2 Demonstrações e testes

| Comando | O que faz |
|---|---|
| `make attack-demo` | Reproduz o INC-VA-0712 contra o legado (VPN só com senha + SQLi + alteração da bomba) |
| `make attack-sqlmap` | Igual ao anterior, rodando também o sqlmap. O SOAR fica 10 min em modo observação (detecta, mas não bloqueia) para o sqlmap terminar |
| `make alertas` | Lista os alertas do SIEM com MTTD, MTTR e as ações do SOAR |
| `make fix-demo` | Repete os ataques contra o painel seguro (com e sem WAF), roda o sqlmap e o teste de segmentação |
| `make test-mtls` | Testa o broker: sem certificado, CA falsa, certificado válido, ACL, revogação e rotação |
| `make test-seg` | Testa VPN, segmentação e permissões do banco |
| `make test-regras` | Testa as regras do SIEM com eventos sintéticos |
| `make comprometer-sensor` | Faz um sensor se comportar mal; o SOAR o isola (revoga o certificado) |
| `make reabilitar CN=horta-umidade-01` | Devolve o sensor isolado com um certificado novo |
| `make chaos MIN=30` | Derruba o link da borda por 30 min (`make chaos-ensaio` = 2 min) |
| `make metrics` | Calcula disponibilidade, MTTD, MTTR, CPU, memória, banda e energia estimada |
| `make ia` | Treina e avalia o Isolation Forest |
| `make phishing-up` e `make phishing-campanha` | Sobe Gophish e Mailpit e roda a campanha contra contas fictícias |
| `make forensics` e `make verificar` | Coleta as evidências e confere os hashes |

Os resultados ficam em `resultados/` e as evidências em `evidencias/` (as duas pastas ficam fora do Git).

**Importante sobre o `make test-seg`:** rode com a VPN do host **desligada**:

```bash
bash scripts/vpn-host.sh down     # ou: make vpn-host-down
make test-seg
```

Com a VPN do host ligada, o próprio host passa a encaminhar o tráfego do container atacante pelo túnel, e o item `atacante -> IP do túnel 10.10.0.1:8443` falha. Isso foi observado no notebook de testes e não indica falha na segmentação dos containers.

### 6.3 Abrir o painel seguro no navegador

```bash
make vpn-host-up                 # conecta este computador à VPN como operador
make totp U=coord.marina         # mostra o código MFA atual
```

Acesse <https://10.10.0.1:8443>. As senhas das contas fictícias ficam em `segredos/usuarios.json`. O certificado do painel é da CA do laboratório: importe `pki/painel/ca.crt` no navegador ou aceite o aviso. Ao terminar, rode `make vpn-host-down`.

| Login | Papel |
|---|---|
| `coord.marina` | coordenação (aprova comandos de alto impacto) |
| `op.joao` | operador |
| `tec.rafael` | técnico |
| `aud.helena` | auditor |

### 6.4 Repetir os testes

- **Não é preciso** rodar `make limpar` nem `make setup` para repetir os testes. Com o ambiente já criado, basta `make up` (se estiver parado) e os comandos da seção 6.2.
- O `make forensics` sempre gera uma pasta nova em `evidencias/`, com **hashes diferentes** dos citados no laudo, porque os logs coletados mudam a cada execução. Os hashes do laudo continuam valendo para a coleta original.
- O caos de 30 min já tem uma rodada válida (seção 8). Só repita (`make chaos MIN=30`) se quiserem números novos; para conferir o funcionamento, o `make chaos-ensaio` (2 min) é suficiente.
- Desligue a VPN do host antes do `make test-seg` (`make vpn-host-down`).

```bash
make vpn-host-down        # se a VPN do host estiver ligada
make up && make status
make test-mtls && make test-seg && make test-regras
make attack-demo && make alertas
make fix-demo
make chaos-ensaio && make metrics
make ia
make forensics && make verificar
```

### 6.5 Encerrar

```bash
make down       # para os containers e mantém os dados
make limpar     # apaga containers, volumes, certificados, segredos e resultados
```

## 7. Roteiro de demonstração para o vídeo

Sugestão de ordem para a gravação, com o que deixar visível na tela ou capturar em print:

| # | Tema | O que mostrar | Comando |
|---|---|---|---|
| C1 | Sensores e mTLS | Rejeição sem certificado, com CA falsa e com certificado revogado; conexão com certificado válido e após rotação | `make test-mtls` |
| C2 | Continuidade sem internet | Pendentes subindo com o link caído, alarme local da câmara fria e sincronização com perda zero | `make chaos-ensaio` (ou `MIN=30`) |
| C3 | Segmentação e VPN | Lista de `[PASSOU]` do atacante, operador, borda e sensores | `make test-seg` (VPN do host desligada) |
| C4 | Antes: ataque no legado | Login VPN só com senha, vazamento do cadastro e agendamento 00:00–23:59 rejeitado pela borda | `make attack-demo` |
| C5 | Depois: painel seguro | 19/19 testes com e sem WAF e sqlmap sem injeção | `make fix-demo` |
| C6 | MFA e RBAC | Login com TOTP, telas diferentes por papel e aprovação de comando só pela coordenação | `make vpn-host-up` + navegador |
| C7 | Detecção e resposta | Alertas R1, R2 e R4 com MTTD abaixo de 1 s, bloqueio automático e pedido de aprovação pendente | `make alertas` |
| C8 | Forense | Pasta `evidencias/INC-VA-0712-*`, cadeia de custódia, linha do tempo e "INTEGRIDADE OK" | `make forensics` e `make verificar` |
| C9 | IA, phishing e métricas | `ia-metricas.json`, validação SPF/DKIM/DMARC, métricas da campanha e `metricas-*.json` | `make ia`, `make phishing-campanha`, `make metrics` |

## 8. Resultados de referência

Os números de caos, MTTD/MTTR e consumo vêm da rodada válida no notebook Linux da equipe. Os demais itens foram medidos no ambiente de desenvolvimento (Linux, Docker). Os valores variam um pouco a cada execução; os arquivos gerados em `resultados/` são a fonte para o relatório.

| Item | Resultado |
|---|---|
| SQLi no legado | login na VPN só com senha, 24 registros vazados, agendamento da bomba alterado; sqlmap extraiu a tabela `usuarios` |
| SQLi no painel seguro | 19/19 testes com WAF e 19/19 sem WAF; sqlmap: "all tested parameters do not appear to be injectable" |
| mTLS | sem certificado e CA falsa: recusados; válido: aceito; tópico fora da ACL: "Not authorized"; revogado: recusado; após rotação: aceito |
| Segmentação | 22/22 verificações conforme o esperado |
| Regras do SIEM | 11/11 casos sintéticos corretos |
| Caos (30 min, notebook) | queda de 30,47 min; 4847 mensagens geradas e 4847 recebidas após a reconciliação; perda 0 (0,0%); sincronização em 18,5 s; 1 alarme local sem internet (câmara fria a 8,06 °C); pico de 4753 pendentes; 1828,1 s de operação autônoma |
| MTTD / MTTR (notebook) | 7 alertas; MTTD médio 0,446 s; MTTR médio 0,438 s nas respostas automáticas |
| Consumo da borda (notebook) | 0,39% de CPU e 21 MiB de memória; túnel 9,31 kbps de envio e 5,12 kbps de recebimento (~100,6 MB/dia) |
| Caos rápido (2 min) | 334/334 mensagens recebidas, perda 0, sincronização em 16,6 s |
| Isolation Forest | precisão 0,692, revocação 0,379, F1 0,49, 37 falsos positivos (3,08/dia), 19 de 25 eventos detectados |
| Phishing (simulado) | 4 enviados, 3 abertos, 1 clique, 0 envios de dados, 2 reportes |

A energia é uma **estimativa** por modelo linear de um Raspberry Pi 4, não uma medição. As métricas de phishing vêm de comportamento simulado (semente fixa) sobre contas fictícias.

## 9. Solução de problemas

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| Containers não se comunicam | Política `FORWARD` do iptables legado em `DROP` | `sudo iptables-legacy -P FORWARD ACCEPT` |
| Painel ou API somem depois de reiniciar só o `nuvem-gw` | Os serviços que compartilham a rede do gateway perdem a interface | `make up` |
| `make test-seg` falha em `atacante -> 10.10.0.1:8443` | VPN do host ligada | `make vpn-host-down` e rode de novo |
| Código TOTP recusado | Relógio fora de sincronia | Verifique o NTP com `timedatectl` |
| Não consigo apagar `evidencias/` | A coleta deixa os itens somente leitura | `chmod -R u+w evidencias && rm -rf evidencias/INC-*` |
| Porta 51820 ocupada | Outro WireGuard ou ambiente antigo | `make down` ou ajuste `WG_BIND` no `.env` |

## 10. Uso de IA

| Uso | Ferramenta | Onde |
|---|---|---|
| Apoio na escrita de código, scripts e documentação | Assistente de IA | Revisado e testado pela equipe |
| Detecção de anomalias no protótipo | Isolation Forest (scikit-learn), sem LLM | `ia/isolation_forest.py` |
| LLM dentro do produto | Não utilizado | RT-17 não se aplica |

> *A completar pela equipe: descrição de como a IA foi usada, o que foi revisado ou alterado e declaração de responsabilidade pelo conteúdo entregue.*

## 11. Estrutura do repositório

```
gs-vila-aurora/
├── Makefile, docker-compose.yml, .env.example
├── docker/py/          imagem base dos serviços Python
├── common/             log em JSON e subida do WireGuard
├── campo/              sensores MQTT
├── borda/              Mosquitto, regras locais e fila SQLite
├── nuvem/              gateway, API e schema do PostgreSQL
├── painel/             painel seguro, painel legado e VPN legada
├── siem/  soar/        detecção e resposta (+ perfil Wazuh opcional, não testado)
├── ataque/  forense/   reprodução do incidente e coleta de evidências
├── ia/  phishing/      Isolation Forest, DNS e campanha simulada
├── testes/  scripts/   testes automáticos e scripts de apoio
├── docs/               modelo de ameaças (STRIDE)
└── pki/ segredos/ resultados/ evidencias/   gerados localmente, fora do Git
```

## 12. Ética

Uso exclusivamente acadêmico. A campanha de phishing só pode mirar as contas fictícias `@vilaaurora.example` criadas pela equipe (Lei 12.737/2012). A VPN legada e o painel legado não devem ser expostos fora do `127.0.0.1`.

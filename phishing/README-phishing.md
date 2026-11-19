# Phishing simulado e fator humano (RT-10, RT-11, RT-18)

> **Ética (RT-11):** a campanha só pode ter como alvo **contas fictícias criadas pela
> equipe**. É proibido mirar pessoas reais, a FIAP ou terceiros (Lei 12.737/2012).
> Tudo roda no laboratório isolado, com e-mail capturado pelo **Mailpit** (não sai para a internet).

## 1. Proteção do domínio fictício (RT-10)
Domínio do projeto: **vilaaurora.example** (reservado para documentação, RFC 2606 - nunca envia e-mail real).
Registros DNS recomendados em `phishing/dns/vilaaurora.zone`:

- **SPF**: autoriza só os servidores de envio; `-all` (falha dura) para o resto.
- **DKIM**: assinatura criptográfica do e-mail (seletor `s1`).
- **DMARC**: política mínima **quarantine** (o enunciado pede no mínimo isso; usamos `quarantine`
  com `pct=100` e relatórios `rua`), alinhando SPF e DKIM.

Verificação local (sem publicar nada): `bash phishing/validar_dns.sh` confere a sintaxe de SPF/DKIM/DMARC.
O `make setup` gera um par de chaves DKIM real (RSA 2048) em `segredos/dkim/` e o registro TXT
correspondente em `segredos/dkim/s1._domainkey.txt` (a chave privada nunca vai para o Git). Em produção, validar com `dig TXT` e ferramentas como MXToolbox.

## 2. Campanha simulada (RT-11)
Perfil opcional do compose com **Gophish** + **Mailpit**:

```
make phishing-up          # sobe gophish (admin 127.0.0.1:3333) e mailpit (127.0.0.1:8025)
```

1. Acesse o admin do Gophish (a senha inicial aparece em `docker logs va-gophish`).
2. **Sending Profile**: host SMTP `va-mailpit:1025`, sem TLS (laboratório).
3. **Users & Groups**: importe **somente** `phishing/alvos_ficticios.csv` (contas @vilaaurora.example da equipe).
4. **Email Template**: use `phishing/modelo_email.html` (réplica do e-mail "da prefeitura" do INC-VA-0712).
5. **Landing Page**: clone simples com captura desabilitada ou apontando para a página de treino.
6. Dispare a campanha e colete as métricas em *Campaign results*:
   - **enviados, abertos, cliques, dados submetidos, reportes**.
   - Exporte o CSV e salve em `resultados/phishing-<data>.csv`.

As métricas pedidas pela rubrica (abertura, clique, submissão, reporte) saem direto do painel do Gophish.
Como é um ambiente de laboratório sem pessoas reais, os números são ilustrativos do fluxo; documente-os
como tal no E3.

## 3. Ameaças potencializadas por IA e controles (RT-18)
O INC-VA-0712 usou **texto gerado por IA** (sem erros, personalizado) e **voz clonada** do secretário.
Controles adotados (e onde aparecem no protótipo):

| Ameaça | Controle | Onde |
|---|---|---|
| E-mail de phishing convincente (IA) | SPF/DKIM/DMARC + banner de "e-mail externo" + treino | DNS + política |
| Voz clonada pedindo urgência | **Verificação fora de banda**: ligar para número oficial e confirmar **palavra-código** da semana | aviso no `login.html`, item 4 do plano |
| Credencial capturada | **MFA TOTP** no painel novo (só senha não basta) | `painel/seguro` |
| Reuso remoto da credencial | Acesso só por **VPN com MFA**; login anômalo detectado (R1) e sessão encerrada (SOAR) | VPN + SIEM/SOAR |

## 4. Plano de conscientização para voluntários (não técnicos)
- Linguagem simples, exemplos reais do bairro; folheto de 1 página.
- Regra de ouro: **"A equipe nunca pede senha por e-mail, WhatsApp ou áudio."**
- **Palavra-código da semana** para qualquer pedido urgente; na dúvida, ligar para o número oficial.
- Como **reportar** um e-mail suspeito (encaminhar para um endereço único, ex.: seguranca@vilaaurora.example).
- Micro-treinos trimestrais e um phishing simulado por semestre, com retorno sem exposição de quem clicou.

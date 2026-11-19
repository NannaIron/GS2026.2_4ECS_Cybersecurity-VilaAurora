#!/bin/sh
# Esquema do banco da nuvem + usuários com PRIVILÉGIO MÍNIMO (RT-08).
# Executado uma única vez pelo entrypoint do postgres na criação do volume.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE TABLE usuarios (
  id serial PRIMARY KEY,
  login text UNIQUE NOT NULL,
  nome text NOT NULL,
  email text,
  telefone text,
  perfil text NOT NULL CHECK (perfil IN ('operador','tecnico','coordenacao','auditor','voluntario')),
  senha_hash text NOT NULL,          -- PBKDF2-SHA256 (painel seguro)
  senha_md5_legado text,             -- MD5 sem sal usado pelo sistema legado (removível após migração)
  totp_secret text,
  ativo boolean NOT NULL DEFAULT true
);
-- Histórico de acessos às portas: crachá PSEUDONIMIZADO (HMAC), sem nome (LGPD, RT-19)
CREATE TABLE acessos (
  id serial PRIMARY KEY,
  ts timestamp NOT NULL,
  espaco text NOT NULL,
  porta text NOT NULL,
  cracha_pseudo text NOT NULL,
  perfil text NOT NULL,
  resultado text NOT NULL
);
CREATE TABLE agendamento_bomba (
  id serial PRIMARY KEY,
  espaco text NOT NULL,
  hora_inicio time NOT NULL,
  hora_fim time NOT NULL,
  ativo boolean NOT NULL DEFAULT true,
  atualizado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_por text NOT NULL DEFAULT 'sistema'
);
INSERT INTO agendamento_bomba (espaco,hora_inicio,hora_fim) VALUES ('escola','06:30','08:30'),('escola','16:00','18:00');
CREATE TABLE telemetria (
  id bigserial PRIMARY KEY,
  borda text NOT NULL,
  seq bigint NOT NULL,
  ts timestamptz NOT NULL,
  topico text NOT NULL,
  payload jsonb NOT NULL,
  recebido_em timestamptz NOT NULL DEFAULT now(),
  UNIQUE (borda, seq)                -- idempotência da reconciliação
);
CREATE TABLE comandos_borda (
  id serial PRIMARY KEY,
  criado_em timestamptz NOT NULL DEFAULT now(),
  borda text NOT NULL DEFAULT 'borda-vila',
  acao text NOT NULL,
  alvo text NOT NULL,
  risco text NOT NULL CHECK (risco IN ('baixo','alto')),
  status text NOT NULL CHECK (status IN ('pendente','aprovado','rejeitado','executado','recusado_borda')),
  solicitado_por text NOT NULL,
  motivo text,
  aprovado_por text,
  aprovado_em timestamptz,
  executado_em timestamptz,
  resultado text
);
CREATE TABLE alertas (
  id serial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  regra text NOT NULL,
  severidade text NOT NULL,
  resumo text NOT NULL,
  detalhe jsonb,
  ts_evento timestamptz,
  resposta text
);
CREATE TABLE auditoria (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  usuario text,
  acao text NOT NULL,
  detalhe text,
  ip text
);

-- ===== Usuários de banco com privilégio mínimo =====
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE ROLE painel_app LOGIN PASSWORD '${PAINEL_APP_PASSWORD}';
CREATE ROLE ingest_app LOGIN PASSWORD '${INGEST_APP_PASSWORD}';
CREATE ROLE siem_app   LOGIN PASSWORD '${SIEM_APP_PASSWORD}';
GRANT USAGE ON SCHEMA public TO painel_app, ingest_app, siem_app;

-- painel: NÃO lê email/telefone/senha_md5 (só colunas necessárias para autenticar)
GRANT SELECT (id, login, nome, perfil, senha_hash, totp_secret, ativo) ON usuarios TO painel_app;
GRANT SELECT ON acessos, telemetria, alertas TO painel_app;
GRANT SELECT, UPDATE (hora_inicio, hora_fim, ativo, atualizado_em, atualizado_por) ON agendamento_bomba TO painel_app;
GRANT SELECT, INSERT, UPDATE (status, aprovado_por, aprovado_em, motivo) ON comandos_borda TO painel_app;
GRANT SELECT, INSERT ON auditoria TO painel_app;
GRANT USAGE ON SEQUENCE comandos_borda_id_seq, auditoria_id_seq TO painel_app;

-- ingestão: grava telemetria, lê agendamento e comandos aprovados
GRANT SELECT, INSERT ON telemetria TO ingest_app;
GRANT INSERT ON acessos TO ingest_app;
GRANT USAGE ON SEQUENCE acessos_id_seq TO ingest_app;
GRANT USAGE ON SEQUENCE telemetria_id_seq TO ingest_app;
GRANT SELECT ON agendamento_bomba TO ingest_app;
GRANT SELECT, UPDATE (status, executado_em, resultado) ON comandos_borda TO ingest_app;

-- SIEM/SOAR: grava alertas e comandos de baixo risco / pedidos de aprovação
GRANT SELECT, INSERT, UPDATE (resposta) ON alertas TO siem_app;
GRANT USAGE ON SEQUENCE alertas_id_seq, comandos_borda_id_seq TO siem_app;
GRANT SELECT, INSERT ON comandos_borda TO siem_app;
GRANT SELECT ON telemetria TO siem_app;
ALTER ROLE aurora_owner SET log_statement = 'all';
ALTER ROLE painel_app SET log_statement = 'all';
SQL

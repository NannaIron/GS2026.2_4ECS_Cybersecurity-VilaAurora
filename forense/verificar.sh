#!/usr/bin/env bash
# Confere a integridade das evidências (SHA-256) contra o manifesto da coleta.
set -euo pipefail
DIR="${1:?uso: forense/verificar.sh evidencias/INC-VA-0712-...}"
cd "$DIR" && sha256sum -c SHA256SUMS && echo "INTEGRIDADE OK: nenhuma evidência foi alterada desde a coleta."

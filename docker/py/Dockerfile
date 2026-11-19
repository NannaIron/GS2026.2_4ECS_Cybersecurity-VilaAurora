# Imagem base única (Python 3 + ferramentas de rede) usada por todos os serviços próprios
# do protótipo: sensores, borda, nuvem, painéis, SIEM/SOAR, operador e atacante.
# Alpine + pacotes do próprio Alpine (numpy/scikit-learn já compilados para musl).
FROM alpine:3.22
RUN apk add --no-cache python3 py3-pip py3-numpy py3-scikit-learn py3-psycopg2 py3-flask \
        py3-gunicorn py3-requests wireguard-tools-wg iproute2 iptables curl openssl bash \
        tzdata sqlite procps mosquitto-clients
COPY docker/py/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt
ENV TZ=America/Sao_Paulo PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY . /app

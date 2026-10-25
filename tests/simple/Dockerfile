ARG DISTRIBUTION=debian:bookworm-slim
FROM ${DISTRIBUTION}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-php php-cli php-fpm python3 ca-certificates openssl curl systemd \
    && rm -rf /var/lib/apt/lists/*
COPY tests/simple/systemctl.py /usr/bin/systemctl
RUN chmod 755 /usr/bin/systemctl
COPY tests/simple/scenario.py /scenario.py
CMD ["python3", "/scenario.py"]

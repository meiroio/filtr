FROM ubuntu:24.04
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
      amd64) checksum=620bb9e16fb53eabc9a3fc45f88bdb41fefa3fee5c05e75892011ce320391716 ;; \
      arm64) checksum=99a790eb8c3e0feaca974bd6b32f0f8d4426a0c5b289f39e833e5b2c7529cd39 ;; \
      *) exit 2 ;; \
    esac \
    && curl --fail --location --output /usr/local/bin/oha \
      "https://github.com/hatoo/oha/releases/download/v1.16.0/oha-linux-$TARGETARCH" \
    && printf '%s  /usr/local/bin/oha\n' "$checksum" | sha256sum --check - \
    && chmod 755 /usr/local/bin/oha
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/oha"]

# syntax=docker/dockerfile:1
FROM rust:1.99.1-bookworm AS builder
ARG TARGETARCH
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY rules/ rules/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=filtr-target-${TARGETARCH},target=/build/target,sharing=locked \
    cargo build --release --locked --bin filtr \
    && cp target/release/filtr /usr/local/bin/filtr

FROM builder AS demo-builder
COPY examples/upstream.rs examples/upstream.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=filtr-target-${TARGETARCH},target=/build/target,sharing=locked \
    cargo build --release --locked --example upstream \
    && cp target/release/examples/upstream /usr/local/bin/filtr-demo-upstream

FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10001 -g 10001 /data
USER 10001:10001
WORKDIR /data

FROM runtime-base AS demo
COPY --from=demo-builder /usr/local/bin/filtr-demo-upstream /usr/local/bin/filtr-demo-upstream
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/filtr-demo-upstream"]
CMD ["0.0.0.0:3000"]

FROM runtime-base AS runtime
COPY --from=builder /usr/local/bin/filtr /usr/local/bin/filtr
COPY --chmod=0755 deploy/probe.sh /usr/local/bin/filtr-probe
ENV FILTR_LISTEN=0.0.0.0:8080 \
    FILTR_ADMIN_LISTEN=127.0.0.1:9090 \
    FILTR_SBOM=/data/sbom.json
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=1560s --retries=3 \
    CMD ["/usr/local/bin/filtr-probe", "live"]
ENTRYPOINT ["/usr/local/bin/filtr"]

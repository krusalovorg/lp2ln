# syntax=docker/dockerfile:1.7
# Production image for lp2lnd with health probes and graceful shutdown.

FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY crates/lp2ln-core-v2 ./crates/lp2ln-core-v2
COPY crates/lp2lnd ./crates/lp2lnd
COPY crates/lp2ln-db-export ./crates/lp2ln-db-export

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p lp2lnd \
    && cp /build/target/release/lp2lnd /tmp/lp2lnd

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpcap0.8 \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/lp2lnd /usr/local/bin/lp2lnd

RUN mkdir -p /app/db /app/logs \
    && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin lp2ln \
    && chown -R lp2ln:lp2ln /app \
    && chmod +x /usr/local/bin/lp2lnd

WORKDIR /app
USER lp2ln

ENV RUST_BACKTRACE=0 \
    LP2LND_HEALTH_ADDR=127.0.0.1:9088

VOLUME ["/app/db", "/app/logs"]

# listents/ports are configured via options json;
# expose common defaults + internal health endpoint.
EXPOSE 8080/tcp 8080/udp 9088/tcp

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD curl -fsS "http://${LP2LND_HEALTH_ADDR}/readyz" || exit 1

STOPSIGNAL SIGTERM

ENTRYPOINT ["tini", "--", "lp2lnd"]
CMD ["-o", "/app/options.json"]

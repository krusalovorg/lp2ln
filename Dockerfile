# syntax=docker/dockerfile:1
# Образ рантайма: бинарник lp2lnd (daemon из crates/lp2lnd).
# Конфиг: смонтируйте JSON с опциями узла в /app/options.json или передайте аргументы после имени образа.

FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml ./
COPY crates/lp2ln-core-v2 ./crates/lp2ln-core-v2
COPY crates/lp2lnd ./crates/lp2lnd
COPY crates/lp2ln-db-export ./crates/lp2ln-db-export

RUN cargo build --release -p lp2lnd

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/lp2lnd /usr/local/bin/lp2lnd

RUN mkdir -p /app/db /app/logs \
    && useradd --system --home-dir /app --shell /usr/sbin/nologin lp2ln \
    && chown -R lp2ln:lp2ln /app

WORKDIR /app
USER lp2ln

VOLUME ["/app/db", "/app/logs"]

# Порты и адреса бинда задаются в options.json (listens, debug_server).
EXPOSE 8080/tcp 8080/udp

ENTRYPOINT ["lp2lnd"]
CMD ["-o", "/app/options.json"]

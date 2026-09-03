# matter-server (Rust): single static-ish binary, debian slim runtime.
# Build context = matter-fast/server (this directory). Only the `matter-server`
# bin and its deps are built; backend-rsm (rs-matter) is not part of this image yet.
FROM docker.io/rust:1-slim AS builder
# No pkg-config/libssl-dev needed: the whole dependency tree uses rustls, not
# openssl/native-tls (verified with `cargo tree -p matter-server | grep -i openssl`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo build --release -p matter-server \
    && cp target/release/matter-server ./matter-server \
    && rm -rf target ~/.cargo/registry

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data \
    && chown 1000:1000 /data

COPY --from=builder /build/matter-server /usr/local/bin/matter-server

ENV STORAGE_PATH=/data
ENV PORT=5580
ENV LOG_LEVEL=info
ENV MATTER_BACKEND=mc

VOLUME ["/data"]
EXPOSE 5580

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --start-interval=5s --retries=6 \
    CMD curl -fsS -o /dev/null -m 5 "http://localhost:${PORT:-5580}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/matter-server"]
CMD []

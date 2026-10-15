FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY certs ./certs
COPY .env.example ./.env

# Build-time environment defaults. Runtime values may override these.
ENV SOCKS5_PORT=0.0.0.0:3000
ENV CACHE_DURATION_SECS=86400
ENV CACHE_ENTRY_LIMIT=10000
ENV CERT_PATH=certs/cert.pem
ENV KEY_PATH=certs/key.pem

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rust-socks /app/rust-socks
COPY --from=builder /app/certs /app/certs
COPY --from=builder /app/.env /app/.env

EXPOSE 3000

CMD ["/app/rust-socks"]
FROM rust:1.88-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY certs ./certs

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rust-socks /app/rust-socks
COPY --from=builder /app/certs /app/certs

EXPOSE 3000
EXPOSE 3001

CMD ["/app/rust-socks"]

FROM rust:1.88 AS builder

WORKDIR /app

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/target/release/rust-socks /app/rust-socks

EXPOSE 3000

EXPOSE 3001

CMD ["/app/rust-socks"]

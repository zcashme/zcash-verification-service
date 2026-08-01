# Build stage
FROM rust:bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Build release binary
RUN cargo build --release && strip target/release/zfa-backend

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zfa-backend /usr/local/bin/zfa-backend

ENV RUST_LOG=info
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/zfa-backend"]
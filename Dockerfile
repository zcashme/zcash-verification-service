# Build stage
FROM rust:bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Build release binary
RUN cargo build --release

# Runtime stage — match zvs-runtime:bookworm
FROM debian:bookworm-slim

# Install runtime deps (libsqlite3, ca-certificates for TLS)
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zfa-backend /usr/local/bin/zfa-backend

# Data directory mount point
VOLUME /app/zfa-data

# Zcash params mount point
VOLUME /root/.zcash-params

ENTRYPOINT ["/usr/local/bin/zfa-backend"]

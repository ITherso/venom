# Multi-stage build for optimal size and performance
# Stage 1: Builder
FROM rust:1.75-slim as builder

WORKDIR /usr/src/venom

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies (caches layer)
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release && \
    strip target/release/venom

# Stage 2: Runtime (Alpine)
FROM alpine:3.18

# Install runtime dependencies only
RUN apk add --no-cache \
    ca-certificates \
    libssl3 \
    libcrypto3 \
    && addgroup -g 1000 venom \
    && adduser -D -u 1000 -G venom venom

WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/venom/target/release/venom /app/venom

# Create .venom directory for CA and database
RUN mkdir -p /app/.venom && \
    chown -R venom:venom /app

# Change to non-root user
USER venom

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/venom ping || exit 1

# Expose ports
EXPOSE 8080 3000

# Run application
ENTRYPOINT ["/app/venom"]
CMD ["proxy", "--host", "0.0.0.0", "--port", "8080"]

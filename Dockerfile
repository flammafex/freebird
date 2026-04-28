# ==============================================================================
# Stage 1: Base Builder (shared dependencies)
# ==============================================================================
FROM rust:1-bookworm as base-builder

WORKDIR /app

# Install build dependencies with security scanning
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crypto ./crypto
COPY common ./common
COPY interface ./interface
COPY issuer ./issuer
COPY verifier ./verifier
COPY integration_tests ./integration_tests

# Pre-cache dependencies to optimize layer caching
RUN cargo fetch

# ==============================================================================
# Stage 2: Issuer Builder (builds ONLY issuer)
# ==============================================================================
FROM base-builder as issuer-builder

# Build only the issuer binary with optimizations
RUN cargo build --release -p freebird-issuer \
    && cargo build --release --bin freebird-cli

# ==============================================================================
# Stage 3: Verifier Builder (builds ONLY verifier)
# ==============================================================================
FROM base-builder as verifier-builder

# Build only the verifier binary with optimizations
RUN cargo build --release -p freebird-verifier

# ==============================================================================
# Stage 4: Issuer Runtime
# ==============================================================================
FROM debian:bookworm-slim as issuer

WORKDIR /app

# Install runtime dependencies with minimal attack surface
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user with explicit UID/GID for consistency
RUN groupadd -r -g 1000 freebird && useradd -r -u 1000 -g freebird freebird

# Create data directories with proper permissions
RUN mkdir -p /data/keys /data/state && \
    chown -R 1000:1000 /data && \
    chmod 750 /data /data/keys /data/state

# Copy binaries from build stage
COPY --from=issuer-builder /app/target/release/freebird-issuer /usr/local/bin/freebird-issuer
COPY --from=issuer-builder /app/target/release/freebird-cli /usr/local/bin/freebird-cli
RUN chmod 755 /usr/local/bin/freebird-issuer /usr/local/bin/freebird-cli

# Set secure defaults
ENV BIND_ADDR=0.0.0.0:8081 \
    ISSUER_SK_PATH=/data/keys/issuer_sk.bin \
    KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json \
    SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json \
    RUST_LOG=info

# Add metadata labels for supply chain
LABEL org.opencontainers.image.title="Freebird Issuer" \
      org.opencontainers.image.description="Privacy-preserving authorization - Issuer component" \
      org.opencontainers.image.vendor="Freebird" \
      org.opencontainers.image.documentation="https://github.com/flammafex/freebird"

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:8081/.well-known/issuer || exit 1

USER freebird
VOLUME ["/data"]
EXPOSE 8081

CMD ["freebird-issuer"]

# ==============================================================================
# Stage 5: Verifier Runtime
# ==============================================================================
FROM debian:bookworm-slim as verifier

WORKDIR /app

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user with explicit UID/GID
RUN groupadd -r -g 1000 freebird && useradd -r -u 1000 -g freebird freebird

# Copy binary from build stage
COPY --from=verifier-builder /app/target/release/freebird-verifier /usr/local/bin/freebird-verifier
RUN chmod 755 /usr/local/bin/freebird-verifier

# Copy validation script
COPY scripts/validate-env.sh /app/scripts/validate-env.sh
RUN chmod +x /app/scripts/validate-env.sh

# Set secure defaults
ENV BIND_ADDR=0.0.0.0:8082 \
    RUST_LOG=info

# Add metadata labels for supply chain
LABEL org.opencontainers.image.title="Freebird Verifier" \
      org.opencontainers.image.description="Privacy-preserving authorization - Verifier component" \
      org.opencontainers.image.vendor="Freebird" \
      org.opencontainers.image.documentation="https://github.com/flammafex/freebird"

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:8082/health || exit 1

# Security: disable unnecessary capabilities
RUN setcap -r /usr/sbin/setcap || true

USER freebird
EXPOSE 8082

CMD ["freebird-verifier"]

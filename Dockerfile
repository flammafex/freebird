# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM rust:latest as builder

WORKDIR /app

# Install build dependencies (OpenSSL is required for reqwest)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire workspace
# Note: For better caching in a larger project, you would copy Cargo.toml files 
# first to cache dependencies, but for this size, copying all is efficient enough.
COPY . .

# Build the release binaries
# We build the whole workspace to ensure all shared crates are compiled
RUN cargo build --release

# ==============================================================================
# Stage 2: Issuer Runtime
# ==============================================================================
FROM debian:bookworm-slim as freebird-issuer

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r freebird && useradd -r -g freebird freebird

# Create directories for state persistence
RUN mkdir -p /data/keys /data/state && \
    chown -R freebird:freebird /data

# Copy binary from builder
COPY --from=builder /app/target/release/freebird-issuer /usr/local/bin/freebird-issuer

# Set environment defaults for container
ENV BIND_ADDR=0.0.0.0:8081
ENV ISSUER_SK_PATH=/data/keys/issuer_sk.bin
ENV KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json
ENV SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json

# Switch to non-root userwitness
USER freebird
VOLUME ["/data"]
EXPOSE 8081

CMD ["freebird-issuer"]

# ==============================================================================
# Stage 3: Verifier Runtime
# ==============================================================================
FROM debian:bookworm-slim as freebird-verifier

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r freebird && useradd -r -g freebird freebird

# Copy binary from builder
COPY --from=builder /app/target/release/freebird-verifier /usr/local/bin/freebird-verifier

ENV BIND_ADDR=0.0.0.0:8082

USER freebird
EXPOSE 8082

CMD ["freebird-verifier"]
# ==============================================================================
# Stage 1: Base Builder (shared dependencies)
# ==============================================================================
FROM rust:latest as base-builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# ==============================================================================
# Stage 2: Issuer Builder (builds ONLY issuer)
# ==============================================================================
FROM base-builder as issuer-builder

# Build only the issuer binary
RUN cargo build --release -p freebird-issuer

# ==============================================================================
# Stage 3: Verifier Builder (builds ONLY verifier)
# ==============================================================================
FROM base-builder as verifier-builder

# Build only the verifier binary
RUN cargo build --release -p freebird-verifier

# ==============================================================================
# Stage 4: Issuer Runtime
# ==============================================================================
FROM debian:bookworm-slim as issuer

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r freebird && useradd -r -g freebird freebird
RUN mkdir -p /data/keys /data/state /data/federation && \
    chown -R freebird:freebird /data

# Copy from issuer-specific builder
COPY --from=issuer-builder /app/target/release/freebird-issuer /usr/local/bin/freebird-issuer
RUN chmod +x /usr/local/bin/freebird-issuer

ENV BIND_ADDR=0.0.0.0:8081
ENV ISSUER_SK_PATH=/data/keys/issuer_sk.bin
ENV KEY_ROTATION_STATE_PATH=/data/keys/key_rotation_state.json
ENV SYBIL_INVITE_PERSISTENCE_PATH=/data/state/invitations.json

USER freebird
VOLUME ["/data"]
EXPOSE 8081

CMD ["freebird-issuer"]

# ==============================================================================
# Stage 5: Verifier Runtime
# ==============================================================================
FROM debian:bookworm-slim as verifier

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r freebird && useradd -r -g freebird freebird

# Copy from verifier-specific builder
COPY --from=verifier-builder /app/target/release/freebird-verifier /usr/local/bin/freebird-verifier
RUN chmod +x /usr/local/bin/freebird-verifier

ENV BIND_ADDR=0.0.0.0:8082

USER freebird
EXPOSE 8082

CMD ["freebird-verifier"]

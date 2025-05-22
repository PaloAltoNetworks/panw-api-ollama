FROM rust:1.86-slim AS builder

# Install SSL certificates and dependencies required for OpenSSL
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

WORKDIR /usr/src/app
COPY . .

# Build the application with release profile
RUN cargo build --release

# Create a smaller runtime image
FROM debian:bookworm-slim

# Install minimal packages needed for runtime and security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# Create a non-root user and group
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/panw-api-ollama .

# Set proper permissions
RUN chown -R appuser:appuser /app

# Set environment variables with defaults
ENV SERVER_HOST="0.0.0.0" \
    SERVER_PORT=11435 \
    SERVER_DEBUG_LEVEL="INFO" \
    OLLAMA_BASE_URL="http://ollama:11434" \
    SECURITY_BASE_URL="https://service.api.aisecurity.paloaltonetworks.com" \
    SECURITY_API_KEY="" \
    SECURITY_PROFILE_NAME="" \
    SECURITY_APP_NAME="panw-api-ollama" \
    SECURITY_APP_USER="docker"

# Note: Sensitive environment variables like SECURITY_API_KEY and SECURITY_PROFILE_NAME 
# should be passed at runtime, not defined in the Dockerfile

# Switch to non-root user
USER appuser

# Expose the port that the application will listen on
EXPOSE 11435

# Command to run the application
CMD ["./panw-api-ollama"]
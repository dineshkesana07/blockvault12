# ==============================================================================
# BLOCKVAULT C++ Backend - Multi-Stage Production Dockerfile
# ==============================================================================
# Builds the C++ Crow REST API server for Linux deployment on Render.
# All dependencies are downloaded and compiled inside the container.
# ==============================================================================

# Stage 1: Build
FROM debian:bookworm-slim AS builder

# Install build tools, compiler, autotools, pkg-config, and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    wget \
    ca-certificates \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libcurl4-openssl-dev \
    xz-utils \
    unzip \
    file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---------- Download and build libsodium ----------
# Uses official source archive with -fL (fails fast on HTTP errors)
RUN curl -fL -o libsodium.tar.gz \
    https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz && \
    tar xzf libsodium.tar.gz && \
    cd libsodium-1.0.20 && \
    ./configure --disable-shared --enable-static --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /app && rm -rf libsodium-1.0.20 libsodium.tar.gz

# Ensure pkg-config discovers libsodium installed in /usr/local/lib/pkgconfig
ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH}"

# ---------- Download Asio headers ----------
RUN curl -fL -o asio.tar.gz \
    https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz && \
    tar xzf asio.tar.gz && \
    rm -f asio.tar.gz

# ---------- Copy application source and build configuration ----------
COPY CMakeLists.txt ./
COPY include/ include/
COPY src/ src/
COPY tests/ tests/

# ---------- Configure and build with CMake ----------
RUN cmake -S . -B build -G "Ninja" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && \
    cmake --build build --config Release -j$(nproc)

# Verify the binary was produced
RUN ls -la build/blockvault_server && file build/blockvault_server

# ==============================================================================
# Stage 2: Production runtime (minimal image)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash blockvault

# Create persistent data directory (Render disk mount point)
RUN mkdir -p /var/data && chown blockvault:blockvault /var/data

WORKDIR /app

# Copy only the compiled binary (static libsodium is linked in)
COPY --from=builder /app/build/blockvault_server /app/blockvault_server

# Make executable
RUN chmod +x /app/blockvault_server

# Switch to non-root user
USER blockvault

# Production environment defaults
# Render automatically injects PORT; default 10000 as fallback
ENV PORT=10000
ENV DB_PATH=/var/data/blockvault.db
ENV HOST=0.0.0.0
EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

CMD ["/app/blockvault_server"]

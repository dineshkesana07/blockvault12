# ==============================================================================
# BLOCKVAULT C++ Backend - Multi-Stage Production Dockerfile
# ==============================================================================
# Builds the C++ Crow REST API server for Linux deployment on Render.
# All dependencies are downloaded and compiled inside the container.
# ==============================================================================

# Stage 1: Build
FROM debian:bookworm-slim AS builder

# Install build tools and download utilities
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
    xz-utils \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---------- Download and build libsodium ----------
RUN curl -L -o libsodium.tar.gz \
    https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20-RELEASE.tar.gz && \
    tar xzf libsodium.tar.gz && \
    cd libsodium-1.0.20-RELEASE && \
    ./configure --disable-shared --enable-static --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /app && rm -f libsodium.tar.gz

# ---------- Download Asio headers ----------
RUN curl -L -o asio.tar.gz \
    https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-30-2.tar.gz && \
    tar xzf asio.tar.gz && \
    rm -f asio.tar.gz

# ---------- Copy application source ----------
COPY include/ include/
COPY src/ src/

# ---------- Create Linux CMakeLists.txt ----------
# Uses system-installed libsodium (built above) and downloads SQLite + nlohmann/json via FetchContent
RUN cat > CMakeLists.txt << 'CMAKEOF'
cmake_minimum_required(VERSION 3.15)
project(BlockVaultBackend CXX C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# 1. SQLite3 (amalgamation)
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3)
add_library(sqlite3_lib STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_lib PUBLIC ${sqlite3_SOURCE_DIR})

# 2. nlohmann/json (header-only)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# 3. Asio standalone headers
set(ASIO_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/asio-asio-1-30-2/asio/include")

# 4. System-installed libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# 5. Backend executable
add_executable(blockvault_server
    src/main.cpp
    src/Database.cpp
    src/Auth.cpp
    src/Encryption.cpp
    src/Vault.cpp
    src/Middleware.cpp
)

target_include_directories(blockvault_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ASIO_INCLUDE_DIR}
    ${sqlite3_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${json_SOURCE_DIR}/include
)

target_compile_definitions(blockvault_server PRIVATE
    CROW_STATIC_DIRECTORY="static"
    ASIO_STANDALONE
)

target_link_libraries(blockvault_server PRIVATE
    sqlite3_lib
    PkgConfig::SODIUM
    pthread
    dl
)
CMAKEOF

# ---------- Build ----------
RUN cmake -S . -B build -G "Ninja" \
      -DCMAKE_BUILD_TYPE=Release && \
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
ENV FRONTEND_ORIGIN=*

EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

CMD ["/app/blockvault_server"]

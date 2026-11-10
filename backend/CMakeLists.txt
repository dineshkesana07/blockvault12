cmake_minimum_required(VERSION 3.15)
project(BlockVaultBackend CXX C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

# 1. SQLite3
FetchContent_Declare(
    sqlite3
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3)

add_library(sqlite3_lib STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_lib PUBLIC ${sqlite3_SOURCE_DIR})

# 2. nlohmann/json
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

# 3. Libsodium
if(WIN32)
    set(SODIUM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libsodium-1.0.20-RELEASE")
    file(GLOB_RECURSE SODIUM_SOURCES "${SODIUM_DIR}/src/libsodium/*.c")

    add_library(sodium_lib STATIC ${SODIUM_SOURCES})
    target_include_directories(sodium_lib PUBLIC
        ${SODIUM_DIR}/src/libsodium/include
        ${SODIUM_DIR}/src/libsodium/include/sodium
    )
    target_compile_definitions(sodium_lib PUBLIC
        SODIUM_STATIC=1
        CONFIGURED=1
        HAVE_ARC4RANDOM=0
        HAVE_ARC4RANDOM_BUF=0
        HAVE_SYS_MMAN_H=0
        NATIVE_LITTLE_ENDIAN=1
    )
    set(SODIUM_TARGET sodium_lib)
    set(SODIUM_INCLUDE_DIRS ${SODIUM_DIR}/src/libsodium/include)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(SODIUM_TARGET PkgConfig::SODIUM)
endif()

# 4. libcurl for Google OAuth HTTPS requests
if(WIN32)
    FetchContent_Declare(
        curl
        URL https://curl.se/download/curl-8.12.1.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
    set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
    set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBSSH OFF CACHE BOOL "" FORCE)
    set(CURL_USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(curl)
else()
    find_package(CURL REQUIRED)
endif()

# 5. Asio standalone include path
set(ASIO_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/asio-asio-1-30-2/asio/include")

# 6. Backend Executable (Crow REST API Server)
add_executable(blockvault_server
    src/main.cpp
    src/Database.cpp
    src/Auth.cpp
    src/GoogleOAuth.cpp
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

if(WIN32)
    target_compile_definitions(blockvault_server PRIVATE
        CROW_STATIC_DIRECTORY="static"
        _WIN32_WINNT=0x0601
        ASIO_STANDALONE
    )

    target_link_libraries(blockvault_server PRIVATE
        sqlite3_lib
        ${SODIUM_TARGET}
        CURL::libcurl
        ws2_32
        mswsock
    )
else()
    target_compile_definitions(blockvault_server PRIVATE
        CROW_STATIC_DIRECTORY="static"
        ASIO_STANDALONE
    )

    target_link_libraries(blockvault_server PRIVATE
        sqlite3_lib
        ${SODIUM_TARGET}
        CURL::libcurl
        pthread
        dl
    )
endif()

enable_testing()
add_executable(blockvault_auth_tests
    tests/AuthTests.cpp
    src/Database.cpp
    src/Auth.cpp
    src/GoogleOAuth.cpp
    src/Encryption.cpp
)
target_include_directories(blockvault_auth_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${sqlite3_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${json_SOURCE_DIR}/include
)
target_link_libraries(blockvault_auth_tests PRIVATE
    sqlite3_lib
    ${SODIUM_TARGET}
    CURL::libcurl
)
add_test(NAME auth_sessions COMMAND blockvault_auth_tests)

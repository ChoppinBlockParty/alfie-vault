cmake_minimum_required(VERSION 3.25)
project(alfie_vault_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic)

# Dependencies: prefer the vendored third_party/ packages used on the Linux deploy box
# (no root apt permission there); fall back to system OpenSSL/Argon2 elsewhere.
set(VENDORED_ARGON2_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/lib/x86_64-linux-gnu")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND EXISTS "${VENDORED_ARGON2_LIB_DIR}")
    set(OPENSSL_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libssl-dev/usr/include")
    set(OPENSSL_ARCH_HEADERS "${OPENSSL_HEADERS}/x86_64-linux-gnu")
    set(ARGON2_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/argon2/usr/include")
    set(ARGON2_LIB_DIR "${VENDORED_ARGON2_LIB_DIR}")

    find_library(CRYPTO_LIB NAMES crypto libcrypto.so.3 REQUIRED)
    find_library(SSL_LIB NAMES ssl libssl.so.3 REQUIRED)
    find_library(ARGON2_LIB NAMES argon2 PATHS "${ARGON2_LIB_DIR}" NO_DEFAULT_PATH REQUIRED)
else()
    find_package(OpenSSL 3 REQUIRED)
    get_target_property(OPENSSL_HEADERS OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)
    set(OPENSSL_ARCH_HEADERS "${OPENSSL_HEADERS}")
    set(CRYPTO_LIB OpenSSL::Crypto)
    set(SSL_LIB OpenSSL::SSL)

    find_path(ARGON2_HEADERS argon2.h REQUIRED)
    find_library(ARGON2_LIB NAMES argon2 REQUIRED)
    get_filename_component(ARGON2_LIB_DIR "${ARGON2_LIB}" DIRECTORY)
endif()

add_library(alfie_vault_core
    src/secure_memory.cpp
    src/ca.cpp
    src/vault.cpp
    src/http_unlock.cpp
    src/ipc_crypto.cpp
    src/ipc_transport.cpp
)

target_include_directories(alfie_vault_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_HEADERS}
    ${OPENSSL_ARCH_HEADERS}
    ${ARGON2_HEADERS}
)

target_link_libraries(alfie_vault_core PUBLIC ${ARGON2_LIB} ${SSL_LIB} ${CRYPTO_LIB})
set_target_properties(alfie_vault_core PROPERTIES
    BUILD_RPATH "${ARGON2_LIB_DIR}"
)

add_executable(alfie-vault src/main.cpp)
target_link_libraries(alfie-vault PRIVATE alfie_vault_core)

include(CTest)

add_executable(test_ca tests/test_ca.cpp)
target_link_libraries(test_ca PRIVATE alfie_vault_core)
add_test(NAME ca COMMAND test_ca)

add_executable(test_vault tests/test_vault.cpp)
target_link_libraries(test_vault PRIVATE alfie_vault_core)
add_test(NAME vault COMMAND test_vault)

add_executable(test_ipc_crypto tests/test_ipc_crypto.cpp)
target_link_libraries(test_ipc_crypto PRIVATE alfie_vault_core)
add_test(NAME ipc_crypto COMMAND test_ipc_crypto)

add_executable(test_ipc_transport tests/test_ipc_transport.cpp)
target_link_libraries(test_ipc_transport PRIVATE alfie_vault_core)
add_test(NAME ipc_transport COMMAND test_ipc_transport)

add_executable(test_corruption tests/test_corruption.cpp)
target_link_libraries(test_corruption PRIVATE alfie_vault_core)
add_test(NAME corruption COMMAND test_corruption)

add_executable(test_secure_memory tests/test_secure_memory.cpp)
target_link_libraries(test_secure_memory PRIVATE alfie_vault_core)
add_test(NAME secure_memory COMMAND test_secure_memory)

add_executable(test_http_unlock tests/test_http_unlock.cpp)
target_link_libraries(test_http_unlock PRIVATE alfie_vault_core)
add_test(NAME http_unlock COMMAND test_http_unlock)

add_test(NAME init_smoke COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/init_smoke.py $<TARGET_FILE:alfie-vault>)
add_test(NAME https_smoke COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/https_smoke.py $<TARGET_FILE:alfie-vault>)
add_test(NAME gen_ip_cert COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_gen_ip_cert.py)

set(CLANG_TOOLS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/clang-tools")
set(CLANG_ENV "LD_LIBRARY_PATH=${CLANG_TOOLS}/usr/lib/x86_64-linux-gnu")
set(CLANG_FORMAT "${CLANG_TOOLS}/usr/bin/clang-format")
set(CLANG_TIDY "${CLANG_TOOLS}/usr/bin/clang-tidy")
file(GLOB_RECURSE CPP_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.hpp tests/*.cpp)

add_custom_target(format
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} -i ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(format-check
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_FORMAT} --dry-run --Werror ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(tidy
    COMMAND ${CMAKE_COMMAND} -E env ${CLANG_ENV} ${CLANG_TIDY} --quiet -p ${CMAKE_BINARY_DIR} ${CPP_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
